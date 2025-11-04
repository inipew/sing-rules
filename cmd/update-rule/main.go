package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	singBoxVersion = "v1.13.0-alpha.27"
	singBoxRepo    = "SagerNet/sing-box"
)

var idPorts = []int{
	21, 22, 23, 80, 81, 123, 143, 182, 183, 194, 443, 465, 587, 853,
	993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
	5222, 5228, 5229, 5230, 8000, 8080, 8081, 8088, 8443,
	8880, 8883, 8888, 8889, 42069,
}

type RuleSet struct {
	Version int           `json:"version"`
	Rules   []RuleElement `json:"rules"`
}
type RuleElement struct {
	Type   string        `json:"type,omitempty"`
	Mode   string        `json:"mode,omitempty"`
	Rules  []RuleElement `json:"rules,omitempty"`
	IPCIDR []string      `json:"ip_cidr,omitempty"`
	Port   []int         `json:"port,omitempty"`
}

func main() {
	ctx := context.Background()
	httpClient := &http.Client{Timeout: 120 * time.Second}

	// Pastikan di root repo
	if err := os.Chdir("."); err != nil {
		die("chdir: %v", err)
	}

	sbPath := "./sing-box"
	if !exists(sbPath) {
		if err := setupSingBox(ctx, httpClient, sbPath); err != nil {
			die("setup sing-box: %v", err)
		}
	}
	_ = os.Chmod(sbPath, 0o755)

	if err := adguardStage(httpClient, sbPath); err != nil { die("adguard: %v", err) }
	if err := idRuleStage(httpClient, sbPath); err != nil { die("id-rule: %v", err) }
	if err := waLocalStage(httpClient, sbPath); err != nil { die("wa-local: %v", err) }
	if err := compileOthers(sbPath); err != nil { die("compile-others: %v", err) }

	// show dir
	if err := run("bash", "-lc", "ls -la"); err != nil { die("ls: %v", err) }

	fmt.Println("Done (no release upload).")
}

// ---- stages ----

func adguardStage(hc *http.Client, sb string) error {
	if err := get(hc, "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adguard.txt"); err != nil { return err }
	if err := get(hc, "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist", "adguard-custom.txt"); err != nil { return err }
	defer os.Remove("adguard.txt"); defer os.Remove("adguard-custom.txt")
	if err := run(sb, "rule-set", "convert", "--type", "adguard", "adguard-custom.txt"); err != nil { return err }
	if err := run(sb, "rule-set", "convert", "--type", "adguard", "adguard.txt"); err != nil { return err }
	return nil
}

func idRuleStage(hc *http.Client, sb string) error {
	if err := get(hc, "https://cdn.jsdelivr.net/gh/malikshi/sing-box-geo@rule-set-geoip/geoip-geoid.srs", "geoip-geoid.srs"); err != nil { return err }
	if err := get(hc, "https://cdn.jsdelivr.net/gh/malikshi/sing-box-geo@rule-set-geoip/geoip-id.srs", "geoip-id.srs"); err != nil { return err }
	if err := run(sb, "rule-set", "decompile", "geoip-geoid.srs"); err != nil { return err }
	if err := run(sb, "rule-set", "decompile", "geoip-id.srs"); err != nil { return err }

	geoid, err := readRS("geoip-geoid.json"); if err != nil { return err }
	idrs, err := readRS("geoip-id.json"); if err != nil { return err }
	union := uniq(append(firstCIDR(geoid), firstCIDR(idrs)...))

	out := RuleSet{
		Version: 3,
		Rules: []RuleElement{{
			Type: "logical", Mode: "and",
			Rules: []RuleElement{{IPCIDR: union}, {Port: idPorts}},
		}},
	}
	if err := writeJSON("geoip-onlyid.json", out); err != nil { return err }
	return run(sb, "rule-set", "compile", "geoip-onlyid.json")
}

func waLocalStage(hc *http.Client, sb string) error {
	if err := get(hc, "https://cdn.jsdelivr.net/gh/malikshi/sing-box-geo@rule-set-geoip/geoip-facebook.srs", "geoip-facebook.srs"); err != nil { return err }
	if err := run(sb, "rule-set", "decompile", "geoip-facebook.srs", "-o", "geoip-facebook-tmp.json"); err != nil { return err }

	base, err := readRS("geoip-facebook-tmp.json"); if err != nil { return err }
	wa, err := readRS("wa_local.json"); if err != nil { return fmt.Errorf("butuh wa_local.json di repo: %w", err) }

	out := RuleSet{Version: wa.Version, Rules: []RuleElement{{IPCIDR: firstCIDR(base), Port: firstPorts(wa)}}}
	if err := writeJSON("wa_local.json", out); err != nil { return err }
	return run(sb, "rule-set", "compile", "wa_local.json")
}

func compileOthers(sb string) error {
	_ = os.Remove("warped.srs")
	_ = os.Remove("commonports.srs")
	_ = os.Remove("rule-direct-custom.srs")
	_ = os.Remove("direct-some-web.srs")

	targets := []string{
		"warped.json",
		"hilook.json",
		"commonports.json",
		"rule-port-game.json",
		"direct-some-web.json",
		"rule-direct-custom.json",
	}
	for _, t := range targets {
		if !exists(t) { return fmt.Errorf("missing %s", t) }
		if err := run("./sing-box", "rule-set", "compile", t); err != nil { return err }
	}
	return nil
}

// ---- helpers ----

func setupSingBox(ctx context.Context, hc *http.Client, out string) error {
	osStr := runtime.GOOS
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" { return fmt.Errorf("unsupported arch: %s", runtime.GOARCH) }
	file := fmt.Sprintf("sing-box-%s-%s-%s.tar.gz", strings.TrimPrefix(singBoxVersion, "v"), osStr, arch)
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", singBoxRepo, singBoxVersion, file)

	tmp := "sing-box.tar.gz"
	if err := get(hc, url, tmp); err != nil { return err }
	defer os.Remove(tmp)
	return extractSingBox(tmp, out)
}

func extractSingBox(targz, out string) error {
	f, err := os.Open(targz); if err != nil { return err }
	defer f.Close()
	gz, err := gzip.NewReader(f); if err != nil { return err }
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found bool
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) { break }
		if err != nil { return err }
		if h.FileInfo().IsDir() { continue }
		if filepath.Base(h.Name) == "sing-box" {
			o, err := os.Create(out); if err != nil { return err }
			if _, err := io.Copy(o, tr); err != nil { o.Close(); return err }
			o.Close()
			_ = os.Chmod(out, 0o755)
			found = true
			break
		}
	}
	if !found { return fmt.Errorf("sing-box binary not found in tar") }
	return nil
}

func run(cmd string, args ...string) error {
	fmt.Printf("+ %s %s\n", cmd, strings.Join(args, " "))
	c := exec.Command(cmd, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

func get(hc *http.Client, url, out string) error {
	fmt.Printf("↓ %s -> %s\n", url, out)
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := hc.Do(req); if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { b, _ := io.ReadAll(resp.Body); return fmt.Errorf("GET %d: %s", resp.StatusCode, string(b)) }
	f, err := os.Create(out); if err != nil { return err }
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func readRS(path string) (RuleSet, error) {
	b, err := os.ReadFile(path); if err != nil { return RuleSet{}, err }
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil { return RuleSet{}, err }
	return rs, nil
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  "); if err != nil { return err }
	return os.WriteFile(path, b, 0o644)
}
func firstCIDR(rs RuleSet) []string { if len(rs.Rules) == 0 { return nil }; return rs.Rules[0].IPCIDR }
func firstPorts(rs RuleSet) []int   { if len(rs.Rules) == 0 { return nil }; return rs.Rules[0].Port }
func uniq(in []string) []string {
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in { if _, ok := m[s]; !ok { m[s] = struct{}{}; out = append(out, s) } }
	return out
}
func exists(p string) bool { _, err := os.Stat(p); return err == nil }
func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", a...); os.Exit(1) }

