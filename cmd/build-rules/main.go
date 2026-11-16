package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultSingBoxVersion = "1.14.0-alpha.28"
	userAgent             = "sing-box-rule-builder/3.0"
)

type config struct {
	singBoxBin     string
	outputDir      string
	singBoxVersion string
	downloads      map[string]string
	localJSON      []string
	onlyIDPorts    []int
	waLocalPorts   []int
}

func loadConfig() config {
	return config{
		singBoxBin:     envOr("SINGBOX_BIN", "./sing-box"),
		outputDir:      envOr("OUTPUT_DIR", "."),
		singBoxVersion: envOr("SINGBOX_VERSION", defaultSingBoxVersion),
		downloads: map[string]string{
			"adguard.txt":               "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
			"adguard-custom.txt":        "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist",
			"doh.json":                  "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/doh.json",
			"geoip-asnid.json":          "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-asnid.json",
			"geoip-id.json":             "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/id.json",
			"geoip-facebook.srs":        "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/facebook.srs",
			"geosite-ecommerce-id.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/marketplace.json",
			"geosite-ewallet.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/ewallet.json",
			"geosite-bank-id.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/bank-id.json",
			"whatsapp.json":             "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/whatsapp.json",
		},
		localJSON: []string{
			"cloudflared-direct.json", "cloudflared-proxy.json", "commonports.json",
			"direct-some-web.json", "geoip-doh.json", "geosite-doh.json",
			"hilook.json", "notifikasi.json", "rule-direct-custom.json",
			"rule-port-game.json", "port-games.json", "wa_local.json",
			"warped.json", "rule-coc.json", "rule-port-mlbb.json",
			"google.json", "youtube.json",
		},
		onlyIDPorts: []int{
			21, 22, 23, 80, 81, 123, 143, 182, 183, 194, 443, 465, 587, 853,
			993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
			5222, 5228, 5229, 5230, 8000, 8080, 8081, 8088, 8443,
			8880, 8883, 8888, 8889, 42069,
		},
		waLocalPorts: []int{3478, 4244, 5222, 5223, 5242, 45395, 50318, 59234},
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type stats struct {
	mu             sync.Mutex
	downloaded     []string
	downloadFailed []string
	compiled       []string
	compileFailed  []string
	skipped        []string
}

func (s *stats) add(target *[]string, value string) {
	s.mu.Lock()
	*target = append(*target, value)
	s.mu.Unlock()
}

func (s *stats) hasErrors() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.downloadFailed) > 0 || len(s.compileFailed) > 0
}

func (s *stats) snapshot() stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return stats{
		downloaded: append([]string(nil), s.downloaded...),
		downloadFailed: append([]string(nil), s.downloadFailed...),
		compiled: append([]string(nil), s.compiled...),
		compileFailed: append([]string(nil), s.compileFailed...),
		skipped: append([]string(nil), s.skipped...),
	}
}

func gha(command, message string) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Printf("::%s::%s\n", command, strings.ReplaceAll(message, "\n", "%0A"))
	}
}

func group(title string) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Printf("::group::%s\n", title)
	}
}

func endGroup() {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Println("::endgroup::")
	}
}

func writeSummary(s *stats, elapsed time.Duration) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	snap := s.snapshot()
	status := "✅ Berhasil"
	if len(snap.downloadFailed)+len(snap.compileFailed) > 0 {
		status = "❌ Ada Kegagalan"
	}
	lines := []string{
		"## " + status + " — Sing-box Rule Set Builder",
		fmt.Sprintf("**Waktu build:** %s | **Durasi:** %.1fs", time.Now().UTC().Format("2006-01-02 15:04 UTC"), elapsed.Seconds()),
		"",
		"| Metrik | Nilai |",
		"|--------|-------|",
		fmt.Sprintf("| Download berhasil | %d/%d |", len(snap.downloaded), len(snap.downloaded)+len(snap.downloadFailed)),
		fmt.Sprintf("| Download gagal | %d |", len(snap.downloadFailed)),
		fmt.Sprintf("| Compile berhasil | %d |", len(snap.compiled)),
		fmt.Sprintf("| Compile gagal | %d |", len(snap.compileFailed)),
		fmt.Sprintf("| Dilewati | %d |", len(snap.skipped)),
	}
	if len(snap.compiled) > 0 {
		lines = append(lines, "", "### File SRS yang Dihasilkan", "```")
		for _, name := range snap.compiled {
			lines = append(lines, "  "+strings.TrimSuffix(name, ".json")+".srs")
		}
		lines = append(lines, "```")
	}
	if len(snap.downloadFailed) > 0 {
		lines = append(lines, "", "> ⚠️ **Gagal diunduh:** "+strings.Join(snap.downloadFailed, ", "))
	}
	if len(snap.compileFailed) > 0 {
		lines = append(lines, "> ⚠️ **Gagal dikompil:** "+strings.Join(snap.compileFailed, ", "))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		log.Printf("WARNING gagal menulis step summary: %v", err)
	}
}

type downloader struct {
	client *http.Client
	stats  *stats
	dryRun bool
	dir    string
}

func newDownloader(s *stats, dryRun bool, dir string) *downloader {
	return &downloader{
		client: &http.Client{Timeout: 45 * time.Second},
		stats: s, dryRun: dryRun, dir: dir,
	}
}

func (d *downloader) fetchOne(ctx context.Context, name, url string) bool {
	if d.dryRun {
		log.Printf("[DRY-RUN] Unduh: %s", name)
		return true
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		log.Printf("  [%d/3] Mengunduh: %s", attempt, name)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := d.client.Do(req)
		if err == nil {
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = fmt.Errorf("HTTP %s", resp.Status)
				resp.Body.Close()
			} else {
				var data []byte
				data, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
				resp.Body.Close()
				if err == nil && len(data) >= 64<<20 {
					err = errors.New("respons melebihi batas 64 MiB")
				}
				if err == nil {
					err = validateDownloaded(name, data)
				}
				if err == nil {
					err = atomicWrite(filepath.Join(d.dir, name), data, 0644)
				}
				if err == nil {
					d.stats.add(&d.stats.downloaded, name)
					log.Printf("  -> Tersimpan: %s (%.1f KiB)", name, float64(len(data))/1024)
					return true
				}
			}
		}
		lastErr = err
		if attempt < 3 {
			delay := time.Duration(1<<(attempt-1)) * 2 * time.Second
			log.Printf("  -> Percobaan %d gagal: %v. Retry dalam %s", attempt, err, delay)
			select {
			case <-ctx.Done():
				lastErr = ctx.Err()
				attempt = 3
			case <-time.After(delay):
			}
		}
	}
	log.Printf("ERROR gagal mengunduh %s: %v", name, lastErr)
	gha("error", fmt.Sprintf("Gagal mengunduh %s: %v", name, lastErr))
	d.stats.add(&d.stats.downloadFailed, name)
	return false
}

func validateDownloaded(name string, data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("respons kosong")
	}
	if strings.HasSuffix(name, ".json") {
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			return fmt.Errorf("JSON tidak valid: %w", err)
		}
		if name == "geoip-id.json" || name == "geoip-asnid.json" {
			rules, ok := payload["rules"].([]any)
			if !ok || len(rules) == 0 {
				return errors.New("rules kosong atau schema tidak dikenal")
			}
			found := false
			for _, raw := range rules {
				rule, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if cidrs, ok := rule["ip_cidr"].([]any); ok && len(cidrs) > 0 {
					found = true
					break
				}
			}
			if !found {
				return errors.New("tidak menemukan rules[].ip_cidr yang berisi data")
			}
		}
	}
	return nil
}

func (d *downloader) fetchAll(ctx context.Context, sources map[string]string, workers int) {
	group("Langkah 1: Parallel Downloads")
	defer endGroup()
	log.Println("LANGKAH 1: Parallel Downloads")
	if workers < 1 {
		workers = 1
	}
	if workers > len(sources) {
		workers = len(sources)
	}
	if workers == 0 {
		return
	}
	type item struct{ name, url string }
	jobs := make(chan item)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				d.fetchOne(ctx, job.name, job.url)
			}
		}()
	}
	for name, url := range sources {
		jobs <- item{name, url}
	}
	close(jobs)
	wg.Wait()
	snap := d.stats.snapshot()
	if len(snap.downloadFailed) > 0 {
		gha("warning", "Download gagal: "+strings.Join(snap.downloadFailed, ", "))
	}
}

type singBoxCLI struct {
	bin    string
	dir    string
	dryRun bool
}

func (c *singBoxCLI) check() error {
	if filepath.IsAbs(c.bin) || strings.ContainsRune(c.bin, filepath.Separator) {
		if _, err := os.Stat(c.bin); err != nil {
			return fmt.Errorf("binary sing-box tidak ditemukan: %s", c.bin)
		}
		return nil
	}
	if _, err := exec.LookPath(c.bin); err != nil {
		return fmt.Errorf("binary sing-box tidak ditemukan: %s", c.bin)
	}
	return nil
}

func (c *singBoxCLI) run(args ...string) error {
	if c.dryRun {
		log.Printf("[DRY-RUN] $ %s %s", c.bin, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(c.bin, args...)
	cmd.Dir = c.dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func (c *singBoxCLI) convert(kind, path string) error {
	return c.run("rule-set", "convert", "--type", kind, path)
}
func (c *singBoxCLI) decompile(input, output string) error {
	return c.run("rule-set", "decompile", input, "-o", output)
}
func (c *singBoxCLI) format(path string) error {
	return c.run("rule-set", "format", path, "-w")
}
func (c *singBoxCLI) compile(path string) error {
	return c.run("rule-set", "compile", path)
}

type builder struct {
	cfg   config
	cli   *singBoxCLI
	stats *stats
	dry   bool
}

func (b *builder) path(name string) string {
	return filepath.Join(b.cfg.outputDir, name)
}

func (b *builder) loadJSON(name string) (map[string]any, error) {
	data, err := os.ReadFile(b.path(name))
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

func (b *builder) writeJSON(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(b.path(name), append(data, '\n'), 0644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sing-rules-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (b *builder) cleanup(names ...string) {
	for _, name := range names {
		if err := os.Remove(b.path(name)); err == nil {
			log.Printf("  Dihapus: %s", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("WARNING gagal menghapus %s: %v", name, err)
		}
	}
}

func (b *builder) convertAndDecompile() {
	group("Langkah 2: Konversi AdGuard & Decompile Facebook")
	defer endGroup()
	for _, item := range []struct{ file, kind string }{{"adguard-custom.txt", "adguard"}, {"adguard.txt", "adguard"}} {
		if _, err := os.Stat(b.path(item.file)); err != nil {
			log.Printf("WARNING dilewati (tidak ada): %s", item.file)
			continue
		}
		if err := b.cli.convert(item.kind, item.file); err != nil {
			log.Printf("WARNING gagal konversi %s: %v", item.file, err)
		}
	}
	if _, err := os.Stat(b.path("geoip-facebook.srs")); err == nil {
		if err := b.cli.decompile("geoip-facebook.srs", "geoip-facebook.json"); err != nil {
			log.Printf("WARNING gagal decompile geoip-facebook.srs: %v", err)
		}
	} else {
		log.Println("WARNING dilewati: geoip-facebook.srs tidak ditemukan")
	}
	b.cleanup("adguard.txt", "adguard-custom.txt", "geoip-facebook.srs")
}

func (b *builder) buildDoH() {
	group("Langkah 2b: Pemisahan doh.json")
	defer endGroup()
	doh, err := b.loadJSON("doh.json")
	if err != nil {
		log.Printf("WARNING doh.json tidak dapat dimuat: %v", err)
		return
	}
	rules, ok := doh["rules"].([]any)
	if !ok || len(rules) == 0 {
		log.Println("WARNING tidak ada rules di doh.json")
		return
	}
	rule, ok := rules[0].(map[string]any)
	if !ok {
		log.Println("WARNING struktur rules[0] doh.json tidak valid")
		return
	}
	domainSuffix := stringSlice(rule["domain_suffix"])
	ipCIDRs := stringSlice(rule["ip_cidr"])
	if b.dry {
		return
	}
	if err := b.writeJSON("geosite-doh.json", map[string]any{"version": 3, "rules": []any{map[string]any{"domain_suffix": domainSuffix}}}); err != nil {
		log.Printf("ERROR menulis geosite-doh.json: %v", err)
		return
	}
	if err := b.writeJSON("geoip-doh.json", map[string]any{"version": 3, "rules": []any{map[string]any{"ip_cidr": ipCIDRs}}}); err != nil {
		log.Printf("ERROR menulis geoip-doh.json: %v", err)
		return
	}
	b.cleanup("doh.json")
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func (b *builder) formatJSON() {
	group("Langkah 3: Format Berkas JSON")
	defer endGroup()
	targets := map[string]struct{}{}
	for _, name := range b.cfg.localJSON {
		targets[name] = struct{}{}
	}
	for name := range b.cfg.downloads {
		if strings.HasSuffix(name, ".json") && name != "doh.json" {
			targets[name] = struct{}{}
		}
	}
	targets["geoip-facebook.json"] = struct{}{}
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := os.Stat(b.path(name)); err != nil {
			b.stats.add(&b.stats.skipped, name)
			continue
		}
		if err := b.cli.format(name); err != nil {
			log.Printf("WARNING format gagal untuk %s: %v", name, err)
		}
	}
}

func (b *builder) buildOnlyID() {
	group("Langkah 4: Build geoip-onlyid.json")
	defer endGroup()
	asn, errASN := b.loadJSON("geoip-asnid.json")
	id, errID := b.loadJSON("geoip-id.json")
	if errASN != nil || errID != nil {
		log.Printf("ERROR sumber geoip-asnid.json / geoip-id.json tidak tersedia: %v %v", errASN, errID)
		gha("error", "geoip-asnid.json atau geoip-id.json tidak tersedia")
		return
	}
	asnRules, okASN := asn["rules"].([]any)
	idRules, okID := id["rules"].([]any)
	if !okASN || !okID || len(asnRules) == 0 || len(idRules) == 0 {
		log.Println("ERROR schema GeoIP tidak memiliki rules")
		gha("error", "Schema GeoIP tidak memiliki rules")
		return
	}
	asnRule, okASN := asnRules[0].(map[string]any)
	idRule, okID := idRules[0].(map[string]any)
	if !okASN || !okID {
		log.Println("ERROR struktur GeoIP rules[0] tidak valid")
		return
	}
	raw := append(stringSlice(asnRule["ip_cidr"]), stringSlice(idRule["ip_cidr"])...)
	prefixes, invalid, err := parsePrefixes(raw)
	if err != nil {
		log.Printf("ERROR CIDR sumber tidak valid: %v", err)
		return
	}
	if invalid > 0 {
		log.Printf("WARNING %d entri CIDR tidak valid diabaikan", invalid)
		gha("warning", fmt.Sprintf("%d entri CIDR tidak valid pada geoip-onlyid", invalid))
	}
	optimized := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		optimized = append(optimized, prefix.String())
	}
	log.Printf("  CIDR: %d asli -> %d setelah optimasi", len(raw), len(optimized))
	gha("notice", fmt.Sprintf("geoip-onlyid: %d CIDR -> %d (hemat %d)", len(raw), len(optimized), len(raw)-len(optimized)))
	data := map[string]any{
		"version": 3,
		"rules": []any{map[string]any{
			"type": "logical", "mode": "and",
			"rules": []any{
				map[string]any{"ip_cidr": optimized},
				map[string]any{"port": b.cfg.onlyIDPorts},
			},
		}},
	}
	if b.dry {
		return
	}
	if err := b.writeJSON("geoip-onlyid.json", data); err != nil {
		log.Printf("ERROR menulis geoip-onlyid.json: %v", err)
		return
	}
	if err := b.cli.format("geoip-onlyid.json"); err != nil {
		log.Printf("WARNING format gagal untuk geoip-onlyid.json: %v", err)
	}
}

func (b *builder) buildWALocal() {
	group("Langkah 5: Build wa_local.json")
	defer endGroup()
	fb, err := b.loadJSON("geoip-facebook.json")
	if err != nil {
		log.Printf("WARNING geoip-facebook.json tidak tersedia: %v", err)
		gha("error", "geoip-facebook.json tidak tersedia untuk wa_local")
		return
	}
	rules, ok := fb["rules"].([]any)
	if !ok || len(rules) == 0 {
		log.Println("WARNING geoip-facebook.json tidak memiliki rules")
		return
	}
	rule, ok := rules[0].(map[string]any)
	if !ok {
		log.Println("WARNING struktur geoip-facebook.json tidak valid")
		return
	}
	ips := stringSlice(rule["ip_cidr"])
	log.Printf("  IP Facebook: %d entri", len(ips))
	data := map[string]any{
		"version": 3,
		"rules": []any{map[string]any{
			"type": "logical", "mode": "and",
			"rules": []any{
				map[string]any{"ip_cidr": ips},
				map[string]any{"port": b.cfg.waLocalPorts},
			},
		}},
	}
	if b.dry {
		return
	}
	if err := b.writeJSON("wa_local.json", data); err != nil {
		log.Printf("ERROR menulis wa_local.json: %v", err)
		return
	}
	if err := b.cli.format("wa_local.json"); err != nil {
		log.Printf("WARNING format gagal untuk wa_local.json: %v", err)
	}
}

func (b *builder) compileAll() {
	group("Langkah 6: Compile ke .srs")
	defer endGroup()
	targets := map[string]struct{}{}
	for _, name := range b.cfg.localJSON {
		targets[name] = struct{}{}
	}
	for name := range b.cfg.downloads {
		if strings.HasSuffix(name, ".txt") {
			targets[strings.TrimSuffix(name, ".txt")+".json"] = struct{}{}
		} else if strings.HasSuffix(name, ".json") && name != "doh.json" {
			targets[name] = struct{}{}
		}
	}
	for _, name := range []string{"geoip-facebook.json", "geoip-onlyid.json", "adguard.json", "adguard-custom.json"} {
		targets[name] = struct{}{}
	}
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := os.Stat(b.path(name)); err != nil {
			b.stats.add(&b.stats.skipped, name)
			continue
		}
		if err := b.cli.compile(name); err != nil {
			log.Printf("ERROR gagal compile %s: %v", name, err)
			gha("error", fmt.Sprintf("Gagal kompil %s: %v", name, err))
			b.stats.add(&b.stats.compileFailed, name)
			continue
		}
		log.Printf("  Dikompil: %s -> %s", name, strings.TrimSuffix(name, ".json")+".srs")
		b.stats.add(&b.stats.compiled, name)
	}
}

func parsePrefixes(raw []string) ([]netip.Prefix, int, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	invalid := 0
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			invalid++
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return collapsePrefixes(prefixes), invalid, nil
}

func collapsePrefixes(input []netip.Prefix) []netip.Prefix {
	if len(input) == 0 {
		return nil
	}
	// First remove duplicates and prefixes already covered by a broader prefix.
	sort.Slice(input, func(i, j int) bool {
		a, c := input[i], input[j]
		if a.Addr().Is4() != c.Addr().Is4() {
			return a.Addr().Is4()
		}
		if a.Bits() != c.Bits() {
			return a.Bits() < c.Bits()
		}
		return a.Addr().Less(c.Addr())
	})
	unique := make([]netip.Prefix, 0, len(input))
	for _, prefix := range input {
		covered := false
		for _, existing := range unique {
			if existing.Addr().Is4() == prefix.Addr().Is4() && existing.Bits() <= prefix.Bits() && existing.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			unique = append(unique, prefix)
		}
	}
	// Repeatedly merge sibling networks into their parent.
	for {
		merged := false
		sort.Slice(unique, func(i, j int) bool {
			if unique[i].Addr().Is4() != unique[j].Addr().Is4() {
				return unique[i].Addr().Is4()
			}
			if unique[i].Bits() != unique[j].Bits() {
				return unique[i].Bits() > unique[j].Bits()
			}
			return unique[i].Addr().Less(unique[j].Addr())
		})
		used := make([]bool, len(unique))
		next := make([]netip.Prefix, 0, len(unique))
		for i, prefix := range unique {
			if used[i] {
				continue
			}
			if prefix.Bits() == 0 {
				next = append(next, prefix)
				used[i] = true
				continue
			}
			parent := netip.PrefixFrom(prefix.Addr(), prefix.Bits()-1).Masked()
			siblingAddr := prefix.Addr()
			hostBits := prefix.Addr().BitLen() - prefix.Bits()
			if hostBits >= 0 {
				if prefix.Addr().Bit(prefix.Bits()-1) == 0 {
					siblingAddr = prefix.Addr().Next()
					step := uint64(1) << min(hostBits, 63)
					_ = step
				}
				_ = siblingAddr
			}
			sibling := siblingPrefix(prefix)
			found := -1
			for j := i + 1; j < len(unique); j++ {
				if !used[j] && unique[j] == sibling {
					found = j
					break
				}
			}
			if found >= 0 {
				next = append(next, parent)
				used[i], used[found] = true, true
				merged = true
				continue
			}
			next = append(next, prefix)
			used[i] = true
		}
		unique = next
		if !merged {
			break
		}
	}
	// A final containment pass keeps output deterministic and minimal.
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Addr().Is4() != unique[j].Addr().Is4() {
			return unique[i].Addr().Is4()
		}
		if unique[i].Bits() != unique[j].Bits() {
			return unique[i].Bits() < unique[j].Bits()
		}
		return unique[i].Addr().Less(unique[j].Addr())
	})
	out := make([]netip.Prefix, 0, len(unique))
	for _, prefix := range unique {
		covered := false
		for _, existing := range out {
			if existing.Addr().Is4() == prefix.Addr().Is4() && existing.Bits() <= prefix.Bits() && existing.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, prefix)
		}
	}
	return out
}

func siblingPrefix(prefix netip.Prefix) netip.Prefix {
	parent := netip.PrefixFrom(prefix.Addr(), prefix.Bits()-1).Masked()
	// The two children of a parent differ in the first bit after the parent prefix.
	if prefix == netip.PrefixFrom(parent.Addr(), parent.Bits()+1).Masked() {
		return netip.PrefixFrom(parent.Addr().Next(), prefix.Bits()).Masked()
	}
	return netip.PrefixFrom(parent.Addr(), prefix.Bits()).Masked()
}

func parseArgs(cfg config) (bool, bool, bool, bool, int, bool) {
	skipDownload := flag.Bool("skip-download", false, "Lewati download.")
	onlyCompile := flag.Bool("only-compile", false, "Hanya compile.")
	dryRun := flag.Bool("dry-run", false, "Simulasi tanpa perubahan.")
	failFast := flag.Bool("fail-fast", false, "Hentikan pipeline jika download gagal.")
	workers := flag.Int("workers", min(len(cfg.downloads), 8), "Jumlah download paralel.")
	verbose := flag.Bool("verbose", false, "Log debug.")
	flag.BoolVar(verbose, "v", false, "Log debug.")
	flag.Parse()
	return *skipDownload, *onlyCompile, *dryRun, *failFast, *workers, *verbose
}

func run() int {
	cfg := loadConfig()
	skipDownload, onlyCompile, dryRun, failFast, workers, verbose := parseArgs(cfg)
	if workers < 1 {
		log.Printf("ERROR --workers harus >= 1")
		return 2
	}
	if verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}
	start := time.Now()
	log.Println(strings.Repeat("=", 55))
	log.Println("SING-BOX RULE SET BUILDER (Go)")
	log.Printf("  Go runtime      : %s", runtime.Version())
	log.Printf("  Versi sing-box  : %s", cfg.singBoxVersion)
	log.Printf("  Output          : %s", cfg.outputDir)
	log.Printf("  GitHub Actions  : %t", os.Getenv("GITHUB_ACTIONS") == "true")
	if dryRun {
		log.Println("  Mode DRY-RUN aktif")
	}
	log.Println(strings.Repeat("=", 55))
	if err := os.MkdirAll(cfg.outputDir, 0755); err != nil {
		log.Printf("ERROR output directory: %v", err)
		return 1
	}
	absDir, err := filepath.Abs(cfg.outputDir)
	if err != nil {
		log.Printf("ERROR output directory: %v", err)
		return 1
	}
	cfg.outputDir = absDir
	cli := &singBoxCLI{bin: cfg.singBoxBin, dir: cfg.outputDir, dryRun: dryRun}
	if err := cli.check(); err != nil {
		log.Printf("ERROR %v", err)
		gha("error", err.Error())
		return 1
	}
	s := &stats{}
	b := &builder{cfg: cfg, cli: cli, stats: s, dry: dryRun}
	if onlyCompile {
		b.compileAll()
	} else {
		if !skipDownload {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			newDownloader(s, dryRun, cfg.outputDir).fetchAll(ctx, cfg.downloads, workers)
			if failFast && len(s.snapshot().downloadFailed) > 0 {
				log.Println("ERROR download kritis gagal; pipeline dihentikan (--fail-fast)")
				gha("error", "Gagal download kritis — pipeline dihentikan (--fail-fast).")
				return 1
			}
		} else {
			log.Println("Download dilewati (--skip-download).")
		}
		b.convertAndDecompile()
		b.buildDoH()
		b.formatJSON()
		b.buildOnlyID()
		b.buildWALocal()
		b.compileAll()
	}
	elapsed := time.Since(start)
	snap := s.snapshot()
	log.Println(strings.Repeat("=", 55))
	log.Println("RINGKASAN BUILD")
	log.Printf("  Download berhasil  : %d/%d", len(snap.downloaded), len(snap.downloaded)+len(snap.downloadFailed))
	log.Printf("  Download gagal     : %d", len(snap.downloadFailed))
	log.Printf("  Compile berhasil   : %d", len(snap.compiled))
	log.Printf("  Compile gagal      : %d", len(snap.compileFailed))
	log.Printf("  Dilewati           : %d", len(snap.skipped))
	log.Printf("Total waktu: %.1f detik", elapsed.Seconds())
	writeSummary(s, elapsed)
	if s.hasErrors() {
		gha("error", "Build selesai dengan error. Periksa log di atas.")
		return 1
	}
	log.Println("Build selesai!")
	return 0
}

func main() {
	os.Exit(run())
}
