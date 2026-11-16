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

type config struct {
	bin, output, version string
	sources map[string]string
	local []string
	onlyIDPorts, waPorts []int
}

func loadConfig() config {
	return config{
		bin: env("SINGBOX_BIN", "./sing-box"), output: env("OUTPUT_DIR", "."),
		version: env("SINGBOX_VERSION", "1.14.0-alpha.28"),
		sources: map[string]string{
			"adguard.txt": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
			"adguard-custom.txt": "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist",
			"doh.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/doh.json",
			"geoip-asnid.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-asnid.json",
			"geoip-id.json": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/id.json",
			"geoip-facebook.srs": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/facebook.srs",
			"geosite-ecommerce-id.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/marketplace.json",
			"geosite-ewallet.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/ewallet.json",
			"geosite-bank-id.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/bank-id.json",
			"whatsapp.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/whatsapp.json",
		},
		local: []string{
			"cloudflared-direct.json", "cloudflared-proxy.json", "commonports.json",
			"direct-some-web.json", "geoip-doh.json", "geosite-doh.json",
			"hilook.json", "notifikasi.json", "rule-direct-custom.json",
			"rule-port-game.json", "port-games.json", "wa_local.json",
			"warped.json", "rule-coc.json", "rule-port-mlbb.json", "google.json", "youtube.json",
		},
		onlyIDPorts: []int{21,22,23,80,81,123,143,182,183,194,443,465,587,853,993,995,998,2052,2053,2082,2083,2086,2095,2096,5222,5228,5229,5230,8000,8080,8081,8088,8443,8880,8883,8888,8889,42069},
		waPorts: []int{3478,4244,5222,5223,5242,45395,50318,59234},
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}

type resultStats struct {
	downloaded, downloadFailed, compiled, compileFailed, skipped, stageFailed []string
}
type stats struct {
	mu sync.Mutex
	resultStats
}
func (s *stats) add(dst *[]string, value string) {
	s.mu.Lock(); defer s.mu.Unlock()
	*dst = append(*dst, value)
}
func (s *stats) snapshot() resultStats {
	s.mu.Lock(); defer s.mu.Unlock()
	return resultStats{
		downloaded: append([]string(nil), s.downloaded...),
		downloadFailed: append([]string(nil), s.downloadFailed...),
		compiled: append([]string(nil), s.compiled...),
		compileFailed: append([]string(nil), s.compileFailed...),
		skipped: append([]string(nil), s.skipped...),
		stageFailed: append([]string(nil), s.stageFailed...),
	}
}
func (s *stats) failed() bool {
	v := s.snapshot()
	return len(v.downloadFailed)+len(v.compileFailed)+len(v.stageFailed)>0
}
func (s *stats) fail(stage string, err error) {
	if err == nil { return }
	log.Printf("ERROR %s: %v", stage, err)
	gha("error", fmt.Sprintf("%s: %v", stage, err))
	s.add(&s.stageFailed, stage)
}

func gha(command, message string) {
	if os.Getenv("GITHUB_ACTIONS")=="true" {
		message = strings.ReplaceAll(strings.ReplaceAll(message, "%", "%25"), "\n", "%0A")
		fmt.Printf("::%s::%s\n", command, message)
	}
}
func group(name string) {
	if os.Getenv("GITHUB_ACTIONS")=="true" { fmt.Printf("::group::%s\n", name) }
}
func endGroup() {
	if os.Getenv("GITHUB_ACTIONS")=="true" { fmt.Println("::endgroup::") }
}

func atomicWrite(path string, data []byte) error {
	if err:=os.MkdirAll(filepath.Dir(path),0755); err!=nil { return err }
	f,err:=os.CreateTemp(filepath.Dir(path),".sing-rules-*.tmp")
	if err!=nil { return err }
	tmp:=f.Name()
	defer os.Remove(tmp)
	if _,err=f.Write(data); err!=nil { f.Close(); return err }
	if err=f.Sync(); err!=nil { f.Close(); return err }
	if err=f.Chmod(0644); err!=nil { f.Close(); return err }
	if err=f.Close(); err!=nil { return err }
	return os.Rename(tmp,path)
}

type downloader struct { client *http.Client; dir string; stats *stats; dry bool }
func (d *downloader) one(ctx context.Context, name,url string) {
	if d.dry { log.Printf("[DRY-RUN] Download %s",name); return }
	var last error
	for attempt:=1; attempt<=3; attempt++ {
		req,err:=http.NewRequestWithContext(ctx,http.MethodGet,url,nil)
		if err==nil {
			req.Header.Set("User-Agent","sing-box-rule-builder/3.0")
			var resp *http.Response
			resp,err=d.client.Do(req)
			if err==nil {
				if resp.StatusCode<200 || resp.StatusCode>=300 { err=fmt.Errorf("HTTP %s",resp.Status); resp.Body.Close() } else {
					data,readErr:=io.ReadAll(io.LimitReader(resp.Body,(64<<20)+1))
					resp.Body.Close()
					err=readErr
					if err==nil && len(data)>64<<20 { err=errors.New("response exceeds 64 MiB") }
					if err==nil { err=validateDownload(name,data) }
					if err==nil { err=atomicWrite(filepath.Join(d.dir,name),data) }
					if err==nil {
						d.stats.add(&d.stats.downloaded,name)
						log.Printf("Downloaded %s (%.1f KiB)",name,float64(len(data))/1024)
						return
					}
				}
			}
		}
		last=err
		if attempt<3 {
			delay:=time.Duration(1<<(attempt-1))*2*time.Second
			log.Printf("Download %s attempt %d failed: %v; retry in %s",name,attempt,err,delay)
			select { case <-ctx.Done(): last=ctx.Err(); attempt=3; case <-time.After(delay): }
		}
	}
	log.Printf("ERROR download %s: %v",name,last)
	gha("error",fmt.Sprintf("Gagal mengunduh %s: %v",name,last))
	d.stats.add(&d.stats.downloadFailed,name)
}
func validateDownload(name string,data []byte) error {
	if len(bytes.TrimSpace(data))==0 { return errors.New("empty response") }
	if !strings.HasSuffix(name,".json") { return nil }
	var doc map[string]any
	if err:=json.Unmarshal(data,&doc); err!=nil { return fmt.Errorf("invalid JSON: %w",err) }
	if name=="geoip-id.json" || name=="geoip-asnid.json" {
		rules,ok:=doc["rules"].([]any); if !ok || len(rules)==0 { return errors.New("missing/non-empty rules array") }
		for _,raw:=range rules {
			rule,ok:=raw.(map[string]any); if !ok { continue }
			if cidrs,ok:=rule["ip_cidr"].([]any); ok && len(cidrs)>0 {
				valid := 0
				for _, rawCIDR := range cidrs {
					value, ok := rawCIDR.(string); if !ok { continue }
					if _, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil { valid++ }
				}
				if valid > 0 { return nil }
			}
		}
		return errors.New("missing non-empty rules[].ip_cidr")
	}
	return nil
}
func (d *downloader) all(ctx context.Context,sources map[string]string,workers int) {
	group("Langkah 1: Parallel Downloads"); defer endGroup()
	if workers<1 { workers=1 }; if workers>len(sources) { workers=len(sources) }
	type job struct{name,url string}
	jobs:=make(chan job)
	var wg sync.WaitGroup
	for i:=0;i<workers;i++ {
		wg.Add(1); go func(){ defer wg.Done(); for j:=range jobs { d.one(ctx,j.name,j.url) } }()
	}
	for n,u:=range sources { jobs<-job{n,u} }; close(jobs); wg.Wait()
}

type cli struct { bin,dir string; dry bool }
func (c *cli) check() error {
	if c.dry { return nil }
	if strings.ContainsRune(c.bin,filepath.Separator) {
		if _,err:=os.Stat(c.bin); err!=nil { return fmt.Errorf("sing-box binary not found: %s",c.bin) }
		return nil
	}
	_,err:=exec.LookPath(c.bin); if err!=nil { return fmt.Errorf("sing-box binary not found: %s",c.bin) }; return nil
}
func (c *cli) run(args ...string) error {
	if c.dry { log.Printf("[DRY-RUN] %s %s",c.bin,strings.Join(args," ")); return nil }
	cmd:=exec.Command(c.bin,args...); cmd.Dir=c.dir
	out,err:=cmd.CombinedOutput()
	if err!=nil { return fmt.Errorf("%s: %w",strings.TrimSpace(string(out)),err) }; return nil
}
func (c *cli) convert(kind,path string) error { return c.run("rule-set","convert","--type",kind,path) }
func (c *cli) decompile(in,out string) error { return c.run("rule-set","decompile",in,"-o",out) }
func (c *cli) format(path string) error { return c.run("rule-set","format",path,"-w") }
func (c *cli) compile(path string) error { return c.run("rule-set","compile",path) }

type builder struct { cfg config; cli *cli; stats *stats; dry bool }
func (b *builder) path(name string) string { return filepath.Join(b.cfg.output,name) }
func (b *builder) load(name string)(map[string]any,error) {
	data,err:=os.ReadFile(b.path(name)); if err!=nil{return nil,err}
	var doc map[string]any; if err=json.Unmarshal(data,&doc);err!=nil{return nil,fmt.Errorf("%s: %w",name,err)}
	return doc,nil
}
func (b *builder) write(name string,v any) error {
	data,err:=json.MarshalIndent(v,"","  "); if err!=nil{return err}
	return atomicWrite(b.path(name),append(data,'\n'))
}
func (b *builder) cleanup(names ...string) {
	for _,n:=range names { if err:=os.Remove(b.path(n)); err!=nil && !errors.Is(err,os.ErrNotExist) { log.Printf("WARNING remove %s: %v",n,err) } }
}
func stringsAt(value any) []string {
	raw,ok:=value.([]any); if !ok{return []string{}}
	out:=make([]string,0,len(raw)); for _,v:=range raw { if s,ok:=v.(string);ok {out=append(out,s)} }; return out
}
func firstRule(doc map[string]any)(map[string]any,error) {
	rules,ok:=doc["rules"].([]any); if !ok||len(rules)==0{return nil,errors.New("rules missing or empty")}
	rule,ok:=rules[0].(map[string]any); if !ok{return nil,errors.New("rules[0] is not an object")}
	return rule,nil
}
func (b *builder) convertAndDecompile() {
	group("Langkah 2: Konversi AdGuard & Decompile Facebook"); defer endGroup()
	for _,item:=range []struct{file,kind string}{{"adguard-custom.txt","adguard"},{"adguard.txt","adguard"}} {
		if _,err:=os.Stat(b.path(item.file)); err!=nil { log.Printf("WARNING skip missing %s",item.file); continue }
		if err:=b.cli.convert(item.kind,item.file);err!=nil { b.stats.fail("convert "+item.file, err); continue }
		b.cleanup(item.file)
	}
	if _,err:=os.Stat(b.path("geoip-facebook.srs"));err==nil {
		if err:=b.cli.decompile("geoip-facebook.srs","geoip-facebook.json");err!=nil { b.stats.fail("decompile geoip-facebook.srs", err) } else { b.cleanup("geoip-facebook.srs") }
	} else { log.Println("WARNING geoip-facebook.srs missing") }
}
func (b *builder) buildDoH() {
	group("Langkah 2b: Pemisahan doh.json"); defer endGroup()
	doc,err:=b.load("doh.json"); if err!=nil {b.stats.fail("load doh.json",err);return}
	rule,err:=firstRule(doc);if err!=nil{b.stats.fail("parse doh.json",err);return}
	if b.dry{return}
	if err=b.write("geosite-doh.json",map[string]any{"version":3,"rules":[]any{map[string]any{"domain_suffix":stringsAt(rule["domain_suffix"])}}});err!=nil{b.stats.fail("write geosite-doh.json",err);return}
	if err=b.write("geoip-doh.json",map[string]any{"version":3,"rules":[]any{map[string]any{"ip_cidr":stringsAt(rule["ip_cidr"])}}});err!=nil{b.stats.fail("write geoip-doh.json",err);return}
	b.cleanup("doh.json")
}
func (b *builder) formatJSON() {
	group("Langkah 3: Format Berkas JSON");defer endGroup()
	set:=map[string]bool{"geoip-facebook.json":true}
	for _,n:=range b.cfg.local{set[n]=true}
	for n:=range b.cfg.sources{if strings.HasSuffix(n,".json")&&n!="doh.json"{set[n]=true}}
	names:=make([]string,0,len(set));for n:=range set{names=append(names,n)};sort.Strings(names)
	for _,n:=range names{if _,err:=os.Stat(b.path(n));err!=nil{b.stats.add(&b.stats.skipped,n);continue};if err:=b.cli.format(n);err!=nil{b.stats.fail("format "+n,err)}}
}

func sibling(p netip.Prefix) netip.Prefix {
	bit:=p.Bits()-1
	if p.Addr().Is4() {
		a:=p.Addr().As4(); a[bit/8]^=byte(1<<uint(7-bit%8))
		return netip.PrefixFrom(netip.AddrFrom4(a),p.Bits()).Masked()
	}
	a:=p.Addr().As16(); a[bit/8]^=byte(1<<uint(7-bit%8))
	return netip.PrefixFrom(netip.AddrFrom16(a),p.Bits()).Masked()
}
func collapse(input []netip.Prefix) []netip.Prefix {
	set:=make(map[string]netip.Prefix,len(input))
	for _,p:=range input { set[p.Masked().String()]=p.Masked() }
	// Drop entries covered by any existing supernet.
	for key,p:=range set {
		covered:=false
		for bits:=0;bits<p.Bits();bits++ { if _,ok:=set[netip.PrefixFrom(p.Addr(),bits).Masked().String()];ok{covered=true;break} }
		if covered {delete(set,key)}
	}
	// Merge exact sibling networks upward until no more merges are possible.
	for changed:=true;changed; {
		changed=false
		for key,p:=range set {
			if p.Bits()==0 {continue}
			sib:=sibling(p); if _,ok:=set[sib.String()];!ok{continue}
			delete(set,key);delete(set,sib.String())
			parent:=netip.PrefixFrom(p.Addr(),p.Bits()-1).Masked()
			set[parent.String()]=parent;changed=true;break
		}
	}
	out:=make([]netip.Prefix,0,len(set));for _,p:=range set{out=append(out,p)}
	sort.Slice(out,func(i,j int)bool{
		if out[i].Addr().Is4()!=out[j].Addr().Is4(){return out[i].Addr().Is4()}
		if out[i].Addr()!=out[j].Addr(){return out[i].Addr().Less(out[j].Addr())}
		return out[i].Bits()<out[j].Bits()
	})
	return out
}
func parseCIDRs(values []string)([]netip.Prefix,int) {
	out:=make([]netip.Prefix,0,len(values));bad:=0
	for _,v:=range values {p,err:=netip.ParsePrefix(strings.TrimSpace(v));if err!=nil{bad++;continue};out=append(out,p.Masked())}
	return collapse(out),bad
}
func (b *builder) buildOnlyID() {
	group("Langkah 4: Build geoip-onlyid.json");defer endGroup()
	asn,err1:=b.load("geoip-asnid.json");id,err2:=b.load("geoip-id.json")
	if err1!=nil||err2!=nil{b.stats.fail("load GeoIP sources",fmt.Errorf("ASN: %v; country: %v",err1,err2));return}
	ar,e1:=firstRule(asn);ir,e2:=firstRule(id);if e1!=nil||e2!=nil{b.stats.fail("parse GeoIP rules",fmt.Errorf("ASN: %v; country: %v",e1,e2));return}
	raw:=append(stringsAt(ar["ip_cidr"]),stringsAt(ir["ip_cidr"])...)
	prefixes,bad:=parseCIDRs(raw);optimized:=make([]string,0,len(prefixes));for _,p:=range prefixes{optimized=append(optimized,p.String())}
	if bad>0{gha("warning",fmt.Sprintf("%d CIDR invalid diabaikan",bad))}
	if len(prefixes)==0 { b.stats.fail("build geoip-onlyid.json",errors.New("no valid CIDR prefixes found")); return }
	log.Printf("  CIDR: %d -> %d setelah optimasi",len(raw),len(optimized))
	gha("notice",fmt.Sprintf("geoip-onlyid: %d CIDR -> %d (hemat %d)",len(raw),len(optimized),len(raw)-len(optimized)))
	data:=map[string]any{"version":3,"rules":[]any{map[string]any{"type":"logical","mode":"and","rules":[]any{map[string]any{"ip_cidr":optimized},map[string]any{"port":b.cfg.onlyIDPorts}}}}}
	if b.dry{return};if err:=b.write("geoip-onlyid.json",data);err!=nil{b.stats.fail("write geoip-onlyid.json",err);return}
	if err:=b.cli.format("geoip-onlyid.json");err!=nil{b.stats.fail("format geoip-onlyid.json",err)}
}
func (b *builder) buildWALocal() {
	group("Langkah 5: Build wa_local.json");defer endGroup()
	doc,err:=b.load("geoip-facebook.json");if err!=nil{b.stats.fail("load geoip-facebook.json",err);return}
	rule,err:=firstRule(doc);if err!=nil{b.stats.fail("parse geoip-facebook.json",err);return}
	ips:=stringsAt(rule["ip_cidr"]);if len(ips)==0{b.stats.fail("build wa_local.json",errors.New("Facebook IP CIDR list is empty"));return};log.Printf("  IP Facebook: %d",len(ips))
	data:=map[string]any{"version":3,"rules":[]any{map[string]any{"type":"logical","mode":"and","rules":[]any{map[string]any{"ip_cidr":ips},map[string]any{"port":b.cfg.waPorts}}}}}
	if b.dry{return};if err:=b.write("wa_local.json",data);err!=nil{b.stats.fail("write wa_local.json",err);return}
	if err:=b.cli.format("wa_local.json");err!=nil{b.stats.fail("format wa_local.json",err)}
}
func (b *builder) compileAll() {
	group("Langkah 6: Compile ke .srs");defer endGroup()
	set:=map[string]bool{}
	for _,n:=range b.cfg.local{set[n]=true}
	for n:=range b.cfg.sources{
		if strings.HasSuffix(n,".txt"){set[strings.TrimSuffix(n,".txt")+".json"]=true
		}else if strings.HasSuffix(n,".json")&&n!="doh.json"{set[n]=true}
	}
	for _,n:=range []string{"geoip-facebook.json","geoip-onlyid.json","adguard.json","adguard-custom.json"}{set[n]=true}
	names:=make([]string,0,len(set));for n:=range set{names=append(names,n)};sort.Strings(names)
	for _,n:=range names{
		if _,err:=os.Stat(b.path(n));err!=nil{b.stats.add(&b.stats.skipped,n);continue}
		if err:=b.cli.compile(n);err!=nil{log.Printf("ERROR compile %s: %v",n,err);gha("error",fmt.Sprintf("Gagal kompil %s: %v",n,err));b.stats.add(&b.stats.compileFailed,n);continue}
		log.Printf("Compiled %s",n);b.stats.add(&b.stats.compiled,n)
	}
}

func writeSummary(s *stats,elapsed time.Duration) {
	path:=os.Getenv("GITHUB_STEP_SUMMARY");if path==""{return}
	v:=s.snapshot();status:="✅ Berhasil";if len(v.downloadFailed)+len(v.compileFailed)>0{status="❌ Ada Kegagalan"}
	lines:=[]string{"## "+status+" — Sing-box Rule Set Builder",fmt.Sprintf("**Waktu build:** %s | **Durasi:** %.1fs",time.Now().UTC().Format("2006-01-02 15:04 UTC"),elapsed.Seconds()),"","| Metrik | Nilai |","|---|---|",fmt.Sprintf("| Download berhasil | %d/%d |",len(v.downloaded),len(v.downloaded)+len(v.downloadFailed)),fmt.Sprintf("| Download gagal | %d |",len(v.downloadFailed)),fmt.Sprintf("| Compile berhasil | %d |",len(v.compiled)),fmt.Sprintf("| Compile gagal | %d |",len(v.compileFailed)),fmt.Sprintf("| Dilewati | %d |",len(v.skipped)),fmt.Sprintf("| Kegagalan tahap | %d |",len(v.stageFailed))}
	if len(v.compiled)>0{lines=append(lines,"","### File SRS yang Dihasilkan","```");for _,n:=range v.compiled{lines=append(lines,"  "+strings.TrimSuffix(n,".json")+".srs")};lines=append(lines,"```")}
	if len(v.downloadFailed)>0{lines=append(lines,"","> ⚠️ **Gagal diunduh:** "+strings.Join(v.downloadFailed,", "))}
	if len(v.compileFailed)>0{lines=append(lines,"> ⚠️ **Gagal dikompil:** "+strings.Join(v.compileFailed,", "))}
	if len(v.stageFailed)>0{lines=append(lines,"> ⚠️ **Gagal tahap:** "+strings.Join(v.stageFailed,", "))}
	if err:=os.WriteFile(path,[]byte(strings.Join(lines,"\n")+"\n"),0644);err!=nil{log.Printf("WARNING step summary: %v",err)}
}

func run() int {
	cfg:=loadConfig()
	skip:=flag.Bool("skip-download",false,"Lewati download")
	only:=flag.Bool("only-compile",false,"Hanya compile")
	dry:=flag.Bool("dry-run",false,"Simulasi tanpa perubahan")
	failFast:=flag.Bool("fail-fast",false,"Hentikan pipeline jika download gagal")
	workers:=flag.Int("workers",min(len(cfg.sources),8),"Jumlah download paralel")
	verbose:=flag.Bool("verbose",false,"Log debug");flag.BoolVar(verbose,"v",false,"Log debug")
	flag.Parse()
	if *workers<1{log.Println("ERROR --workers harus >= 1");return 2}
	if *verbose{log.SetFlags(log.LstdFlags|log.Lmicroseconds)}
	start:=time.Now()
	log.Printf("SING-BOX RULE SET BUILDER (Go %s)",runtime.Version())
	log.Printf("sing-box=%s output=%s",cfg.version,cfg.output)
	if err:=os.MkdirAll(cfg.output,0755);err!=nil{log.Printf("ERROR output dir: %v",err);return 1}
	abs,err:=filepath.Abs(cfg.output);if err!=nil{log.Printf("ERROR output dir: %v",err);return 1};cfg.output=abs
	c:=&cli{bin:cfg.bin,dir:cfg.output,dry:*dry};if err:=c.check();err!=nil{log.Printf("ERROR %v",err);gha("error",err.Error());return 1}
	s:=&stats{};b:=&builder{cfg:cfg,cli:c,stats:s,dry:*dry}
	if *only{b.compileAll()}else{
		if !*skip{
			d:=&downloader{client:&http.Client{Timeout:45*time.Second},dir:cfg.output,stats:s,dry:*dry}
			d.all(context.Background(),cfg.sources,*workers)
			if *failFast&&len(s.snapshot().downloadFailed)>0{log.Println("ERROR download gagal (--fail-fast)");return 1}
		}else{log.Println("Download dilewati (--skip-download)")}
		b.convertAndDecompile();b.buildDoH();b.formatJSON();b.buildOnlyID();b.buildWALocal();b.compileAll()
	}
	v:=s.snapshot();elapsed:=time.Since(start)
	log.Printf("SUMMARY download=%d failed=%d compiled=%d compile_failed=%d stage_failed=%d skipped=%d",len(v.downloaded),len(v.downloadFailed),len(v.compiled),len(v.compileFailed),len(v.stageFailed),len(v.skipped))
	writeSummary(s,elapsed)
	if s.failed(){gha("error","Build selesai dengan error. Periksa log.");return 1}
	log.Printf("Build selesai dalam %.1fs",elapsed.Seconds());return 0
}
func main(){os.Exit(run())}
