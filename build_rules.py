#!/usr/bin/env python3

import os
import sys
import json
import time
import logging
import argparse
import ipaddress
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Any, Callable


# ─────────────────────────────────────────────────────────────────────────────
# KONFIGURASI DAN KONSTANTA
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AppConfig:
    """Konfigurasi aplikasi yang bisa di-override via environment variable."""
    singbox_bin: str = os.environ.get("SINGBOX_BIN", "./sing-box")
    output_dir: Path = Path(os.environ.get("OUTPUT_DIR", "."))
    singbox_version: str = os.environ.get("SINGBOX_VERSION", "1.14.0-alpha.28")

    downloads: dict[str, str] = field(default_factory=lambda: {
        "adguard.txt":               "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "adguard-custom.txt":        "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist",
        "doh.json":                  "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/doh.json",
        "geoip-asnid.json":          "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-asnid.json",
        "geoip-id.json":             "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-id.json",
        "geoip-facebook.srs":        "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/facebook.srs",
        "geosite-ecommerce-id.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/marketplace.json",
        "geosite-ewallet.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/ewallet.json",
        "geosite-bank-id.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/bank-id.json",
        "whatsapp.json":             "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/whatsapp.json",
    })

    local_json_files: list[str] = field(default_factory=lambda: [
        "cloudflared-direct.json", "cloudflared-proxy.json", "commonports.json",
        "direct-some-web.json",    "geoip-doh.json",         "geosite-doh.json",
        "hilook.json",             "notifikasi.json",         "rule-direct-custom.json",
        "rule-port-game.json",     "port-games.json",         "wa_local.json",
        "warped.json",
    ])

    onlyid_ports: list[int] = field(default_factory=lambda: sorted([
        21, 22, 23, 80, 81, 123, 143, 182, 183, 194, 443, 465, 587, 853,
        993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
        5222, 5228, 5229, 5230, 8000, 8080, 8081, 8088, 8443,
        8880, 8883, 8888, 8889, 42069,
    ]))

    wa_local_ports: list[int] = field(default_factory=lambda: [
        3478, 4244, 5222, 5223, 5242, 45395, 50318, 59234
    ])

    is_gha: bool = os.environ.get("GITHUB_ACTIONS") == "true"
    step_summary: Optional[str] = os.environ.get("GITHUB_STEP_SUMMARY")

CONFIG = AppConfig()


# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTION & LOGGING
# ─────────────────────────────────────────────────────────────────────────────

class BuildError(Exception):
    """Exception dasar untuk proses build."""
    pass

class DownloadError(BuildError):
    """Exception khusus untuk kegagalan unduh."""
    pass

class SingBoxError(BuildError):
    """Exception saat interaksi dengan CLI sing-box gagal."""
    pass

log = logging.getLogger("build_rules")

class GHActionsLogger:
    """Helper untuk berinteraksi dengan output GitHub Actions."""
    
    @staticmethod
    def group(title: str) -> None:
        if CONFIG.is_gha:
            print(f"::group::{title}", flush=True)

    @staticmethod
    def endgroup() -> None:
        if CONFIG.is_gha:
            print("::endgroup::", flush=True)

    @staticmethod
    def error(msg: str) -> None:
        if CONFIG.is_gha:
            print(f"::error::{msg}", flush=True)

    @staticmethod
    def warning(msg: str) -> None:
        if CONFIG.is_gha:
            print(f"::warning::{msg}", flush=True)

    @staticmethod
    def notice(msg: str) -> None:
        if CONFIG.is_gha:
            print(f"::notice::{msg}", flush=True)

    @staticmethod
    def write_step_summary(content: str) -> None:
        if CONFIG.step_summary:
            try:
                Path(CONFIG.step_summary).write_text(content + "\n", encoding="utf-8")
            except OSError as exc:
                log.warning(f"Gagal menulis ke GITHUB_STEP_SUMMARY: {exc}")

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(levelname)-5s %(message)s" if CONFIG.is_gha else "[%(asctime)s] %(levelname)-5s %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S", stream=sys.stdout)


# ─────────────────────────────────────────────────────────────────────────────
# KELAS UTILITAS & KOMPONEN
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Stats:
    """Melacak statistik jalannya proses build."""
    downloaded: list[str] = field(default_factory=list)
    download_failed: list[str] = field(default_factory=list)
    compiled: list[str] = field(default_factory=list)
    compile_failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return bool(self.download_failed or self.compile_failed)

    def print_summary(self) -> None:
        total_dl = len(self.downloaded) + len(self.download_failed)
        lines = [
            "=" * 55,
            "RINGKASAN BUILD",
            "=" * 55,
            f"  Download berhasil  : {len(self.downloaded)}/{total_dl}",
            f"  Download gagal     : {len(self.download_failed)}",
            f"  Compile berhasil   : {len(self.compiled)}",
            f"  Compile gagal      : {len(self.compile_failed)}",
            f"  Dilewati           : {len(self.skipped)}",
        ]
        if self.download_failed:
            lines.append(f"  [!] Gagal diunduh  : {', '.join(self.download_failed)}")
        if self.compile_failed:
            lines.append(f"  [!] Gagal dikompil : {', '.join(self.compile_failed)}")
        lines.append("=" * 55)
        for line in lines:
            log.info(line)

    def generate_markdown(self, elapsed: float) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total_dl = len(self.downloaded) + len(self.download_failed)
        status = "✅ Berhasil" if not self.has_errors else "❌ Ada Kegagalan"

        lines = [
            f"## {status} — Sing-box Rule Set Builder",
            f"**Waktu build:** {now} | **Durasi:** {elapsed:.1f}s",
            "",
            "| Metrik | Nilai |",
            "|--------|-------|",
            f"| Download berhasil | {len(self.downloaded)}/{total_dl} |",
            f"| Download gagal | {len(self.download_failed)} |",
            f"| Compile berhasil | {len(self.compiled)} |",
            f"| Compile gagal | {len(self.compile_failed)} |",
            f"| Dilewati | {len(self.skipped)} |",
        ]

        if self.compiled:
            lines += ["", "### File SRS yang Dihasilkan", "```"]
            lines += [f"  {f.replace('.json', '.srs')}" for f in self.compiled]
            lines.append("```")

        if self.download_failed:
            lines += ["", f"> ⚠️ **Gagal diunduh:** {', '.join(self.download_failed)}"]
        if self.compile_failed:
            lines += [f"> ⚠️ **Gagal dikompil:** {', '.join(self.compile_failed)}"]

        return "\n".join(lines)


class Downloader:
    """Menangani pengunduhan sumber file eksternal dengan paralelisme dan retry."""
    
    def __init__(self, stats: Stats, dry_run: bool = False):
        self.stats = stats
        self.dry_run = dry_run
        self.headers = {"User-Agent": "sing-box-rule-builder/2.0"}

    def download_file(self, filename: str, url: str, retries: int = 3, base_delay: float = 3.0) -> bool:
        if self.dry_run:
            log.info(f"[DRY-RUN] Unduh: {filename}")
            return True

        filepath = Path(filename)
        for attempt in range(1, retries + 1):
            try:
                log.info(f"  [{attempt}/{retries}] Mengunduh: {filename}")
                req = urllib.request.Request(url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                
                filepath.write_bytes(data)
                size_kb = len(data) / 1024
                log.debug(f"  -> Tersimpan: {filename} ({size_kb:.1f} KB)")
                self.stats.downloaded.append(filename)
                return True
            except (urllib.error.URLError, OSError) as exc:
                wait = base_delay * (2 ** (attempt - 1))
                if attempt < retries:
                    log.warning(f"  -> Percobaan {attempt} gagal: {exc}. Retry dalam {wait:.0f}s...")
                    time.sleep(wait)
                else:
                    msg = f"Gagal mengunduh {filename} setelah {retries}x: {exc}"
                    log.error(f"  -> {msg}")
                    GHActionsLogger.error(msg)
                    self.stats.download_failed.append(filename)
                    return False
        return False

    def fetch_all(self, max_workers: int) -> None:
        GHActionsLogger.group("Langkah 1: Parallel Downloads")
        log.info("=" * 55)
        log.info("LANGKAH 1: Parallel Downloads")
        log.info("=" * 55)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self.download_file, name, url): name
                for name, url in CONFIG.downloads.items()
            }
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    log.error(f"Kesalahan tak terduga saat mengunduh: {exc}")

        if self.stats.download_failed:
            GHActionsLogger.warning(f"Download gagal: {', '.join(self.stats.download_failed)}")
            
        GHActionsLogger.endgroup()


class SingBoxCLI:
    """Wrapper untuk memanggil binary sing-box."""
    
    def __init__(self, bin_path: str, dry_run: bool = False):
        self.bin_path = bin_path
        self.dry_run = dry_run

    def check_availability(self) -> None:
        import shutil
        if not Path(self.bin_path).exists() and shutil.which(self.bin_path) is None:
            msg = f"Binary sing-box tidak ditemukan: {self.bin_path}"
            log.error(msg)
            GHActionsLogger.error(msg)
            sys.exit(1)

    def _run(self, args: list[str]) -> str:
        if self.dry_run:
            log.debug(f"[DRY-RUN] $ {' '.join(args)}")
            return ""
        
        log.debug(f"$ {' '.join(args)}")
        result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            raise SingBoxError(err)
        return result.stdout

    def convert(self, rule_type: str, filepath: str) -> None:
        self._run([self.bin_path, "rule-set", "convert", "--type", rule_type, filepath])

    def decompile(self, srs_path: str, json_path: str) -> None:
        self._run([self.bin_path, "rule-set", "decompile", srs_path, "-o", json_path])

    def format(self, filepath: str) -> None:
        self._run([self.bin_path, "rule-set", "format", filepath, "-w"])

    def compile(self, json_path: str) -> None:
        self._run([self.bin_path, "rule-set", "compile", json_path])


# ─────────────────────────────────────────────────────────────────────────────
# BUILDER LOGIC
# ─────────────────────────────────────────────────────────────────────────────

class RuleBuilder:
    """Mengelola keseluruhan alur transformasi dan pembuatan ruleset."""
    
    def __init__(self, cli: SingBoxCLI, stats: Stats, dry_run: bool = False):
        self.cli = cli
        self.stats = stats
        self.dry_run = dry_run

    def safe_load_json(self, filepath: Path) -> Optional[dict[str, Any]]:
        try:
            return json.loads(filepath.read_text(encoding='utf-8'))
        except FileNotFoundError:
            log.warning(f"  Berkas tidak ditemukan: {filepath}")
        except json.JSONDecodeError as exc:
            log.error(f"  JSON tidak valid di {filepath}: {exc}")
            GHActionsLogger.error(f"JSON tidak valid: {filepath}")
        return None

    def write_json(self, filepath: Path, data: dict[str, Any]) -> None:
        filepath.write_text(json.dumps(data, indent=2), encoding='utf-8')

    def cleanup_files(self, filenames: list[str]) -> None:
        for f in filenames:
            p = Path(f)
            if p.exists():
                p.unlink()
                log.debug(f"  Dihapus: {f}")

    def step_convert_and_decompile(self) -> None:
        GHActionsLogger.group("Langkah 2: Konversi AdGuard & Decompile Facebook")
        log.info("=" * 55)
        log.info("LANGKAH 2: Konversi AdGuard & Decompile Facebook")
        log.info("=" * 55)

        for fname, rule_type in [("adguard-custom.txt", "adguard"), ("adguard.txt", "adguard")]:
            if Path(fname).exists():
                try:
                    self.cli.convert(rule_type, fname)
                except SingBoxError as e:
                    log.warning(f"  Gagal konversi {fname}: {e}")
            else:
                log.warning(f"  Dilewati (tidak ada): {fname}")

        if Path("geoip-facebook.srs").exists():
            try:
                self.cli.decompile("geoip-facebook.srs", "geoip-facebook.json")
            except SingBoxError as e:
                log.warning(f"  Gagal decompile geoip-facebook.srs: {e}")
        else:
            log.warning("  Dilewati: geoip-facebook.srs tidak ditemukan")

        self.cleanup_files(["adguard.txt", "adguard-custom.txt", "geoip-facebook.srs"])
        GHActionsLogger.endgroup()

    def step_build_doh(self) -> None:
        GHActionsLogger.group("Langkah 2b: Pemisahan doh.json")
        log.info("=" * 55)
        log.info("LANGKAH 2b: Pemisahan doh.json")
        log.info("=" * 55)

        doh_path = Path("doh.json")
        if not doh_path.exists():
            log.warning("  Dilewati: doh.json tidak ditemukan")
            GHActionsLogger.endgroup()
            return

        doh = self.safe_load_json(doh_path)
        if not doh:
            log.error("  Gagal memuat doh.json — langkah dilewati.")
            GHActionsLogger.error("doh.json tidak valid atau tidak bisa dimuat")
            GHActionsLogger.endgroup()
            return

        rules = doh.get("rules", [])
        if not rules:
            log.error("  Tidak ada rules di doh.json — langkah dilewati.")
            GHActionsLogger.endgroup()
            return

        rule = rules[0]
        domain_suffixes = rule.get("domain_suffix", [])
        ip_cidrs = rule.get("ip_cidr", [])

        geosite_doh = {"version": 3, "rules": [{"domain_suffix": domain_suffixes}]}
        geoip_doh = {"version": 3, "rules": [{"ip_cidr": ip_cidrs}]}

        if not self.dry_run:
            self.write_json(Path("geosite-doh.json"), geosite_doh)
            log.info("  Dibuat: geosite-doh.json")
            
            self.write_json(Path("geoip-doh.json"), geoip_doh)
            log.info("  Dibuat: geoip-doh.json")

        self.cleanup_files(["doh.json"])
        GHActionsLogger.endgroup()

    def step_format_json(self) -> None:
        GHActionsLogger.group("Langkah 3: Format Berkas JSON")
        log.info("=" * 55)
        log.info("LANGKAH 3: Format Berkas JSON")
        log.info("=" * 55)

        downloaded_json = [f for f in CONFIG.downloads.keys() if f.endswith(".json") and f != "doh.json"]
        all_targets = set(CONFIG.local_json_files + downloaded_json + ["geoip-facebook.json"])

        for filepath in sorted(all_targets):
            if Path(filepath).exists():
                try:
                    self.cli.format(filepath)
                except SingBoxError as exc:
                    log.warning(f"  Format gagal untuk {filepath}: {exc}")
            else:
                self.stats.skipped.append(filepath)
                log.debug(f"  Dilewati (tidak ada): {filepath}")

        GHActionsLogger.endgroup()

    def step_build_geoip_onlyid(self) -> None:
        GHActionsLogger.group("Langkah 4: Build geoip-onlyid.json")
        log.info("=" * 55)
        log.info("LANGKAH 4: Build geoip-onlyid.json")
        log.info("=" * 55)

        asnid = self.safe_load_json(Path("geoip-asnid.json"))
        geoip_id = self.safe_load_json(Path("geoip-id.json"))

        if not asnid or not geoip_id:
            log.error("  Gagal memuat sumber data — langkah dilewati.")
            GHActionsLogger.error("geoip-asnid.json atau geoip-id.json tidak tersedia")
            GHActionsLogger.endgroup()
            return

        raw_ips: list[str] = (
            asnid.get("rules", [{}])[0].get("ip_cidr", []) +
            geoip_id.get("rules", [{}])[0].get("ip_cidr", [])
        )

        ipv4_nets: list[ipaddress.IPv4Network] = []
        ipv6_nets: list[ipaddress.IPv6Network] = []
        invalid = 0

        for cidr in raw_ips:
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                if net.version == 4:
                    ipv4_nets.append(net) # type: ignore
                else:
                    ipv6_nets.append(net) # type: ignore
            except ValueError:
                invalid += 1

        if invalid:
            log.warning(f"  {invalid} entri CIDR tidak valid diabaikan.")
            GHActionsLogger.warning(f"{invalid} entri CIDR tidak valid pada geoip-onlyid")

        optimized = (
            [str(n) for n in ipaddress.collapse_addresses(ipv4_nets)] +
            [str(n) for n in ipaddress.collapse_addresses(ipv6_nets)]
        )
        log.info(f"  CIDR: {len(raw_ips):,} asli -> {len(optimized):,} setelah optimasi")
        GHActionsLogger.notice(f"geoip-onlyid: {len(raw_ips):,} CIDR -> {len(optimized):,} (hemat {len(raw_ips)-len(optimized):,})")

        data = {
            "version": 3,
            "rules": [{
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"ip_cidr": optimized},
                    {"port": CONFIG.onlyid_ports},
                ],
            }],
        }

        if not self.dry_run:
            tgt = Path("geoip-onlyid.json")
            self.write_json(tgt, data)
            try:
                self.cli.format(str(tgt))
            except SingBoxError as e:
                log.warning(f"  Format gagal untuk {tgt}: {e}")

        GHActionsLogger.endgroup()

    def step_build_wa_local(self) -> None:
        GHActionsLogger.group("Langkah 5: Build wa_local.json")
        log.info("=" * 55)
        log.info("LANGKAH 5: Build wa_local.json")
        log.info("=" * 55)

        fb = self.safe_load_json(Path("geoip-facebook.json"))
        if not fb:
            log.error("  Gagal memuat geoip-facebook.json — langkah dilewati.")
            GHActionsLogger.error("geoip-facebook.json tidak tersedia untuk wa_local")
            GHActionsLogger.endgroup()
            return

        fb_ips: list[str] = fb.get("rules", [{}])[0].get("ip_cidr", [])
        log.info(f"  IP Facebook: {len(fb_ips):,} entri")

        data = {
            "version": 3,
            "rules": [{
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"ip_cidr": fb_ips},
                    {"port": CONFIG.wa_local_ports},
                ],
            }],
        }

        if not self.dry_run:
            tgt = Path("wa_local.json")
            self.write_json(tgt, data)
            try:
                self.cli.format(str(tgt))
            except SingBoxError as e:
                log.warning(f"  Format gagal untuk {tgt}: {e}")

        GHActionsLogger.endgroup()

    def step_compile_all(self) -> None:
        GHActionsLogger.group("Langkah 6: Compile ke .srs")
        log.info("=" * 55)
        log.info("LANGKAH 6: Compile ke .srs")
        log.info("=" * 55)

        downloaded_json = [f.replace(".txt", ".json") for f in CONFIG.downloads.keys() if f.endswith(".txt")]
        downloaded_json += [f for f in CONFIG.downloads.keys() if f.endswith(".json") and f != "doh.json"]

        all_targets = sorted(set(
            CONFIG.local_json_files
            + downloaded_json
            + ["geoip-facebook.json", "geoip-onlyid.json", "adguard.json", "adguard-custom.json"]
        ))

        for filepath in all_targets:
            if not Path(filepath).exists():
                log.debug(f"  Dilewati (tidak ada): {filepath}")
                self.stats.skipped.append(filepath)
                continue
            
            try:
                self.cli.compile(filepath)
                srs_file = filepath.replace(".json", ".srs")
                log.info(f"  Dikompil: {filepath} -> {srs_file}")
                self.stats.compiled.append(filepath)
            except SingBoxError as exc:
                msg = f"Gagal kompil {filepath}: {exc}"
                log.error(f"  {msg}")
                GHActionsLogger.error(msg)
                self.stats.compile_failed.append(filepath)

        GHActionsLogger.endgroup()


# ─────────────────────────────────────────────────────────────────────────────
# CLI & MAIN ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sing-box Rule Set Builder (Modernized)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--skip-download",  action="store_true", help="Lewati download.")
    parser.add_argument("--only-compile",   action="store_true", help="Hanya compile (langkah 6).")
    parser.add_argument("--dry-run",        action="store_true", help="Simulasi tanpa eksekusi nyata.")
    parser.add_argument("--fail-fast",      action="store_true", help="Hentikan pipeline jika download gagal.")
    parser.add_argument("--workers", type=int, default=min(len(CONFIG.downloads), 8),
                        help="Jumlah thread download paralel.")
    parser.add_argument("--verbose", "-v",  action="store_true", help="Log debug.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    start_time = datetime.now(timezone.utc)

    log.info("=" * 55)
    log.info("SING-BOX RULE SET BUILDER")
    log.info(f"  Versi sing-box : {CONFIG.singbox_version}")
    log.info(f"  Mulai          : {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    log.info(f"  GitHub Actions : {'Ya' if CONFIG.is_gha else 'Tidak'}")
    if args.dry_run:
        log.info("  Mode DRY-RUN aktif")
    log.info("=" * 55)

    cli = SingBoxCLI(CONFIG.singbox_bin, dry_run=args.dry_run)
    cli.check_availability()
    
    stats = Stats()
    builder = RuleBuilder(cli, stats, dry_run=args.dry_run)
    downloader = Downloader(stats, dry_run=args.dry_run)

    if args.only_compile:
        builder.step_compile_all()
    else:
        if not args.skip_download:
            downloader.fetch_all(max_workers=args.workers)
            if args.fail_fast and stats.download_failed:
                msg = "Gagal download kritis — pipeline dihentikan (--fail-fast)."
                log.error(msg)
                GHActionsLogger.error(msg)
                sys.exit(1)
        else:
            log.info("Download dilewati (--skip-download).")

        builder.step_convert_and_decompile()
        builder.step_build_doh()
        builder.step_format_json()
        builder.step_build_geoip_onlyid()
        builder.step_build_wa_local()
        builder.step_compile_all()

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    stats.print_summary()
    log.info(f"Total waktu: {elapsed:.1f} detik")

    GHActionsLogger.write_step_summary(stats.generate_markdown(elapsed))

    if stats.has_errors:
        GHActionsLogger.error("Build selesai dengan error. Periksa log di atas.")
        sys.exit(1)

    log.info("Build selesai!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBuild dibatalkan oleh pengguna.")
        sys.exit(130)