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
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# KONFIGURASI — ubah di sini atau via environment variable
# ─────────────────────────────────────────────────────────────────────────────

SINGBOX_BIN: str = os.environ.get("SINGBOX_BIN", "./sing-box")

# Semua output .srs dikumpulkan ke folder ini agar mudah di-glob di workflow
OUTPUT_DIR: str = os.environ.get("OUTPUT_DIR", ".")

SINGBOX_VERSION: str = os.environ.get("SINGBOX_VERSION", "1.14.0-alpha.28")

DOWNLOADS: dict[str, str] = {
    "adguard.txt":               "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "adguard-custom.txt":        "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist",
    "geoip-asnid.json":          "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-asnid.json",
    "geoip-id.json":             "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/geoip-id.json",
    "geoip-facebook.srs":        "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/facebook.srs",
    "geosite-ecommerce-id.json": "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/marketplace.json",
    "geosite-ewallet.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/ewallet.json",
    "geosite-bank-id.json":      "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/bank-id.json",
    "whatsapp.json":             "https://raw.githubusercontent.com/malikshi/route/refs/heads/release/srs/json/whatsapp.json",
}

# Berkas JSON lokal yang sudah ada di repo (tidak diunduh)
LOCAL_JSON_FILES: list[str] = [
    "cloudflared-direct.json", "cloudflared-proxy.json", "commonports.json",
    "direct-some-web.json",    "geosite-doh.json",       "hilook.json",
    "notifikasi.json",         "rule-direct-custom.json","rule-port-game.json",
    "wa_local.json",           "warped.json",
]

# Port filter untuk geoip-onlyid
ONLYID_PORTS: list[int] = sorted([
    21, 22, 23, 80, 81, 123, 143, 182, 183, 194, 443, 465, 587, 853,
    993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
    5222, 5228, 5229, 5230, 8000, 8080, 8081, 8088, 8443,
    8880, 8883, 8888, 8889, 42069,
])

# Port WhatsApp lokal
WA_LOCAL_PORTS: list[int] = [3478, 4244, 5222, 5223, 5242, 45395, 50318, 59234]

# ─────────────────────────────────────────────────────────────────────────────
# DETEKSI GITHUB ACTIONS
# ─────────────────────────────────────────────────────────────────────────────

IS_GHA: bool = os.environ.get("GITHUB_ACTIONS") == "true"
STEP_SUMMARY: Optional[str] = os.environ.get("GITHUB_STEP_SUMMARY")

def gha_group(title: str) -> None:
    """Buka collapsible group di GitHub Actions log."""
    if IS_GHA:
        print(f"::group::{title}", flush=True)

def gha_endgroup() -> None:
    if IS_GHA:
        print("::endgroup::", flush=True)

def gha_error(msg: str) -> None:
    if IS_GHA:
        print(f"::error::{msg}", flush=True)

def gha_warning(msg: str) -> None:
    if IS_GHA:
        print(f"::warning::{msg}", flush=True)

def gha_notice(msg: str) -> None:
    if IS_GHA:
        print(f"::notice::{msg}", flush=True)

def write_step_summary(content: str) -> None:
    """Tulis ke GITHUB_STEP_SUMMARY jika tersedia."""
    if STEP_SUMMARY:
        try:
            with open(STEP_SUMMARY, "a") as f:
                f.write(content + "\n")
        except OSError:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    # GitHub Actions sudah ada timestamp di log-nya, jadi cukup pakai format ringkas
    fmt = "%(levelname)-5s %(message)s" if IS_GHA else "[%(asctime)s] %(levelname)-5s %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S", stream=sys.stdout)

log = logging.getLogger("build_rules")

# ─────────────────────────────────────────────────────────────────────────────
# TRACKER STATISTIK
# ─────────────────────────────────────────────────────────────────────────────

class Stats:
    def __init__(self) -> None:
        self.downloaded:      list[str] = []
        self.download_failed: list[str] = []
        self.compiled:        list[str] = []
        self.compile_failed:  list[str] = []
        self.skipped:         list[str] = []

    @property
    def has_errors(self) -> bool:
        return bool(self.download_failed or self.compile_failed)

    def log_summary(self) -> None:
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

    def markdown_summary(self, elapsed: float) -> str:
        """Buat Markdown untuk GITHUB_STEP_SUMMARY."""
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


stats = Stats()

# ─────────────────────────────────────────────────────────────────────────────
# UTILITAS
# ─────────────────────────────────────────────────────────────────────────────

def download_file(
    filename: str,
    url: str,
    retries: int = 3,
    base_delay: float = 3.0,
    dry_run: bool = False,
) -> bool:
    """Unduh berkas dengan retry exponential backoff. Return True jika berhasil."""
    if dry_run:
        log.info(f"[DRY-RUN] Unduh: {filename}")
        return True

    for attempt in range(1, retries + 1):
        try:
            log.info(f"  [{attempt}/{retries}] Mengunduh: {filename}")
            req = urllib.request.Request(url, headers={"User-Agent": "sing-box-rule-builder/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            Path(filename).write_bytes(data)
            size_kb = len(data) / 1024
            log.debug(f"  -> Tersimpan: {filename} ({size_kb:.1f} KB)")
            stats.downloaded.append(filename)
            return True
        except Exception as exc:
            wait = base_delay * (2 ** (attempt - 1))
            if attempt < retries:
                log.warning(f"  -> Percobaan {attempt} gagal: {exc}. Retry dalam {wait:.0f}s...")
                time.sleep(wait)
            else:
                msg = f"Gagal mengunduh {filename} setelah {retries}x: {exc}"
                log.error(f"  -> {msg}")
                gha_error(msg)
                stats.download_failed.append(filename)
                return False
    return False  # tidak seharusnya dicapai


def run_command(args: list[str], dry_run: bool = False, check: bool = True) -> str:
    """Jalankan subprocess. Raise RuntimeError jika gagal dan check=True."""
    if dry_run:
        log.debug(f"[DRY-RUN] $ {' '.join(args)}")
        return ""
    log.debug(f"$ {' '.join(args)}")
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0 and check:
        err = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(err)
    return result.stdout


def load_json_safe(filepath: str) -> Optional[dict]:
    """Muat JSON, return None jika gagal."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning(f"  Berkas tidak ditemukan: {filepath}")
    except json.JSONDecodeError as exc:
        log.error(f"  JSON tidak valid di {filepath}: {exc}")
        gha_error(f"JSON tidak valid: {filepath}")
    return None


def write_json(filepath: str, data: dict, indent: int = 2) -> None:
    with open(filepath, "w") as f:
        json.dump(data, f, indent=indent)


def remove_files(filenames: list[str]) -> None:
    for f in filenames:
        p = Path(f)
        if p.exists():
            p.unlink()
            log.debug(f"  Dihapus: {f}")


def format_json_file(filepath: str, dry_run: bool = False) -> None:
    if Path(filepath).exists():
        try:
            run_command([SINGBOX_BIN, "rule-set", "format", filepath, "-w"], dry_run)
        except RuntimeError as exc:
            log.warning(f"  Format gagal untuk {filepath}: {exc}")
    else:
        stats.skipped.append(filepath)
        log.debug(f"  Dilewati (tidak ada): {filepath}")


def compile_rule(json_file: str, dry_run: bool = False) -> None:
    if not Path(json_file).exists():
        log.debug(f"  Dilewati (tidak ada): {json_file}")
        stats.skipped.append(json_file)
        return
    try:
        run_command([SINGBOX_BIN, "rule-set", "compile", json_file], dry_run)
        srs_file = json_file.replace(".json", ".srs")
        log.info(f"  Dikompil: {json_file} -> {srs_file}")
        stats.compiled.append(json_file)
    except RuntimeError as exc:
        msg = f"Gagal kompil {json_file}: {exc}"
        log.error(f"  {msg}")
        gha_error(msg)
        stats.compile_failed.append(json_file)

# ─────────────────────────────────────────────────────────────────────────────
# PARSER CLASH RULE PROVIDER
# ─────────────────────────────────────────────────────────────────────────────

def fetch_text(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sing-box-rule-builder/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        log.error(f"Gagal fetch text dari {url}: {exc}")
        return ""


def convert_clash_to_singbox(url: str) -> dict:
    """
    Konversi Clash Rule Provider (YAML/TXT) ke format sing-box v3.
    Mendukung: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6.
    """
    text = fetch_text(url)
    if not text:
        return {}

    domains:  set[str] = set()
    suffixes: set[str] = set()
    keywords: set[str] = set()
    regexes:  set[str] = set()
    ip_cidrs: set[str] = set()

    CLASH_RULE_MAP = {
        "DOMAIN":         domains,
        "DOMAIN-SUFFIX":  suffixes,
        "DOMAIN-KEYWORD": keywords,
        "DOMAIN-REGEX":   regexes,
        "IP-CIDR":        ip_cidrs,
        "IP-CIDR6":       ip_cidrs,
    }

    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("- ").strip("'\"")
        if not line or line.startswith(("#", "//")):
            continue

        if "," in line:
            parts = line.split(",", 2)
            rule_type = parts[0].strip().upper()
            value = parts[1].strip()
            if rule_type in CLASH_RULE_MAP:
                if rule_type == "DOMAIN-SUFFIX":
                    value = value if value.startswith(".") else f".{value}"
                CLASH_RULE_MAP[rule_type].add(value)
        elif "/" in line:
            ip_cidrs.add(line)

    rule: dict = {}
    if domains:   rule["domain"]         = sorted(domains)
    if suffixes:  rule["domain_suffix"]  = sorted(suffixes)
    if keywords:  rule["domain_keyword"] = sorted(keywords)
    if regexes:   rule["domain_regex"]   = sorted(regexes)
    if ip_cidrs:  rule["ip_cidr"]        = sorted(ip_cidrs)

    return {"version": 3, "rules": [rule]} if rule else {}

# ─────────────────────────────────────────────────────────────────────────────
# LANGKAH-LANGKAH BUILD
# ─────────────────────────────────────────────────────────────────────────────

def step_download(dry_run: bool, max_workers: int) -> None:
    gha_group("Langkah 1: Parallel Downloads")
    log.info("=" * 55)
    log.info("LANGKAH 1: Parallel Downloads")
    log.info("=" * 55)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(download_file, name, url, dry_run=dry_run): name
            for name, url in DOWNLOADS.items()
        }
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                log.error(f"Unexpected error: {exc}")

    if stats.download_failed:
        gha_warning(f"Download gagal: {', '.join(stats.download_failed)}")

    gha_endgroup()


def step_convert_and_decompile(dry_run: bool) -> None:
    gha_group("Langkah 2: Konversi AdGuard & Decompile Facebook")
    log.info("=" * 55)
    log.info("LANGKAH 2: Konversi AdGuard & Decompile Facebook")
    log.info("=" * 55)

    for fname, rule_type in [("adguard-custom.txt", "adguard"), ("adguard.txt", "adguard")]:
        if Path(fname).exists():
            run_command([SINGBOX_BIN, "rule-set", "convert", "--type", rule_type, fname], dry_run)
        else:
            log.warning(f"  Dilewati (tidak ada): {fname}")

    if Path("geoip-facebook.srs").exists():
        run_command([SINGBOX_BIN, "rule-set", "decompile", "geoip-facebook.srs", "-o", "geoip-facebook.json"], dry_run)
    else:
        log.warning("  Dilewati: geoip-facebook.srs tidak ditemukan")

    remove_files(["adguard.txt", "adguard-custom.txt", "geoip-facebook.srs"])
    gha_endgroup()


def step_format_json(dry_run: bool) -> None:
    gha_group("Langkah 3: Format Berkas JSON")
    log.info("=" * 55)
    log.info("LANGKAH 3: Format Berkas JSON")
    log.info("=" * 55)

    downloaded_json = [f for f in DOWNLOADS if f.endswith(".json")]
    all_targets = LOCAL_JSON_FILES + downloaded_json + ["geoip-facebook.json"]

    for filepath in all_targets:
        format_json_file(filepath, dry_run)

    gha_endgroup()


def step_build_geoip_onlyid(dry_run: bool) -> None:
    gha_group("Langkah 4: Build geoip-onlyid.json")
    log.info("=" * 55)
    log.info("LANGKAH 4: Build geoip-onlyid.json")
    log.info("=" * 55)

    asnid   = load_json_safe("geoip-asnid.json")
    geoip_id = load_json_safe("geoip-id.json")

    if not asnid or not geoip_id:
        log.error("  Gagal memuat sumber data — langkah dilewati.")
        gha_error("geoip-asnid.json atau geoip-id.json tidak tersedia")
        gha_endgroup()
        return

    raw_ips: list[str] = (
        asnid["rules"][0].get("ip_cidr", []) +
        geoip_id["rules"][0].get("ip_cidr", [])
    )

    ipv4_nets: list[ipaddress.IPv4Network] = []
    ipv6_nets: list[ipaddress.IPv6Network] = []
    invalid = 0

    for cidr in raw_ips:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if net.version == 4:
                ipv4_nets.append(net)  # type: ignore[arg-type]
            else:
                ipv6_nets.append(net)  # type: ignore[arg-type]
        except ValueError:
            invalid += 1

    if invalid:
        log.warning(f"  {invalid} entri CIDR tidak valid diabaikan.")
        gha_warning(f"{invalid} entri CIDR tidak valid pada geoip-onlyid")

    optimized = (
        [str(n) for n in ipaddress.collapse_addresses(ipv4_nets)] +
        [str(n) for n in ipaddress.collapse_addresses(ipv6_nets)]
    )
    log.info(f"  CIDR: {len(raw_ips):,} asli -> {len(optimized):,} setelah optimasi")
    gha_notice(f"geoip-onlyid: {len(raw_ips):,} CIDR -> {len(optimized):,} (hemat {len(raw_ips)-len(optimized):,})")

    data = {
        "version": 3,
        "rules": [{
            "type": "logical",
            "mode": "and",
            "rules": [
                {"ip_cidr": optimized},
                {"port": ONLYID_PORTS},
            ],
        }],
    }

    if not dry_run:
        write_json("geoip-onlyid.json", data)
        run_command([SINGBOX_BIN, "rule-set", "format", "geoip-onlyid.json", "-w"])

    gha_endgroup()


def step_build_wa_local(dry_run: bool) -> None:
    gha_group("Langkah 5: Build wa_local.json")
    log.info("=" * 55)
    log.info("LANGKAH 5: Build wa_local.json")
    log.info("=" * 55)

    fb = load_json_safe("geoip-facebook.json")
    if not fb:
        log.error("  Gagal memuat geoip-facebook.json — langkah dilewati.")
        gha_error("geoip-facebook.json tidak tersedia untuk wa_local")
        gha_endgroup()
        return

    fb_ips: list[str] = fb["rules"][0].get("ip_cidr", [])
    log.info(f"  IP Facebook: {len(fb_ips):,} entri")

    data = {
        "version": 3,
        "rules": [{
            "type": "logical",
            "mode": "and",
            "rules": [
                {"ip_cidr": fb_ips},
                {"port": WA_LOCAL_PORTS},
            ],
        }],
    }

    if not dry_run:
        write_json("wa_local.json", data)
        run_command([SINGBOX_BIN, "rule-set", "format", "wa_local.json", "-w"])

    gha_endgroup()


def step_compile_all(dry_run: bool) -> None:
    gha_group("Langkah 6: Compile ke .srs")
    log.info("=" * 55)
    log.info("LANGKAH 6: Compile ke .srs")
    log.info("=" * 55)

    # Berkas yang diunduh sebagai .txt dikonversi menjadi .json
    downloaded_json = [f.replace(".txt", ".json") for f in DOWNLOADS if f.endswith(".txt")]
    downloaded_json += [f for f in DOWNLOADS if f.endswith(".json")]

    all_targets: list[str] = sorted(set(
        LOCAL_JSON_FILES
        + downloaded_json
        + ["geoip-facebook.json", "geoip-onlyid.json", "adguard.json", "adguard-custom.json"]
    ))

    for filepath in all_targets:
        compile_rule(filepath, dry_run)

    gha_endgroup()

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sing-box Rule Set Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--skip-download",  action="store_true", help="Lewati download.")
    parser.add_argument("--only-compile",   action="store_true", help="Hanya compile (langkah 6).")
    parser.add_argument("--dry-run",        action="store_true", help="Simulasi tanpa eksekusi nyata.")
    parser.add_argument("--fail-fast",      action="store_true", help="Hentikan pipeline jika download gagal.")
    parser.add_argument("--workers", type=int, default=min(len(DOWNLOADS), 8),
                        help="Jumlah thread download paralel.")
    parser.add_argument("--verbose", "-v",  action="store_true", help="Log debug.")
    return parser.parse_args()


def check_singbox_bin() -> None:
    if not Path(SINGBOX_BIN).exists():
        msg = f"Binary sing-box tidak ditemukan: {SINGBOX_BIN}"
        log.error(msg)
        gha_error(msg)
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    start_time = datetime.now()

    log.info("=" * 55)
    log.info("SING-BOX RULE SET BUILDER")
    log.info(f"  Versi sing-box : {SINGBOX_VERSION}")
    log.info(f"  Mulai          : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    log.info(f"  GitHub Actions : {'Ya' if IS_GHA else 'Tidak'}")
    if args.dry_run:
        log.info("  Mode DRY-RUN aktif")
    log.info("=" * 55)

    check_singbox_bin()

    if args.only_compile:
        step_compile_all(args.dry_run)
    else:
        if not args.skip_download:
            step_download(args.dry_run, args.workers)

            if args.fail_fast and stats.download_failed:
                log.error("Gagal download kritis — pipeline dihentikan (--fail-fast).")
                gha_error("Build dihentikan karena download gagal.")
                sys.exit(1)
        else:
            log.info("Download dilewati (--skip-download).")

        step_convert_and_decompile(args.dry_run)
        step_format_json(args.dry_run)
        step_build_geoip_onlyid(args.dry_run)
        step_build_wa_local(args.dry_run)
        step_compile_all(args.dry_run)

    elapsed = (datetime.now() - start_time).total_seconds()

    stats.log_summary()
    log.info(f"Total waktu: {elapsed:.1f} detik")

    # Tulis ringkasan ke GitHub Step Summary
    write_step_summary(stats.markdown_summary(elapsed))

    # Exit code non-zero jika ada kegagalan — penting untuk CI
    if stats.has_errors:
        gha_error("Build selesai dengan error. Periksa log di atas.")
        sys.exit(1)

    log.info("Build selesai!")


if __name__ == "__main__":
    main()