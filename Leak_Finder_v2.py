#!/usr/bin/env python3
"""
leak_hunter.py — recursive sensitive string hunter for dirs, TARs, and ZIPs (incl. nested archives)

Usage:
  python3 leak_hunter.py /path/to/dir_or_archive [--max-bytes 4194304] [--force-text]
                        [--format table|csv|json]
                        [--include-cats mobile,generic]
                        [--exclude-cats aws,ai,payments]

Notes:
  - Reads EVERY readable file. Binary-ish files are skipped unless --force-text.
  - Supports nested archives (zip-in-zip, tar-in-zip, tar.gz-in-tar, etc.) in memory.
  - Prints exact values (NO MASKING). Be careful where you run this.
  - Exit code is 2 if any findings (handy for CI gates).
"""

import argparse
import io
import json
import os
import re
import sys
import tarfile
import zipfile
from datetime import datetime

# ---------- config ----------
TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
ZIP_EXTS = (".zip",)
ARCHIVE_EXTS = TAR_EXTS + ZIP_EXTS
DEFAULT_MAX_BYTES = 4 * 1024 * 1024  # 4 MiB cap per file

def is_tar_path(name: str) -> bool:
    return name.lower().endswith(TAR_EXTS)

def is_zip_path(name: str) -> bool:
    return name.lower().endswith(ZIP_EXTS)

def is_archive_path(name: str) -> bool:
    return name.lower().endswith(ARCHIVE_EXTS)

def looks_text(data: bytes) -> bool:
    # Heuristic: NUL byte in first KB => probably binary
    return b"\x00" not in data[:1024]

def safe_read_file(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(max_bytes)

# ---------- categories + patterns ----------
# Category map (used to include/exclude families of rules)
PATTERN_META = {
    # mobile / appium / adb
    "appium_udid": "mobile",
    "appium_device_name": "mobile",
    "adb_connect_cmd": "mobile",
    "adb_serial": "mobile",
    "adb_known_hosts": "mobile",
    "android_keystore_storepass": "mobile",
    "android_keystore_keypass": "mobile",
    "android_key_alias": "mobile",
    "google_services_api_key": "mobile",
    "xcode_org_id": "mobile",
    "xcode_signing_id": "mobile",
    "mobileprovision_uuid": "mobile",

    # generic auth / secrets
    "password": "generic",
    "token": "generic",
    "api_key": "generic",
    "client_secret": "generic",
    "basic_auth_url": "generic",
    "jwt": "generic",
    "private_key_header": "generic",
    "dockerhub_password": "generic",      # base64 user:pass in config.json
    "base64_blob_suspect": "generic",     # long base64 looking string

    # infra (non-aws/ai/payments)
    "kube_token": "infra",
    "helm_repo_auth": "infra",
    "postgres_url": "infra",
    "mysql_url": "infra",
    "mongodb_url": "infra",
    "redis_url": "infra",
    "snowflake_conn": "infra",

    # (These categories exist but are excluded by default)
    # "aws_access_key_id": "aws", "openai_api_key": "ai", "stripe_live_key": "payments", etc.
    # If you later add those rules, the category filtering will apply.
}

REGEX_PATTERNS = {
    # --- Mobile / Appium / ADB ---
    # DesiredCapabilities spill often
    "appium_udid": re.compile(r'(?i)\b(udid)\b\s*[:=]\s*["\']?([A-Za-z0-9\-\:_]{8,})["\']?'),
    "appium_device_name": re.compile(r'(?i)\b(deviceName)\b\s*[:=]\s*["\']?([A-Za-z0-9\-\._\s]{3,})["\']?'),
    # adb over Wi-Fi
    "adb_connect_cmd": re.compile(r'(?i)\badb\s+connect\s+(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'),
    # Serial-ish IDs (emulator-5554, hex-ish, OEM serials). Keep it reasonable to limit noise.
    "adb_serial": re.compile(r'\b(?:emulator-\d{4}|[A-F0-9]{8,16}|[A-Za-z0-9]{12,})\b'),
    # adb keys / known hosts in paths
    "adb_known_hosts": re.compile(r'(?i)\.android/(?:adbkey|adbkey\.pub|adb_known_hosts)\b'),
    # Android signing (Gradle)
    "android_keystore_storepass": re.compile(r'(?i)\bstorePassword\b\s*[:=]\s*["\']?([^\s"\']{4,})["\']?'),
    "android_keystore_keypass": re.compile(r'(?i)\bkeyPassword\b\s*[:=]\s*["\']?([^\s"\']{4,})["\']?'),
    "android_key_alias": re.compile(r'(?i)\bkeyAlias\b\s*[:=]\s*["\']?([^\s"\']{2,})["\']?'),
    # google-services.json (explicit)
    "google_services_api_key": re.compile(r'(?i)"current_key"\s*:\s*"([A-Za-z0-9_\-]{20,})"'),
    # iOS signing
    "xcode_org_id": re.compile(r'(?i)\b(xcodeOrgId|DEVELOPMENT_TEAM)\b\s*[:=]\s*["\']?([A-Z0-9]{10})["\']?'),
    "xcode_signing_id": re.compile(r'(?i)\b(xcodeSigningId)\b\s*[:=]\s*["\']?([A-Za-z \.]{3,})["\']?'),
    "mobileprovision_uuid": re.compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b'),

    # --- Generic secrets & auth ---
    "password": re.compile(r'(?i)\b(pass|passwd|password|pwd)\b\s*[:=]\s*["\']?([^"\']{3,})["\']?'),
    "token": re.compile(r'(?i)\b(access[-_ ]?token|auth[-_ ]?token|token|bearer)\b\s*[:=]\s*["\']?([A-Za-z0-9_\-\.=]{8,})["\']?'),
    "api_key": re.compile(r'(?i)\b(api[-_ ]?key|apikey|apiKey)\b\s*[:=]\s*["\']?([A-Za-z0-9_\-:/+=\.]{8,})["\']?'),
    "client_secret": re.compile(r'(?i)\b(client[-_ ]?secret|secret)\b\s*[:=]\s*["\']?([A-Za-z0-9/_\-\+=]{6,})["\']?'),
    "basic_auth_url": re.compile(r'(?i)\b[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+'),
    "jwt": re.compile(r'\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),
    "private_key_header": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

    # docker config.json auth (base64 of user:pass)
    "dockerhub_password": re.compile(r'(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"'),

    # --- Base64 suspects (generic, long) ---
    # Only triggers when preceded by a clue on the same line and 64+ chars of base64
    "base64_blob_suspect": re.compile(
        r'(?i)(?:secret|password|token|key|auth|bearer)\S*["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/]{64,}={0,2})["\']?'
    ),

    # --- Infra URLs with creds ---
    "postgres_url": re.compile(r'(?i)\bpostgres(?:ql)?://[^:\s/@]+:[^@\s]+@[^/\s:]+(?::\d+)?/[^?\s]+'),
    "mysql_url": re.compile(r'(?i)\bmysql://[^:\s/@]+:[^@\s]+@[^/\s:]+(?::\d+)?/[^?\s]+'),
    "mongodb_url": re.compile(r'(?i)\bmongodb(?:\+srv)?://[^:\s/@]+:[^@\s]+@[^/\s:]+'),
    "redis_url": re.compile(r'(?i)\bredis://[^:\s/@]+:[^@\s]+@[^/\s:]+'),
    "snowflake_conn": re.compile(r'(?i)\bsnowflake://[^:\s/@]+:[^@\s]+@[^/\s]+'),
}

# Preferential ordering (lower = louder)
ORDER = {
    # ultra-critical
    "private_key_header": 0,
    "dockerhub_password": 1,
    "jwt": 2,

    # mobile / appium / adb
    "android_keystore_storepass": 10,
    "android_keystore_keypass": 11,
    "android_key_alias": 12,
    "appium_udid": 13,
    "appium_device_name": 14,
    "adb_connect_cmd": 15,
    "adb_known_hosts": 16,
    "adb_serial": 17,
    "xcode_org_id": 18,
    "xcode_signing_id": 19,
    "mobileprovision_uuid": 20,
    "google_services_api_key": 21,

    # generic secrets
    "client_secret": 40,
    "api_key": 41,
    "token": 42,
    "password": 43,
    "basic_auth_url": 44,
    "base64_blob_suspect": 45,

    # infra
    "postgres_url": 60,
    "mysql_url": 61,
    "mongodb_url": 62,
    "redis_url": 63,
    "snowflake_conn": 64,
    "kube_token": 70,
    "helm_repo_auth": 71,
}

# ---------- category gate ----------
def _category_enabled(pattern_name: str, include_set, exclude_set):
    cat = PATTERN_META.get(pattern_name, "generic")
    if include_set and cat not in include_set:
        return False
    if cat in exclude_set:
        return False
    return True

# ---------- scanning ----------
def scan_text(buffer: str, virtual_path: str, include_set=None, exclude_set=None):
    results = []
    for lineno, line in enumerate(buffer.splitlines(), 1):
        for name, cregex in REGEX_PATTERNS.items():
            if not _category_enabled(name, include_set, exclude_set):
                continue
            for m in cregex.finditer(line):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                context = line.strip()
                results.append({
                    "path": virtual_path,
                    "line": lineno,
                    "type": name,
                    "value": value,   # NO MASKING
                    "raw_len": len(value),
                    "context": (context[:200] + "…") if len(context) > 200 else context,
                })
    return results

def scan_bytes(data: bytes, virtual_path: str, include_set=None, exclude_set=None):
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return scan_text(text, virtual_path, include_set, exclude_set)

def scan_tar_bytes(data: bytes, outer_path: str, max_bytes: int, force_text: bool,
                   include_set=None, exclude_set=None):
    findings = []
    bio = io.BytesIO(data)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                vpath = f"{outer_path}::{member.name}"
                if member.size <= 0:
                    continue
                f = tf.extractfile(member)
                if not f:
                    continue
                mbuf = f.read(max_bytes)
                if is_tar_path(member.name):
                    findings.extend(scan_tar_bytes(mbuf, vpath, max_bytes, force_text, include_set, exclude_set))
                    continue
                if is_zip_path(member.name):
                    findings.extend(scan_zip_bytes(mbuf, vpath, max_bytes, force_text, include_set, exclude_set))
                    continue
                if force_text or looks_text(mbuf):
                    findings.extend(scan_bytes(mbuf, vpath, include_set, exclude_set))
    except tarfile.ReadError:
        pass
    return findings

def scan_zip_bytes(data: bytes, outer_path: str, max_bytes: int, force_text: bool,
                   include_set=None, exclude_set=None):
    findings = []
    bio = io.BytesIO(data)
    try:
        with zipfile.ZipFile(bio) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                vpath = f"{outer_path}::{zi.filename}"
                with zf.open(zi, "r") as fh:
                    mbuf = fh.read(max_bytes)
                if is_tar_path(zi.filename):
                    findings.extend(scan_tar_bytes(mbuf, vpath, max_bytes, force_text, include_set, exclude_set))
                    continue
                if is_zip_path(zi.filename):
                    findings.extend(scan_zip_bytes(mbuf, vpath, max_bytes, force_text, include_set, exclude_set))
                    continue
                if force_text or looks_text(mbuf):
                    findings.extend(scan_bytes(mbuf, vpath, include_set, exclude_set))
    except zipfile.BadZipFile:
        pass
    return findings

def scan_path(path: str, max_bytes: int, force_text: bool, include_set=None, exclude_set=None):
    all_results = []
    if os.path.isdir(path):
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    buf = safe_read_file(fp, max_bytes)
                except (PermissionError, FileNotFoundError):
                    continue
                if is_tar_path(fp):
                    all_results.extend(scan_tar_bytes(buf, fp, max_bytes, force_text, include_set, exclude_set))
                elif is_zip_path(fp):
                    all_results.extend(scan_zip_bytes(buf, fp, max_bytes, force_text, include_set, exclude_set))
                else:
                    if force_text or looks_text(buf):
                        all_results.extend(scan_bytes(buf, fp, include_set, exclude_set))
    else:
        try:
            buf = safe_read_file(path, max_bytes)
        except (PermissionError, FileNotFoundError) as e:
            print(f"[warn] cannot read {path}: {e}", file=sys.stderr)
            return []
        if is_tar_path(path):
            all_results.extend(scan_tar_bytes(buf, path, max_bytes, force_text, include_set, exclude_set))
        elif is_zip_path(path):
            all_results.extend(scan_zip_bytes(buf, path, max_bytes, force_text, include_set, exclude_set))
        else:
            if force_text or looks_text(buf):
                all_results.extend(scan_bytes(buf, path, include_set, exclude_set))
    return all_results

# ---------- output ----------
def print_table(rows):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        console = Console()
        table = Table(title=f"Sensitive Findings ({len(rows)}) — {datetime.now().isoformat(timespec='seconds')}",
                      box=box.SIMPLE_HEAVY)
        table.add_column("#", justify="right", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Value / Snippet", style="magenta")
        table.add_column("File", style="green")
        table.add_column("Line", justify="right", style="yellow")
        for i, r in enumerate(rows, 1):
            val = r["value"]
            snip = r["context"]
            merged = val if val in snip else f"{val}\n… {snip}"
            table.add_row(str(i), r["type"], merged, r["path"], str(r["line"]))
        console.print(table)
    except Exception:
        from textwrap import shorten
        print("index\ttype\tvalue\tfile\tline")
        for i, r in enumerate(rows, 1):
            print("\t".join([
                str(i),
                r["type"],
                shorten(r["value"], width=120, placeholder="…"),
                shorten(r["path"], width=140, placeholder="…"),
                str(r["line"]),
            ]))

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Scan directory/TAR/ZIP (incl. nested archives) for sensitive strings.")
    ap.add_argument("target", help="Directory, tar, or zip to scan")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help=f"Max bytes to read per file (default {DEFAULT_MAX_BYTES})")
    ap.add_argument("--force-text", action="store_true",
                    help="Force treat files as text (skip binary sniff; slower)")
    ap.add_argument("--format", choices=["table", "csv", "json"], default="table",
                    help="Output format (default table)")
    ap.add_argument("--include-cats", default="",
                    help="Comma list of categories to include (others skipped). E.g. 'mobile,generic'")
    ap.add_argument("--exclude-cats", default="aws,ai,payments",
                    help="Comma list of categories to exclude (default: aws,ai,payments)")
    args = ap.parse_args()

    include_set = set([s.strip().lower() for s in args.include_cats.split(",") if s.strip()])
    exclude_set = set([s.strip().lower() for s in args.exclude_cats.split(",") if s.strip()])

    findings = scan_path(args.target, args.max_bytes, args.force_text, include_set, exclude_set)

    findings.sort(key=lambda r: (ORDER.get(r["type"], 999), r["path"], r["line"]))

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif args.format == "csv":
        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(["type", "value", "file", "line", "raw_len", "context"])
        for r in findings:
            writer.writerow([r["type"], r["value"], r["path"], r["line"], r["raw_len"], r["context"]])
    else:
        print_table(findings)

    sys.exit(2 if findings else 0)

if __name__ == "__main__":
    main()
