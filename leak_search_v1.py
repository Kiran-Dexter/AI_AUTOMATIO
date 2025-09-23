#!/usr/bin/env python3
"""
leak_hunter.py — recursive sensitive string hunter for dirs and tar files (incl. nested tars)

Usage:
  python3 leak_hunter.py /path/to/dir_or_tar [--max-bytes 4194304] [--mask false] [--format table|csv|json]

Tips:
  - Works on directories and .tar / .tar.gz / .tgz / .tar.bz2 / .tar.xz
  - Scans nested tar members without extracting to disk
  - Skips likely-binary files by sniffing for NUL bytes (configurable via --force-text)
  - Limits per-file bytes (default 4 MiB) to keep it fast; bump with --max-bytes if needed
"""

import argparse
import io
import json
import os
import re
import sys
import tarfile
from datetime import datetime

# ---------- config ----------
TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
LOG_LIKE_EXTS = (
    ".log", ".txt", ".cfg", ".ini", ".env", ".yaml", ".yml", ".json",
    ".xml", ".properties", ".conf", ".sh", ".bash", ".zsh", ".ps1",
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".rs", ".cs", ".c", ".cpp",
)
DEFAULT_MAX_BYTES = 4 * 1024 * 1024  # 4 MiB

# Sensitive patterns (add more as needed)
REGEX_PATTERNS = {
    # Generic key=value (json/yaml/etc.)
    "api_key": re.compile(r'(?i)\b(api[-_ ]?key|apikey|apiKey)\b\s*[:=]\s*["\']?([A-Za-z0-9_\-:/+=\.]{8,})["\']?'),
    "token": re.compile(r'(?i)\b(access[-_ ]?token|auth[-_ ]?token|token|bearer)\b\s*[:=]\s*["\']?([A-Za-z0-9_\-\.=]{8,})["\']?'),
    "password": re.compile(r'(?i)\b(pass|passwd|password|pwd)\b\s*[:=]\s*["\']?([^"\']{3,})["\']?'),
    "client_secret": re.compile(r'(?i)\b(client[-_ ]?secret|secret)\b\s*[:=]\s*["\']?([A-Za-z0-9/_\-\+=]{6,})["\']?'),

    # Cloud / common creds
    "aws_access_key_id": re.compile(r'\b(AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA)[0-9A-Z]{16}\b'),
    "aws_secret_access_key": re.compile(r'(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    "gcp_api_key": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "github_pat": re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
    "slack_token": re.compile(r'\bxox[abprs]-[0-9A-Za-z-]{10,48}\b'),

    # JWT
    "jwt": re.compile(r'\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),

    # Private keys
    "private_key_header": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

    # URLs with embedded basic auth (user:pass@)
    "basic_auth_url": re.compile(r'(?i)\b[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+'),
}

# ---------- helpers ----------

def is_tar_path(name: str) -> bool:
    lname = name.lower()
    return lname.endswith(TAR_EXTS)

def looks_text(data: bytes) -> bool:
    # Heuristic: reject if NUL bytes; accept otherwise
    if b"\x00" in data[:1024]:
        return False
    return True

def safe_read_file(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(max_bytes)

def mask_value(val: str) -> str:
    if len(val) <= 8:
        return "*" * max(1, len(val) - 1) + val[-1:]
    return val[:4] + "*" * (len(val) - 8) + val[-4:]

def iter_dir_files(root: str):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            yield os.path.join(dirpath, fn)

def scan_text(buffer: str, virtual_path: str, mask: bool):
    results = []
    # Scan line-by-line (gives better location + context)
    for lineno, line in enumerate(buffer.splitlines(), 1):
        for name, cregex in REGEX_PATTERNS.items():
            for m in cregex.finditer(line):
                # value extraction: try last group if groups exist; else full match
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                shown = mask_value(value) if mask else value
                context = line.strip()
                results.append({
                    "path": virtual_path,
                    "line": lineno,
                    "type": name,
                    "value": shown,
                    "raw_len": len(value),
                    "context": (context[:200] + "…") if len(context) > 200 else context,
                })
    return results

def scan_bytes(data: bytes, virtual_path: str, mask: bool):
    # Decode best-effort to UTF-8 without bombing on weird encodings
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return scan_text(text, virtual_path, mask)

def scan_tar_bytes(data: bytes, outer_path: str, max_bytes: int, mask: bool, force_text: bool):
    findings = []
    bio = io.BytesIO(data)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                vpath = f"{outer_path}::{member.name}"
                # size guard
                if member.size > max_bytes:
                    continue
                f = tf.extractfile(member)
                if not f:
                    continue
                mbuf = f.read(max_bytes)
                # Nested tar?
                if is_tar_path(member.name):
                    findings.extend(scan_tar_bytes(mbuf, vpath, max_bytes, mask, force_text))
                    continue
                # Otherwise scan text-ish files (ext hint or sniff)
                if member.name.lower().endswith(LOG_LIKE_EXTS) or force_text or looks_text(mbuf):
                    findings.extend(scan_bytes(mbuf, vpath, mask))
    except tarfile.ReadError:
        # Not actually a tar (or corrupted) — ignore
        pass
    return findings

def scan_path(path: str, max_bytes: int, mask: bool, force_text: bool):
    all_results = []
    if os.path.isdir(path):
        for fp in iter_dir_files(path):
            try:
                if is_tar_path(fp):
                    buf = safe_read_file(fp, max_bytes)
                    all_results.extend(scan_tar_bytes(buf, fp, max_bytes, mask, force_text))
                else:
                    buf = safe_read_file(fp, max_bytes)
                    if fp.lower().endswith(LOG_LIKE_EXTS) or force_text or looks_text(buf):
                        all_results.extend(scan_bytes(buf, fp, mask))
            except (PermissionError, FileNotFoundError):
                continue
    else:
        # single file
        try:
            buf = safe_read_file(path, max_bytes)
        except (PermissionError, FileNotFoundError) as e:
            print(f"[warn] cannot read {path}: {e}", file=sys.stderr)
            return []
        if is_tar_path(path):
            all_results.extend(scan_tar_bytes(buf, path, max_bytes, mask, force_text))
        else:
            if path.lower().endswith(LOG_LIKE_EXTS) or force_text or looks_text(buf):
                all_results.extend(scan_bytes(buf, path, mask))
    return all_results

def print_table(rows):
    # Try rich for a nice table; fallback if unavailable
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
        # Plain fallback
        from textwrap import shorten
        header = ["#", "type", "value", "file", "line"]
        print("\t".join(header))
        for i, r in enumerate(rows, 1):
            print("\t".join([
                str(i),
                r["type"],
                shorten(r["value"], width=80, placeholder="…"),
                shorten(r["path"], width=100, placeholder="…"),
                str(r["line"]),
            ]))

def main():
    ap = argparse.ArgumentParser(description="Scan directory or tar for sensitive strings.")
    ap.add_argument("target", help="Directory or tar file to scan")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help=f"Max bytes to read per file (default {DEFAULT_MAX_BYTES})")
    ap.add_argument("--mask", type=str, default="true",
                    help="Mask sensitive values in output (true/false)")
    ap.add_argument("--force-text", action="store_true",
                    help="Force treat files as text (skip binary sniff)")
    ap.add_argument("--format", choices=["table", "csv", "json"], default="table",
                    help="Output format (default table)")
    args = ap.parse_args()

    mask = str(args.mask).lower() in ("1", "true", "yes", "y")
    findings = scan_path(args.target, args.max_bytes, mask, args.force_text)

    # sort by severity-ish (private keys first), then type, then path/line
    order = {
        "private_key_header": 0,
        "aws_secret_access_key": 1,
        "aws_access_key_id": 2,
        "gcp_api_key": 3,
        "github_pat": 4,
        "slack_token": 5,
        "jwt": 6,
        "basic_auth_url": 7,
        "client_secret": 8,
        "api_key": 9,
        "token": 10,
        "password": 11,
    }
    findings.sort(key=lambda r: (order.get(r["type"], 99), r["path"], r["line"]))

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

    # exit code: 0 if no findings, 2 if found any (handy for CI gates)
    sys.exit(2 if findings else 0)

if __name__ == "__main__":
    main()
