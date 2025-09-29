#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
target_inspector_cli.py  — v3.2 (TLS-enabled)

Adds TLS/SSL inspection for https targets:
- TLS version, cipher, issuer CN, subject CN, SANs (DNS), notBefore/notAfter, days_to_expiry
- Shows in table and writes to JSON
- Robust: timeouts, retries, per-target isolation

Other features preserved:
- Auto classify: git_repo | api_endpoint | download_url | html_page
- Creds-aware (basic/bearer/headers/cookies)
- Download + resume, speed sampling, ETA
- ASCII or --rich table, JSON report

Deps: Python 3.9+, requests; git in PATH for git checks. (Optional: rich)
"""
from __future__ import annotations
import argparse, json, math, os, re, shutil, subprocess, sys, time, traceback, socket, ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse, unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================ Formatting helpers ============================

def human_bytes(n: int | None) -> str:
    if n is None: return "—"
    u = ["B","KB","MB","GB","TB"]; f=float(n); i=0
    while f >= 1024 and i < len(u)-1: f/=1024.0; i+=1
    return f"{f:.2f} {u[i]}"

def human_time(s: float | None) -> str:
    if s is None or math.isinf(s): return "—"
    if s < 1: return f"{s*1000:.0f} ms"
    m, sec = divmod(int(round(s)), 60); h, m = divmod(m, 60)
    out=[]; 
    if h: out.append(f"{h}h")
    if m: out.append(f"{m}m")
    out.append(f"{sec}s")
    return " ".join(out)

def wrap_text(s: str, width: int) -> List[str]:
    s = "" if s is None else str(s)
    if width <= 0: return [s]
    words = re.findall(r'\S+\s*', s)
    lines, line = [], ""
    for w in words:
        if len(line) + len(w) <= width:
            line += w
        else:
            lines.append(line.rstrip())
            line = w
    if line: lines.append(line.rstrip())
    if not lines: lines = [""]
    return lines

def build_ascii_table(rows: List[Dict[str, Any]],
                      headers_spec: List[Tuple[str,str,int,int,str]],
                      max_width: int = None) -> str:
    if max_width is None:
        max_width = shutil.get_terminal_size((140, 24)).columns
    widths = []
    for key, label, minw, maxw, _align in headers_spec:
        content_w = len(label)
        for r in rows:
            content_w = max(content_w, len(str(r.get(key, ""))))
        widths.append(min(max(content_w, minw), maxw))
    static_overhead = 1 + 1 + len(headers_spec)*2 + (len(headers_spec)-1) + 1
    total = sum(widths) + static_overhead
    while total > max_width:
        idx = max(range(len(widths)), key=lambda i: widths[i] - headers_spec[i][2])
        if widths[idx] > headers_spec[idx][2]:
            widths[idx] -= 1
            total = sum(widths) + static_overhead
        else:
            break
    top    = "┌" + "┬".join("─"*w for w in widths) + "┐"
    mid    = "├" + "┼".join("─"*w for w in widths) + "┤"
    bottom = "└" + "┴".join("─"*w for w in widths) + "┘"
    header_cells = [wrap_text(label, w) for (key,label,_,_,_), w in zip(headers_spec, widths)]
    header_height = max(len(c) for c in header_cells)
    header_lines = []
    for i in range(header_height):
        line_cells = []
        for (key,label,_,_,align), w, cell_lines in zip(headers_spec, widths, header_cells):
            text = cell_lines[i] if i < len(cell_lines) else ""
            if align == "right":
                line_cells.append(text.rjust(w))
            elif align == "center":
                line_cells.append(text.center(w))
            else:
                line_cells.append(text.ljust(w))
        header_lines.append("│" + "│".join(line_cells) + "│")
    data_lines = []
    for r in rows:
        cell_lines_sets = []
        for (key,_label,_,_,align), w in zip(headers_spec, widths):
            cell_lines_sets.append((wrap_text(str(r.get(key,"")), w), align, w))
        row_h = max(len(cl[0]) for cl in cell_lines_sets)
        for i in range(row_h):
            parts=[]
            for (lineset, align, w) in cell_lines_sets:
                text = lineset[i] if i < len(lineset) else ""
                if align == "right":
                    parts.append(text.rjust(w))
                elif align == "center":
                    parts.append(text.center(w))
                else:
                    parts.append(text.ljust(w))
            data_lines.append("│" + "│".join(parts) + "│")
    out = [top] + header_lines + [mid] + data_lines + [bottom]
    return "\n".join(out)

def maybe_rich_table(rows, headers_spec):
    try:
        from rich.table import Table
        from rich.console import Console
        table = Table(box=None, show_lines=False, pad_edge=False)
        for _k, label, _minw, _maxw, align in headers_spec:
            table.add_column(label, justify=align, no_wrap=False, overflow="fold")
        for r in rows:
            table.add_row(*[str(r.get(k,"")) for k, *_ in headers_spec])
        Console().print(table); return True
    except Exception:
        return False

# ============================ HTTP helpers ============================

def install_retries(session: requests.Session, total=3, backoff=0.6):
    retry = Retry(total=total, backoff_factor=backoff,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["HEAD","GET"])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter); session.mount("https://", adapter)

def get_header(h: Dict[str,str], k: str):
    return h.get(k) or h.get(k.title()) or h.get(k.lower())

def content_length(h: Dict[str,str]) -> int | None:
    v = get_header(h, "content-length")
    try: return int(v) if v is not None else None
    except: return None

def guess_filename(url: str, headers: Dict[str,str]) -> str:
    cd = get_header(headers, "content-disposition") or ""
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^\";]+)"?', cd, re.I)
    if m: return unquote(m.group(1))
    path = urlparse(url).path
    if path and path != "/": return unquote(path.rstrip("/").split("/")[-1])
    return "(unknown)"

def sniff_magic(b: bytes) -> Dict[str,str]:
    info={}
    if b.startswith(b"%PDF-"):
        info["kind"]="PDF"; 
        m=re.match(rb"%PDF-(\d\.\d)", b[:12])
        if m: info["details"]=f"v{m.group(1).decode()}"
        return info
    if b.startswith(b"\x50\x4b\x03\x04") or b.startswith(b"\x50\x4b\x05\x06") or b.startswith(b"\x50\x4b\x07\x08"):
        info["kind"]="ZIP/OOXML/JAR/APK"; return info
    if b.startswith(b"\x1F\x8B\x08"): info["kind"]="GZIP"; return info
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        info={"kind":"PNG"}
        if len(b)>=33 and b[12:16]==b"IHDR":
            w=int.from_bytes(b[16:20],"big"); h=int.from_bytes(b[20:24],"big")
            info["details"]=f"{w}x{h}px"
        return info
    if b.startswith(b"\xFF\xD8\xFF"): return {"kind":"JPEG"}
    if b[4:8]==b"ftyp": return {"kind":"MP4/MOV"}
    return info

def extract_html_bits(sample: bytes) -> Dict[str,str]:
    out={}
    try: text=sample.decode("utf-8", errors="ignore")
    except Exception: return out
    m=re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m: out["title"]=re.sub(r"\s+"," ",m.group(1)).strip()
    m=re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
    if m: out["description"]=m.group(1).strip()
    return out

def make_session(args) -> requests.Session:
    s = requests.Session()
    install_retries(s, total=3, backoff=0.6)
    s.headers.update({"User-Agent": args.ua})
    if args.header:
        for kv in args.header:
            if ":" in kv:
                k,v = kv.split(":",1)
                s.headers[k.strip()] = v.strip()
    if args.cookie:
        for cv in args.cookie:
            if "=" in cv:
                k,v = cv.split("=",1)
                s.cookies.set(k.strip(), v.strip())
    s.auth = None
    if args.auth_basic:
        if ":" not in args.auth_basic:
            print("[WARN] --auth-basic requires user:pass", file=sys.stderr)
        else:
            u,p = args.auth_basic.split(":",1)
            s.auth = (u,p)
    if args.bearer:
        s.headers["Authorization"] = f"Bearer {args.bearer}"
    return s

def head_or_range(session: requests.Session, url: str, timeout: int = 12) -> requests.Response:
    try:
        r = session.head(url, allow_redirects=True, timeout=timeout)
        if r.status_code >= 400 or r.status_code == 405:
            raise requests.RequestException(f"HEAD {r.status_code}")
        return r
    except Exception:
        return session.get(url, headers={"Range":"bytes=0-0"}, allow_redirects=True, timeout=timeout, stream=True)

def fetch_first_bytes(session: requests.Session, url: str, timeout: int = 12, n: int = 8192) -> bytes:
    try:
        r = session.get(url, headers={"Range":f"bytes=0-{n-1}"}, timeout=timeout, stream=True)
        r.raise_for_status()
        data = b""
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk: break
            data += chunk
            if len(data) >= n: break
        return data[:n]
    except Exception:
        return b""

def sample_speed(session: requests.Session, url: str, nbytes: int, timeout: int = 20) -> float | None:
    try:
        t0 = time.time()
        r = session.get(url, headers={"Range":f"bytes=0-{nbytes-1}"}, stream=True, timeout=timeout)
        r.raise_for_status()
        got = 0
        for chunk in r.iter_content(65536):
            if not chunk: break
            got += len(chunk)
            if got >= nbytes: break
        dt = max(time.time()-t0, 1e-6)
        return got/dt
    except Exception:
        return None

def stream_download(session: requests.Session, url: str, out_path: str, timeout: int = 60, resume: bool = False) -> Dict[str,Any]:
    tmp = out_path + ".part"
    written = 0
    headers = {}
    mode = "wb"
    resumed = False
    try:
        if resume and os.path.exists(tmp):
            written = os.path.getsize(tmp)
            headers["Range"] = f"bytes={written}-"
            mode = "ab"; resumed = True
        with session.get(url, stream=True, timeout=timeout, headers=headers) as r:
            status = r.status_code
            if resumed and status not in (206,200):
                written = 0; resumed = False; mode = "wb"
            if not resumed and status >= 400:
                return {"written":0,"total":None,"resumed":False,"status":status,"error":f"HTTP {status}"}
            total = None
            cl = content_length(r.headers)
            if cl is not None:
                total = cl + (written if resumed and status==206 else 0)
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(tmp, mode) as f:
                acc = written; last = time.time()
                for chunk in r.iter_content(1024*256):
                    if not chunk: continue
                    f.write(chunk); acc += len(chunk)
                    now = time.time()
                    if now - last >= 0.5:
                        if total:
                            pct = acc/total*100.0
                            eta = (total-acc)/max(1, (acc-written)/(now-last))
                            sys.stdout.write(f"\r   -> {human_bytes(acc)} / {human_bytes(total)} ({pct:5.1f}%)  |  ETA {human_time(eta)}")
                        else:
                            sys.stdout.write(f"\r   -> {human_bytes(acc)}")
                        sys.stdout.flush(); last = now
                sys.stdout.write("\n")
        os.replace(tmp, out_path)
        return {"written":acc,"total":total,"resumed":resumed,"status":status}
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Partial file kept as .part", file=sys.stderr)
        return {"written":written,"total":None,"resumed":resumed,"status":-1,"error":"interrupted"}
    except Exception as e:
        return {"written":written,"total":None,"resumed":resumed,"status":-1,"error":str(e)}

# ============================ TLS / SSL probe ============================

def parse_asn1_time(s: str) -> datetime:
    # format like 'Jun 12 12:00:00 2026 GMT'
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        # Some platforms omit TZ
        return datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

def tls_probe(host: str, port: int = 443, timeout: int = 6) -> Dict[str,Any]:
    """
    Returns dict with tls_version, cipher, issuer, subject, sans, not_before, not_after, days_to_expiry.
    Uses no verification (we want info even if invalid).
    """
    info = {"ok": False}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()  # dict form
                info["tls_version"] = ssock.version()
                c = ssock.cipher()
                info["cipher"] = f"{c[0]} ({c[1]})" if c else None
        # Parse cert dict
        issuer = cert.get("issuer", [])
        subject = cert.get("subject", [])
        def tuple_to_cn(t):
            for k,v in t:
                if k.lower() in ("commonname","cn"):
                    return v
            return None
        issuer_cn = tuple_to_cn(issuer[0]) if issuer else None
        subject_cn = tuple_to_cn(subject[0]) if subject else None
        sans = []
        for k,v in cert.get("subjectAltName", []):
            if k.lower() == "dns": sans.append(v)
        nb = cert.get("notBefore"); na = cert.get("notAfter")
        nb_dt = parse_asn1_time(nb) if nb else None
        na_dt = parse_asn1_time(na) if na else None
        days = None
        if na_dt:
            days = max(0, int((na_dt - datetime.now(timezone.utc)).total_seconds()//86400))
        info.update({
            "ok": True,
            "issuer_cn": issuer_cn,
            "subject_cn": subject_cn,
            "sans": sans[:20],
            "not_before": nb,
            "not_after": na,
            "days_to_expiry": days,
        })
    except Exception as e:
        info["error"] = str(e)
    return info

# ============================ Classifiers ============================

def looks_like_git(s: str) -> bool:
    if s.startswith("git@") or s.endswith(".git"): return True
    try:
        u = urlparse(s)
        if u.scheme in ("http","https") and u.netloc and u.path:
            parts = [p for p in u.path.split("/") if p]
            if len(parts) >= 2 and u.netloc.lower() in ("github.com","gitlab.com","bitbucket.org"):
                return True
    except Exception:
        pass
    return False

def validate_git(url: str, timeout: int = 15) -> Dict[str,Any]:
    if shutil.which("git") is None:
        return {"reachable":False,"error":"git not found in PATH"}
    try:
        cp = subprocess.run(["git","ls-remote","--heads","--tags",url],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if cp.returncode != 0:
            return {"reachable":False,"error":cp.stderr.strip() or "ls-remote failed"}
        refs = [ln.split("\t",1)[1] for ln in cp.stdout.strip().splitlines() if "\t" in ln]
        cp2 = subprocess.run(["git","ls-remote","--symref",url,"HEAD"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        default=None
        for ln in cp2.stdout.splitlines():
            if ln.startswith("ref:") and "\tHEAD" in ln:
                default = ln.split()[1].split("\t")[0]
        return {"reachable":True,"default_branch":default,"refs_count":len(refs)}
    except subprocess.TimeoutExpired:
        return {"reachable":False,"error":"git ls-remote timed out"}
    except Exception as e:
        return {"reachable":False,"error":str(e)}

def classify_http(session: requests.Session, url: str, timeout: int = 12) -> Tuple[str, Dict[str,Any]]:
    try:
        h = head_or_range(session, url, timeout=timeout)
    except Exception as e:
        return ("unknown", {"status":None,"content_type":None,"content_length":None,"error":f"{e}"})
    headers = dict(h.headers or {})
    status  = h.status_code
    ctype   = (get_header(headers,"content-type") or "unknown").lower()
    clen    = content_length(headers)
    first = b""
    try: first = fetch_first_bytes(session, url, timeout=timeout, n=8192)
    except Exception: first = b""
    info = {"status":status,"content_type":ctype,"content_length":clen}
    looks_api = ("application/json" in ctype) or ctype.endswith("+json") or bool(get_header(headers,"x-ratelimit-limit"))
    openapi_hint = None; json_keys = None
    if "application/json" in ctype or ctype.endswith("+json"):
        try:
            r = session.get(url, timeout=timeout)
            if r.ok and len(r.text) <= 200000:
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        json_keys = list(data.keys())[:10]
                        if "openapi" in data or "swagger" in data or ("paths" in data and "info" in data):
                            openapi_hint = "OpenAPI/Swagger-like"
                        looks_api = True
                except Exception:
                    pass
        except Exception:
            pass
    magic = sniff_magic(first)
    disp  = (get_header(headers,"content-disposition") or "").lower()
    if looks_api:
        return ("api_endpoint", info | {"openapi_hint":openapi_hint, "json_keys":json_keys})
    if "text/html" in ctype or (not magic and first[:32].lower().startswith(b"<!doctype html")):
        bits = extract_html_bits(first)
        return ("html_page", info | bits)
    if "attachment" in disp or magic or (ctype!="unknown" and not ctype.startswith("text/")):
        return ("download_url", info | {"filename":guess_filename(url, headers), "magic":magic})
    return ("unknown", info)

# ============================ Main ============================

def main():
    ap = argparse.ArgumentParser(description="Classify targets, print table, save JSON, TLS-aware, creds-aware, robust.")
    ap.add_argument("targets", nargs="+", help="URLs or git URLs")
    # Net controls
    ap.add_argument("--timeout", type=int, default=20, help="Network timeout seconds")
    ap.add_argument("--ua", default="target-inspector/3.2", help="User-Agent")
    ap.add_argument("--bandwidth", type=float, default=None, help="Assumed Mbps for ETA when not sampling")
    ap.add_argument("--sample-bytes", type=int, default=0, help="Sample N bytes via Range to measure throughput")
    # Auth / headers
    ap.add_argument("--auth-basic", help="user:pass")
    ap.add_argument("--bearer", help="Bearer token")
    ap.add_argument("--header", action="append", help='Extra header, e.g. --header "X-API-Key: abc" (repeatable)')
    ap.add_argument("--cookie", action="append", help='Cookie, e.g. --cookie "sid=123" (repeatable)')
    # Download
    ap.add_argument("--download", help="Path or directory to save file when target is a download URL")
    ap.add_argument("--resume", action="store_true", help="Resume partial download if server supports Range")
    # TLS
    ap.add_argument("--no-tls", action="store_true", help="Disable TLS inspection for https targets")
    ap.add_argument("--tls-port", type=int, default=443, help="TLS port (override if needed)")
    # Output
    ap.add_argument("--json-out", default=None, help="Path to write JSON report")
    ap.add_argument("--rich", action="store_true", help="Use rich table if available")
    args = ap.parse_args()

    session = make_session(args)

    results: List[Dict[str,Any]] = []
    total = len(args.targets)

    for i, t in enumerate(args.targets, 1):
        print(f"\n▶ [{i}/{total}] Inspecting: {t}")
        row: Dict[str,Any] = {
            "target": t, "kind": None, "status": None, "content_type": None,
            "size_bytes": None, "size_human": None, "filename": None,
            "sample_mbps": None, "eta_seconds": None, "eta_human": None,
            "api_openapi": None, "api_json_keys": None,
            "html_title": None, "html_desc": None,
            "git_reachable": None, "git_default_branch": None, "git_refs_count": None,
            "downloaded": False, "download_path": None, "resumed": False,
            "tls": None,
            "error": None,
        }

        try:
            if looks_like_git(t):
                print("   • Detected: git repository")
                info = validate_git(t, timeout=args.timeout)
                row["kind"]="git_repo"
                row["git_reachable"]=bool(info.get("reachable"))
                row["git_default_branch"]=info.get("default_branch")
                row["git_refs_count"]=info.get("refs_count")
                if not info.get("reachable"):
                    row["error"]=info.get("error") or "git unreachable"
                    print(f"   ! {row['error']}")
                else:
                    print(f"   ✓ reachable | default: {row['git_default_branch'] or 'unknown'} | refs: {row['git_refs_count']}")
                results.append(row); continue

            u = urlparse(t)
            if u.scheme not in ("http","https"):
                row["kind"]="unknown"; row["error"]="unsupported scheme"
                print("   ! unsupported scheme (need http/https or git)")
                results.append(row); continue

            # TLS probe for HTTPS (unless disabled)
            if u.scheme == "https" and not args.no_tls and u.hostname:
                tlsinfo = tls_probe(u.hostname, args.tls_port, timeout=6)
                row["tls"] = tlsinfo
                if tlsinfo.get("ok"):
                    print(f"   • TLS: {tlsinfo.get('tls_version')} | {tlsinfo.get('cipher')}")
                    print(f"     Issuer: {tlsinfo.get('issuer_cn')} | Subject: {tlsinfo.get('subject_cn')}")
                    print(f"     Expiry: {tlsinfo.get('not_after')}  (~{tlsinfo.get('days_to_expiry')} days)")
                else:
                    print(f"   ! TLS probe failed: {tlsinfo.get('error','unknown')}")

            kind, info = classify_http(session, t, timeout=args.timeout)
            row["kind"]=kind
            row["status"]=info.get("status")
            row["content_type"]=info.get("content_type")
            row["size_bytes"]=info.get("content_length")
            row["size_human"]=human_bytes(row["size_bytes"])

            if kind=="api_endpoint":
                row["api_openapi"]=info.get("openapi_hint")
                row["api_json_keys"]=info.get("json_keys")
                print("   • API endpoint")
                if row["api_openapi"]: print(f"   ✓ Spec hint: {row['api_openapi']}")
                if row["api_json_keys"]: print(f"   ✓ JSON keys: {', '.join(row['api_json_keys'])}")

            elif kind=="html_page":
                row["html_title"]=info.get("title")
                row["html_desc"]=info.get("description")
                print("   • HTML page")
                if row["html_title"]: print(f"   ✓ Title: {row['html_title']}")
                if row["html_desc"]:  print(f"   ✓ Desc : {row['html_desc'][:100]}{'…' if len(row['html_desc'])>100 else ''}")

            elif kind=="download_url":
                row["filename"]=info.get("filename") or guess_filename(t, {})
                print("   • Download URL")
                print(f"   ✓ Name: {row['filename']} | Size: {row['size_human']} | Type: {row['content_type']}")
                measured_bps = None
                if args.sample_bytes > 0:
                    print(f"   • Sampling {human_bytes(args.sample_bytes)} for speed…")
                    measured_bps = sample_speed(session, t, args.sample_bytes, timeout=args.timeout)
                    if measured_bps:
                        row["sample_mbps"] = (measured_bps/1_000_000.0)*8.0
                        print(f"   ✓ Measured: {row['sample_mbps']:.2f} Mbps")
                    else:
                        print("   ! Sampling failed (continuing)")
                eta = None
                if row["size_bytes"]:
                    if measured_bps:
                        eta = row["size_bytes"]/measured_bps
                    elif args.bandwidth and args.bandwidth > 0:
                        eta = row["size_bytes"] / (args.bandwidth*1_000_000/8.0)
                row["eta_seconds"]=eta; row["eta_human"]=human_time(eta)
                print(f"   • ETA: {row['eta_human']}")
                if args.download:
                    out = args.download
                    if os.path.isdir(out) or out.endswith(os.sep):
                        os.makedirs(out, exist_ok=True)
                        out = os.path.join(out, row["filename"] or "download.bin")
                    print(f"   • Downloading to: {out}  ({'resume' if args.resume else 'fresh'})")
                    dl = stream_download(session, t, out, timeout=max(args.timeout,60), resume=args.resume)
                    if dl.get("error"):
                        row["error"] = dl["error"]
                        print(f"   ! Download error: {dl['error']}")
                    elif dl.get("status", 200) >= 400:
                        row["error"] = f"download failed HTTP {dl['status']}"
                        print(f"   ! Download failed HTTP {dl['status']}")
                    else:
                        row["downloaded"]=True
                        row["download_path"]=os.path.abspath(out)
                        row["resumed"]=bool(dl.get("resumed"))
                        print(f"   ✓ Downloaded {human_bytes(dl.get('written'))}{' (resumed)' if row['resumed'] else ''}")
            else:
                print("   • Unknown (may require auth or dynamic content)")

        except KeyboardInterrupt:
            print("\n[INTERRUPTED] Skipping this target.", file=sys.stderr)
            row["error"]="interrupted"
        except Exception as e:
            row["error"]=str(e)
            if os.environ.get("TI_DEBUG"):
                traceback.print_exc()
            print(f"   ! Error: {row['error']}")
        results.append(row)

    # -------- Summary table --------
    headers_spec = [
        ("kind","Kind",8,12,"left"),
        ("target","Target",22,54,"left"),
        ("status","HTTP",3,5,"right"),
        ("content_type","Content-Type",10,24,"left"),
        ("filename","Filename",10,22,"left"),
        ("size_human","Size",6,9,"right"),
        ("sample_mbps","Speed(Mbps)",6,12,"right"),
        ("eta_human","ETA",4,9,"right"),
        ("tls_version","TLS",4,7,"center"),
        ("tls_exp","Expiry(D)",6,9,"right"),
        ("downloaded","DL",2,3,"center"),
    ]

    table_rows = []
    for r in results:
        tls = r.get("tls") or {}
        table_rows.append({
            "kind": r.get("kind") or "—",
            "target": r.get("target") or "—",
            "status": r.get("status") if r.get("status") is not None else "—",
            "content_type": r.get("content_type") or "—",
            "filename": r.get("filename") or "—",
            "size_human": r.get("size_human") or "—",
            "sample_mbps": f"{r['sample_mbps']:.2f}" if r.get("sample_mbps") else "—",
            "eta_human": r.get("eta_human") or "—",
            "tls_version": tls.get("tls_version") or "—",
            "tls_exp": str(tls.get("days_to_expiry")) if tls.get("days_to_expiry") is not None else "—",
            "downloaded": "Y" if r.get("downloaded") else "N",
        })

    print("\n=== Summary ===")
    if args.rich and maybe_rich_table(table_rows, headers_spec):
        pass
    else:
        print(build_ascii_table(table_rows, headers_spec))

    # -------- JSON output --------
    try:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out = args.json_out or f"ti_report_{ts}.json"
        payload = {
            "generated_at_utc": ts,
            "args": {
                "timeout": args.timeout, "ua": args.ua,
                "bandwidth": args.bandwidth, "sample_bytes": args.sample_bytes,
                "auth_basic": bool(args.auth_basic), "bearer": bool(args.bearer),
                "headers": args.header or [], "cookies": args.cookie or [],
                "download": args.download, "resume": args.resume,
                "tls": not args.no_tls, "tls_port": args.tls_port
            },
            "results": results,
        }
        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"\n📦 JSON saved to: {os.path.abspath(out)}")
    except Exception as e:
        print(f"\n[WARN] Failed to write JSON: {e}", file=sys.stderr)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr); sys.exit(130)
