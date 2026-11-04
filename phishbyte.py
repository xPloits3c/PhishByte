#!/usr/bin/env python3
# PhishByte - passive, offline phishing email analyzer
# Author: xPloits3c  |  License: MIT
"""
PhishByte - triage of suspicious emails (.eml / .msg), passive and offline.

Analyzes one or more emails WITHOUT making any network request and WITHOUT
opening attachments. For each message it produces:
  - header analysis: spoofing (From vs Return-Path vs Reply-To), SPF/DKIM/
    DMARC, mismatched Message-ID, public IPs from the Received chain;
  - body analysis: tracking pixels with scoring, wrapped links (click-
    tracking/redirect) resolved to their real destination, IDN/homograph
    domains;
  - attachment analysis: SHA-256, real type (magic bytes) vs extension, flags
    for disguised executables and high-risk extensions;
  - aggregated IOCs (IP, domains, URLs, emails, hashes) and a risk score.

Opt-in features that touch the network / external deps (OFF by default):
  --vt      VirusTotal BY-HASH lookup on attachments (needs VT_API_KEY and
            'requests'); never sends the file, only the hash.
  --deep    deep attachment inspection via oletools/pdfid if installed.

Usage:
  python3 phishbyte.py suspicious.eml
  python3 phishbyte.py ./inbox/ --json -o report.json
  python3 phishbyte.py suspicious.eml --no-defang
  python3 phishbyte.py suspicious.eml --vt
"""

import os
import re
import sys
import json
import hashlib
import argparse
from email import message_from_binary_file
from email.policy import default
from email.utils import parseaddr
from urllib.parse import urlparse, parse_qs, unquote

__version__ = "1.0.0"

# --- Colors (optional) ---------------------------------------------------
try:
    from colorama import init as _color_init, Fore
    _color_init(autoreset=True)
except Exception:  # pragma: no cover
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()

# --- HTML parsing: bs4 if available, otherwise regex fallback ------------
try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

# --- Outlook .msg: extract-msg optional ----------------------------------
try:
    import extract_msg  # type: ignore
    HAVE_EXTRACT_MSG = True
except Exception:
    HAVE_EXTRACT_MSG = False

EMAIL_EXTENSIONS = (".eml", ".msg")

# --- Heuristics ----------------------------------------------------------
SUSPECT_HOST_HINTS = ("track", "click", "pixel", "open", "beacon", "wf",
                      "mailstat", "sendgrid", "mailchimp", "hubspot",
                      "mandrill", "sparkpost", "sendinblue", "list-manage")
SUSPECT_PATH_HINTS = ("/o.gif", "/open", "/pixel", "/wf/open", "/beacon",
                      "/track", "/q/", "/ss/o")

RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
             ".jar", ".bat", ".cmd", ".ps1", ".lnk", ".iso", ".img",
             ".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}

MAGIC = {
    b"MZ": "PE/EXE (Windows)",
    b"\x7fELF": "ELF (Linux)",
    b"%PDF": "PDF",
    b"PK\x03\x04": "ZIP/OOXML (docx/xlsx/jar/...)",
    b"\xd0\xcf\x11\xe0": "OLE (doc/xls legacy)",
    b"Rar!": "RAR",
    b"\x1f\x8b": "GZIP",
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG": "PNG",
    b"GIF8": "GIF",
}

RE_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_IMG_TAG = re.compile(r"<img\b[^>]*>", re.IGNORECASE | re.DOTALL)

PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                       "172.19.", "172.2", "172.30.", "172.31.", "127.",
                       "169.254.", "0.", "255.")


def _attr_re(name):
    return re.compile(name + r"\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)


# --- Utils ---------------------------------------------------------------
def is_email_file(path):
    return path.lower().endswith(EMAIL_EXTENSIONS)


def is_public_ip(ip):
    try:
        if not all(0 <= int(o) <= 255 for o in ip.split(".")):
            return False
    except ValueError:
        return False
    return not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


def defang(value):
    """Make an IOC non-clickable for safe reporting/pasting."""
    return (value.replace("http", "hxxp")
                 .replace(".", "[.]")
                 .replace("@", "[at]"))


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def has_idn_homograph(host):
    if not host:
        return False
    if host.startswith("xn--") or ".xn--" in host:
        return True
    try:
        host.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


# --- Message loading -----------------------------------------------------
def _load_message(path):
    if path.lower().endswith(".msg"):
        if not HAVE_EXTRACT_MSG:
            raise RuntimeError(
                ".msg file: install 'extract-msg' (pip install extract-msg)")
        import io
        data = extract_msg.Message(path).as_email().as_bytes()
        return message_from_binary_file(io.BytesIO(data), policy=default)
    with open(path, "rb") as f:
        return message_from_binary_file(f, policy=default)


def _get_bodies(msg):
    html_parts, text_parts = [], []
    for part in msg.walk():
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/html":
            try:
                html_parts.append(part.get_content())
            except Exception:
                pass
        elif ctype == "text/plain":
            try:
                text_parts.append(part.get_content())
            except Exception:
                pass
    return html_parts, text_parts


def _get_attachments(msg):
    out = []
    for part in msg.walk():
        disp = (part.get_content_disposition() or "")
        fname = part.get_filename()
        if disp == "attachment" or (fname and disp != "inline"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            out.append({
                "filename": fname or "(no name)",
                "declared_type": part.get_content_type(),
                "size": len(payload),
                "raw": payload,
            })
    return out


# --- Header analysis -----------------------------------------------------
def analyze_headers(msg):
    findings, flags = {}, []
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    return_path = parseaddr(msg.get("Return-Path", ""))[1].lower()
    reply_to = parseaddr(msg.get("Reply-To", ""))[1].lower()

    findings["from"] = from_addr
    findings["return_path"] = return_path
    findings["reply_to"] = reply_to
    findings["subject"] = str(msg.get("Subject", ""))
    findings["message_id"] = str(msg.get("Message-ID", ""))

    def dom(addr):
        return addr.split("@")[-1] if "@" in addr else ""

    if return_path and dom(return_path) and dom(return_path) != dom(from_addr):
        flags.append(f"From ({dom(from_addr)}) != Return-Path "
                     f"({dom(return_path)})")
    if reply_to and dom(reply_to) and dom(reply_to) != dom(from_addr):
        flags.append(f"Reply-To differs from From ({dom(reply_to)})")

    mid = findings["message_id"]
    if mid and dom(from_addr) and dom(from_addr) not in mid:
        flags.append("Message-ID domain does not match From")

    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    auth_low = auth.lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", auth_low)
        if m:
            res = m.group(1)
            findings[mech] = res
            if res in ("fail", "softfail", "none", "temperror", "permerror"):
                flags.append(f"{mech.upper()}={res}")

    received = msg.get_all("Received", [])
    hop_ips = []
    for r in received:
        for ip in RE_IPV4.findall(str(r)):
            if is_public_ip(ip) and ip not in hop_ips:
                hop_ips.append(ip)
    findings["received_public_ips"] = hop_ips
    findings["received_count"] = len(received)

    xmailer = str(msg.get("X-Mailer", "") or msg.get("X-Campaign", ""))
    if xmailer:
        findings["x_mailer"] = xmailer

    findings["flags"] = flags
    return findings


# --- Body analysis -------------------------------------------------------
def _iter_img_tags(html):
    if HAVE_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for img in soup.find_all("img"):
            yield {
                "src": img.get("src", "") or "",
                "width": str(img.get("width", "") or ""),
                "height": str(img.get("height", "") or ""),
                "style": (img.get("style", "") or ""),
                "alt": img.get("alt", None),
            }
    else:
        for tag in RE_IMG_TAG.findall(html):
            def g(attr):
                m = _attr_re(attr).search(tag)
                return m.group(1) if m else ""
            yield {
                "src": g("src"),
                "width": g("width"),
                "height": g("height"),
                "style": g("style"),
                "alt": g("alt") or None,
            }


def _score_pixel(img):
    score, reasons = 0, []
    src = img["src"]
    w, h = img["width"], img["height"]
    style = img["style"].lower().replace(" ", "")

    if w in ("1", "0") and h in ("1", "0"):
        score += 3
        reasons.append("1x1/0 dimensions")
    if any(x in style for x in ("display:none", "visibility:hidden",
                                "opacity:0", "width:1px", "height:1px")):
        score += 2
        reasons.append("hidden via CSS")
    if src:
        u = urlparse(src)
        host, path = (u.hostname or "").lower(), u.path.lower()
        if any(hh in host for hh in SUSPECT_HOST_HINTS):
            score += 2
            reasons.append(f"suspect host: {host}")
        if any(p in path for p in SUSPECT_PATH_HINTS):
            score += 2
            reasons.append("beacon-like path")
        qs = parse_qs(u.query)
        if any(len(v[0]) >= 16 for v in qs.values() if v):
            score += 1
            reasons.append("opaque ID in query")
        if img["alt"] is None or img["alt"] == "":
            score += 1
            reasons.append("no alt")
    return score, reasons


def _unwrap_url(url):
    """Return the real destination if the URL nests another encoded one."""
    dec = unquote(url)
    starts = [m.start() for m in re.finditer(r"https?://", dec)]
    if len(starts) >= 2:
        inner = dec[starts[-1]:]
        return re.split(r"[\s\"'<>]", inner)[0]
    return None


def analyze_body(html_parts):
    pixels, wrapped, homographs = [], [], []
    for html in html_parts:
        for img in _iter_img_tags(html):
            s, why = _score_pixel(img)
            if s >= 3:
                pixels.append({"src": img["src"], "score": s, "reasons": why})
        hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html,
                           re.IGNORECASE)
        for href in hrefs:
            if not href.lower().startswith("http"):
                continue
            inner = _unwrap_url(href)
            if inner:
                wrapped.append({"wrapper": href, "destination": inner})
            host = (urlparse(href).hostname or "")
            if has_idn_homograph(host):
                homographs.append(host)
    return {"tracking_pixels": pixels,
            "wrapped_links": wrapped,
            "idn_homographs": sorted(set(homographs))}


# --- Attachment analysis -------------------------------------------------
def analyze_attachment(att, deep=False):
    raw = att["raw"]
    info = {
        "filename": att["filename"],
        "declared_type": att["declared_type"],
        "size": att["size"],
        "sha256": _sha256(raw) if raw else None,
        "flags": [],
    }
    real = None
    for magic, label in MAGIC.items():
        if raw.startswith(magic):
            real = label
            break
    info["real_type"] = real or "unknown"

    ext = os.path.splitext(att["filename"])[1].lower()
    if ext in RISKY_EXT:
        info["flags"].append(f"high-risk extension ({ext})")
    if real and real.startswith("PE/EXE") and ext not in (".exe", ".scr",
                                                           ".dll"):
        info["flags"].append("executable with deceptive extension")
    if real == "ZIP/OOXML (docx/xlsx/jar/...)" and ext == ".pdf":
        info["flags"].append("real type ZIP but .pdf extension")

    if deep:
        info["deep"] = _deep_inspect(raw, real)
    return info


def _deep_inspect(raw, real):
    """Deep inspection (oletools/pdfid) if installed. Static only."""
    notes = []
    try:
        if real == "OLE (doc/xls legacy)" or real == "ZIP/OOXML (docx/xlsx/jar/...)":
            from oletools.olevba import VBA_Parser  # type: ignore
            vp = VBA_Parser("att", data=raw)
            if vp.detect_vba_macros():
                notes.append("VBA macros detected")
                for _, _, _, analysis in (vp.analyze_macros() or []):
                    if analysis:
                        notes.append(str(analysis)[:120])
            vp.close()
    except ImportError:
        notes.append("oletools not installed (pip install oletools)")
    except Exception as e:
        notes.append(f"ole analysis error: {e}")

    try:
        if real == "PDF":
            import io
            from pdfid import pdfid  # type: ignore
            xml = pdfid.PDFiD(io.BytesIO(raw), "att")
            s = pdfid.PDFiD2String(xml, False)
            for kw in ("/JS", "/JavaScript", "/OpenAction", "/Launch",
                       "/AA", "/EmbeddedFile"):
                m = re.search(re.escape(kw) + r"\s+(\d+)", s)
                if m and int(m.group(1)) > 0:
                    notes.append(f"PDF keyword {kw} x{m.group(1)}")
    except ImportError:
        notes.append("pdfid not installed (pip install pdfid)")
    except Exception as e:
        notes.append(f"pdf analysis error: {e}")

    return notes


# --- VirusTotal by-hash (opt-in, passive) --------------------------------
def vt_lookup_hashes(hashes):
    """VirusTotal BY-HASH lookup. Never sends the file, only the hash.
    Needs VT_API_KEY and 'requests'. Off by default."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY not set in environment"}
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed (pip install requests)"}

    results = {}
    for h in hashes:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": api_key}, timeout=20)
            if r.status_code == 200:
                stats = (r.json().get("data", {}).get("attributes", {})
                         .get("last_analysis_stats", {}))
                results[h] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            elif r.status_code == 404:
                results[h] = {"status": "not found on VT"}
            else:
                results[h] = {"status": f"HTTP {r.status_code}"}
        except Exception as e:
            results[h] = {"error": str(e)}
    return results


# --- IOCs ----------------------------------------------------------------
def extract_iocs(msg, html_parts, text_parts, header_info, attachments):
    urls, ips, domains, emails, hashes = set(), set(), set(), set(), set()
    blobs = list(html_parts) + list(text_parts)
    blobs += [str(msg.get(h, "")) for h in ("Subject", "From", "Reply-To")]

    for b in blobs:
        for u in RE_URL.findall(b):
            u = u.rstrip(".,);]'\"")
            urls.add(u)
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
        for e in RE_EMAIL.findall(b):
            emails.add(e.lower())

    for ip in header_info.get("received_public_ips", []):
        ips.add(ip)

    for u in list(urls):
        inner = _unwrap_url(u)
        if inner:
            urls.add(inner)
            h = urlparse(inner).hostname
            if h:
                domains.add(h.lower())

    for a in attachments:
        if a.get("sha256"):
            hashes.add(a["sha256"])

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "emails": sorted(emails),
        "attachment_sha256": sorted(hashes),
    }


# --- Triage orchestrator -------------------------------------------------
def analyze(path, deep=False, do_vt=False):
    msg = _load_message(path)
    html_parts, text_parts = _get_bodies(msg)
    raw_attachments = _get_attachments(msg)

    header_info = analyze_headers(msg)
    body_info = analyze_body(html_parts)
    att_info = [analyze_attachment(a, deep=deep) for a in raw_attachments]
    iocs = extract_iocs(msg, html_parts, text_parts, header_info,
                        raw_attachments)

    risk = 0
    risk += len(header_info.get("flags", [])) * 2
    risk += len(body_info["tracking_pixels"])
    risk += len(body_info["wrapped_links"])
    risk += len(body_info["idn_homographs"]) * 3
    risk += sum(len(a["flags"]) for a in att_info) * 3

    report = {
        "file": os.path.basename(path),
        "version": __version__,
        "risk_score": risk,
        "risk_level": _risk_level(risk),
        "headers": header_info,
        "body": body_info,
        "attachments": att_info,
        "iocs": iocs,
    }
    if do_vt and iocs["attachment_sha256"]:
        report["virustotal"] = vt_lookup_hashes(iocs["attachment_sha256"])
    return report


def _risk_level(score):
    if score >= 10:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "CLEAN"


# --- Console report ------------------------------------------------------
def print_report(report, do_defang=True):
    def d(v):
        return defang(v) if do_defang else v

    lvl = report["risk_level"]
    color = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW,
             "LOW": Fore.CYAN, "CLEAN": Fore.GREEN}.get(lvl, "")
    h = report["headers"]

    print(Fore.CYAN + "=" * 62)
    print(Fore.CYAN + f"  {report['file']}   "
          + color + f"[{lvl}] score={report['risk_score']}")
    print(Fore.CYAN + "=" * 62)
    print(f"  Subject : {h.get('subject', '')[:80]}")
    print(f"  From    : {h.get('from', '')}")
    print(f"  Reply-To: {h.get('reply_to', '') or '-'}")
    print(f"  Ret-Path: {h.get('return_path', '') or '-'}")
    for mech in ("spf", "dkim", "dmarc"):
        if mech in h:
            print(f"  {mech.upper():7s} : {h[mech]}")
    if h.get("received_public_ips"):
        print(f"  IP hops : {', '.join(h['received_public_ips'])}")

    if h.get("flags"):
        print(Fore.RED + "\n  [!] HEADER FLAGS:")
        for f in h["flags"]:
            print(Fore.RED + f"      - {f}")

    b = report["body"]
    if b["tracking_pixels"]:
        print(Fore.RED + "\n  [!] TRACKING PIXELS:")
        for p in b["tracking_pixels"]:
            print(Fore.RED + f"      - score={p['score']}  {d(p['src'])[:88]}")
            print(f"        -> {', '.join(p['reasons'])}")
    if b["wrapped_links"]:
        print(Fore.RED + "\n  [!] WRAPPED LINKS:")
        for w in b["wrapped_links"]:
            print(Fore.RED + f"      -> {d(w['destination'])[:88]}")
    if b["idn_homographs"]:
        print(Fore.RED + "\n  [!] IDN/HOMOGRAPH DOMAINS:")
        for dom in b["idn_homographs"]:
            print(Fore.RED + f"      - {d(dom)}")

    if report["attachments"]:
        print(Fore.CYAN + "\n  ATTACHMENTS:")
        for a in report["attachments"]:
            print(f"      - {a['filename']}  ({a['size']} bytes)")
            print(f"        declared: {a['declared_type']} | real: {a['real_type']}")
            print(f"        sha256: {a['sha256']}")
            for f in a["flags"]:
                print(Fore.RED + f"        [!] {f}")
            for note in a.get("deep", []):
                print(Fore.YELLOW + f"        [deep] {note}")

    vt = report.get("virustotal")
    if vt:
        print(Fore.CYAN + "\n  VIRUSTOTAL (by hash):")
        for hsh, res in vt.items():
            print(f"      {hsh[:16]}... -> {res}")

    io = report["iocs"]
    print(Fore.CYAN + "\n  IOCs:")
    for k in ("ips", "domains", "urls", "emails", "attachment_sha256"):
        vals = io[k]
        if not vals:
            continue
        print(Fore.GREEN + f"    {k} ({len(vals)}):")
        for v in vals[:40]:
            show = d(v) if (do_defang and k != "attachment_sha256") else v
            print(f"      {show}")
    print()


# --- File collection + CLI -----------------------------------------------
def collect_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in names:
                    if n.lower().endswith(EMAIL_EXTENSIONS):
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(Fore.YELLOW + f"[!] not found: {p}", file=sys.stderr)
    return sorted(files)


BANNER = Fore.RED + r"""
  ___ _    _    _    ___      _
 | _ \ |_ (_)__| |_ | _ ) _  | |_ ___
 |  _/ ' \| (_-< ' \| _ \ || |  _/ -_)
 |_| |_||_|_/__/_||_|___/\_, |\__\___|
                         |__/  PhishByte v%s
""" % __version__ + Fore.YELLOW + "  passive & offline email triage - by xPloits3c\n"


def main():
    examples = """
examples:
  phishbyte.py suspicious.eml                one email -> console report
  phishbyte.py ./inbox/                      scan a folder, sorted by risk
  phishbyte.py ./inbox/ -o report.json       write JSON to a file (SIEM/tools)
  phishbyte.py suspicious.eml --no-defang    IOCs not defanged (for piping)
  phishbyte.py suspicious.eml --deep         deep attachment check (oletools/pdfid)
  VT_API_KEY=key phishbyte.py m.eml --vt     VirusTotal by-hash lookup

notes:
  Passive & offline by default: no DNS, no URL fetch, attachments never opened.
  Export a suspicious message from your mail client as .eml ("Show original").
"""
    ap = argparse.ArgumentParser(
        description="PhishByte - passive, offline phishing email analyzer",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True)
    ap.add_argument("paths", nargs="*", help="one or more .eml/.msg files or folders")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("-o", "--output", help="write JSON to this file (implies --json)")
    ap.add_argument("--no-defang", action="store_true",
                    help="do not defang IOCs in console output")
    ap.add_argument("--deep", action="store_true",
                    help="deep attachment inspection via oletools/pdfid if installed")
    ap.add_argument("--vt", action="store_true",
                    help="VirusTotal by-hash lookup (needs VT_API_KEY, requests)")
    ap.add_argument("-v", "--version", action="store_true", help="show version")
    args = ap.parse_args()

    if args.version:
        print(f"PhishByte {__version__}")
        return
    if not args.paths:
        print(BANNER)
        ap.print_help()
        return

    files = collect_files(args.paths)
    if not files:
        print(Fore.YELLOW + "No .eml/.msg files found.", file=sys.stderr)
        sys.exit(1)

    reports = []
    for f in files:
        try:
            reports.append(analyze(f, deep=args.deep, do_vt=args.vt))
        except Exception as e:
            print(Fore.RED + f"[error] {f}: {e}", file=sys.stderr)

    reports.sort(key=lambda r: r["risk_score"], reverse=True)

    want_json = args.json or args.output
    if want_json:
        payload = json.dumps(reports, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(payload)
            print(Fore.GREEN + f"[✓] JSON written to {args.output} "
                  f"({len(reports)} message(s))")
        else:
            print(payload)
        return

    for r in reports:
        print_report(r, do_defang=not args.no_defang)


if __name__ == "__main__":
    main()
