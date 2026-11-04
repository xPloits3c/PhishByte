# PhishByte

**Passive, offline triage of suspicious emails (`.eml` / `.msg`).**

PhishByte inspects a suspicious email the way an analyst would — reading the raw message **offline**, never opening attachments, never making a network request that could tell the sender the address is live. It flags spoofed headers, tracking pixels, click-tracking/redirect links and deceptive attachments, extracts all IOCs, and gives each message a risk score.

> PhishByte **analyzes** phishing email you received. It is not a phishing *simulation* tool and never sends anything.

<img width="1908" height="2332" alt="image" src="https://github.com/user-attachments/assets/f9f5f9c7-6dc0-47e4-9582-c79b77245967" />

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Options](#options)
- [Output](#output)
- [Safety model](#safety-model)
- [Credits](#credits)
- [Roadmap](#roadmap)

---

## Features

- Reads `.eml` and `.msg` (Outlook, with optional `extract-msg`)
- **Header analysis** — `From` vs `Return-Path` vs `Reply-To` divergence, `Message-ID` mismatch, SPF/DKIM/DMARC results, public IPs from the `Received` chain
- **Body analysis** — tracking pixels with a transparent scoring model, click-tracking/redirect links unwrapped to their real destination, IDN/homograph domains
- **Attachment analysis** — SHA-256, real type via magic bytes vs declared extension, flags for executables masquerading as documents and other high-risk types (attachments are **never opened**)
- **IOC extraction** — IP, domains, URLs, emails, attachment hashes, defanged by default
- **Risk score & level** (CLEAN / LOW / MEDIUM / HIGH) per message
- Single file, folder (batch), console or JSON output
- Optional, opt-in: VirusTotal **by-hash** lookup (`--vt`) and deep attachment inspection (`--deep`, via `oletools` / `pdfid`)

---

## Installation

```bash
git clone https://github.com/xPloits3c/PhishByte.git
cd PhishByte
pip install -r requirements.txt
```

Requires Python 3. Only `colorama` is mandatory; everything else is optional
(`beautifulsoup4`, `extract-msg`, `requests`, `oletools`, `pdfid`).

---

## Usage

```bash
# One email -> console report
python3 phishbyte.py suspicious.eml

# A whole folder (sorted by risk), as JSON to a file
python3 phishbyte.py ./inbox/ -o report.json

# IOCs not defanged (ready to pipe into other tools)
python3 phishbyte.py suspicious.eml --no-defang

# Deep attachment inspection (needs oletools/pdfid installed)
python3 phishbyte.py suspicious.eml --deep

# VirusTotal by-hash (needs VT_API_KEY env var and requests)
export VT_API_KEY=your_key
python3 phishbyte.py suspicious.eml --vt
```

---

## What it checks

| Layer       | Checks |
|-------------|--------|
| **Headers** | From/Return-Path/Reply-To mismatch, Message-ID domain, SPF/DKIM/DMARC, Received-chain public IPs, mass-mailer `X-*` hints |
| **Body**    | Tracking pixels (1×1 size, CSS hiding, beacon host/path, opaque query ID, missing `alt`), wrapped redirect links, IDN/homograph domains |
| **Attachments** | SHA-256, magic-byte real type vs extension, high-risk extensions, executables disguised as documents, optional macro/PDF-JS inspection |

### Pixel scoring

Each `<img>` accumulates points; a tag scoring **≥ 3** is reported as a pixel.

| Signal | Points |
|--------|:------:|
| 1×1 / 0 dimensions | +3 |
| hidden via CSS (`display:none`, `opacity:0`, ...) | +2 |
| suspect host (`track.`, `click.`, ESP domains) | +2 |
| beacon-like path (`/o.gif`, `/open`, ...) | +2 |
| opaque ID in query string | +1 |
| no `alt` attribute | +1 |

### Risk level

| Level  | Score |
|--------|:-----:|
| CLEAN  | 0 |
| LOW    | 1–3 |
| MEDIUM | 4–9 |
| HIGH   | ≥ 10 |

---

## Options

| Option           | Description |
|------------------|-------------|
| `paths`          | One or more `.eml`/`.msg` files or folders |
| `--json`         | Output JSON instead of the console report |
| `-o`, `--output` | Write JSON to a file (implies `--json`) |
| `--no-defang`    | Do not defang IOCs in console output |
| `--deep`         | Deep attachment inspection via `oletools`/`pdfid` if installed |
| `--vt`           | VirusTotal **by-hash** lookup (needs `VT_API_KEY` and `requests`) |
| `-v`, `--version`| Show version |

---

## Output

The console report groups header flags, tracking pixels, wrapped links,
attachments and IOCs, led by the risk level. `--json` emits the full
structured report (one object per message, sorted by risk) for ingestion by
other tools or a SIEM.

---

## Safety model

- **No network by default.** No DNS resolution, no fetching of pixel or link URLs — nothing that confirms to the sender that the mailbox is live.
- **Attachments are never opened or executed** — only hashed and inspected statically.
- **IOCs are defanged** (`hxxp`, `[.]`, `[at]`) in console output so they can be pasted safely. Use `--no-defang` when piping to other tooling.
- `--vt` is the only feature that talks to the network, and it sends **only the SHA-256 hash**, never the file. It is off unless you ask for it.

Analyze mail on a copy, offline. Do not open suspicious emails in a client
that loads remote content.

---

## Credits

- **Developed by:** xPloits3c
- **GitHub:** https://github.com/xPloits3c/PhishByte
- **License:** MIT

---

## Roadmap

- [ ] YARA rules on bodies and attachments
- [ ] STIX / CSV IOC export
- [ ] Recursive scan of archive attachments (zip/rar)
- [ ] URL reputation (passive, by-hash/domain)
- [ ] Optional HTML report
