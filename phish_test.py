#!/usr/bin/env python3
# PhishByte - sample generator (test fixtures)
# Author: xPloits3c  |  License: MIT
"""
samplegen.py - generate SYNTHETIC .eml test fixtures for PhishByte.

Produces self-contained sample emails so you can exercise the analyzer,
build demos and write tests without using real mail. Everything it emits is
INERT and non-routable by design:

  - domains use reserved TLDs / documentation names (RFC 2606):
    example.com, *.example, *.test, *.invalid  -> never resolve
  - IP addresses use the RFC 5737 TEST-NET ranges:
    192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
  - the "tracking pixel" is a 1x1 <img> pointing at a .invalid host, so it
    can never load, never phone home, never track anyone
  - the "attachment" is a few magic-byte placeholder bytes, not a real binary

This is a TEST-DATA generator, not a beacon and not a tool to send mail.
It writes files to disk; it never connects to the network.

Usage:
  python3 samplegen.py                         # one phishing sample -> ./samples/
  python3 samplegen.py -k clean                # a benign sample
  python3 samplegen.py -k mixed -n 5 -o out/   # 5 mixed samples into out/
"""

import os
import sys
import random
import argparse
from email.message import EmailMessage
from email.utils import make_msgid, formatdate

__version__ = "1.0.0"

# Reserved / documentation identifiers only (RFC 2606 + RFC 5737).
FAKE_BRANDS = ["paypai-secure.test", "secure-appleid.test",
               "account-amaz0n.invalid", "login-microsft.example",
               "bank-verify.test"]
FAKE_SENDER_DOMAINS = ["mailer-xyz.invalid", "bulk-sender.test",
                       "promo-blast.example", "newsletter-x.invalid"]
FAKE_DROP_DOMAINS = ["phish-drop.invalid", "collect-creds.test",
                     "exfil-box.example"]
TESTNET_IPS = ["192.0.2.{}", "198.51.100.{}", "203.0.113.{}"]

SUBJECTS_PHISH = [
    "Your account has been limited",
    "Unusual sign-in detected - verify now",
    "Action required: confirm your payment details",
    "Your invoice is ready",
    "Security alert: password expires today",
]
SUBJECTS_CLEAN = [
    "Monthly newsletter",
    "Your order has shipped",
    "Welcome to the community",
    "Weekly product digest",
]


def _ip():
    return random.choice(TESTNET_IPS).format(random.randint(2, 254))


def _rand_hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _pixel_img():
    """An INERT 1x1 tracking-pixel tag pointing at a .invalid host."""
    host = random.choice(["track", "open", "beacon", "pixel"]) + \
        ".mailstat.invalid"
    uid = _rand_hex(24)
    return (f'<img src="https://{host}/o.gif?uid={uid}" '
            f'width="1" height="1" style="display:none" alt="">')


def _wrapped_link(final):
    """A click-tracking wrapper around a final destination (both inert)."""
    tracker = random.choice(["click", "t", "r"]) + ".mailer-xyz.invalid"
    enc = final.replace(":", "%3A").replace("/", "%2F")
    return f"https://{tracker}/CL0/{enc}/1/{_rand_hex(6)}"


def _disguised_attachment(msg):
    """Attach inert placeholder bytes (PE magic) named as a .pdf."""
    payload = b"MZ\x90\x00" + b"\x00" * 48 + b"PHISHBYTE-SAMPLE-INERT"
    msg.add_attachment(payload, maintype="application", subtype="pdf",
                       filename="invoice.pdf")


def build_phishing_sample(idx=0):
    brand = random.choice(FAKE_BRANDS)
    sender_dom = random.choice(FAKE_SENDER_DOMAINS)
    drop = random.choice(FAKE_DROP_DOMAINS)
    ip_edge, ip_int = _ip(), _ip()

    msg = EmailMessage()
    msg["From"] = f'"Security Team" <service@{brand}>'
    msg["Reply-To"] = f"<collect@{drop}>"
    msg["Return-Path"] = f"<bounce@{sender_dom}>"
    msg["To"] = "<victim@example.com>"
    msg["Subject"] = random.choice(SUBJECTS_PHISH)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender_dom)
    msg["X-PhishByte-Sample"] = "synthetic-phishing (inert, do not send)"
    # Fake routing + failing auth, as a real phish often shows.
    msg["Received"] = (f"from mx.{sender_dom} (mx.{sender_dom} [{ip_edge}]) "
                       f"by mail.example.com; {formatdate(localtime=True)}")
    msg["Authentication-Results"] = ("mail.example.com; spf=softfail; "
                                     "dkim=fail; dmarc=fail")

    final = f"https://{brand}/verify?id={_rand_hex(6)}"
    msg.set_content(
        f"Please verify your account: {final}\n"
        f"Need help? support@{brand}\n")
    msg.add_alternative(
        f"<html><body>"
        f'<p>Dear customer, please <a href="{_wrapped_link(final)}">'
        f"verify your account</a>.</p>"
        f"{_pixel_img()}"
        f'<img src="https://cdn.example.com/logo.png" width="180" '
        f'height="50" alt="logo">'
        f"</body></html>", subtype="html")

    _disguised_attachment(msg)
    return msg


def build_clean_sample(idx=0):
    dom = "example.com"
    msg = EmailMessage()
    msg["From"] = f'"Real Company" <news@{dom}>'
    msg["To"] = "<user@example.com>"
    msg["Subject"] = random.choice(SUBJECTS_CLEAN)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=dom)
    msg["X-PhishByte-Sample"] = "synthetic-clean (inert)"
    msg["Received"] = (f"from mail.{dom} (mail.{dom} [{_ip()}]) "
                       f"by mx.example.com; {formatdate(localtime=True)}")
    msg["Authentication-Results"] = ("mx.example.com; spf=pass; dkim=pass; "
                                     "dmarc=pass")
    msg.set_content("Hello! Read our latest updates on the blog.\n")
    msg.add_alternative(
        f'<html><body><p>Hello! Read more at '
        f'<a href="https://{dom}/blog">our blog</a>.</p>'
        f'<img src="https://{dom}/logo.png" width="180" height="50" '
        f'alt="Real Company"></body></html>', subtype="html")
    return msg


def write_sample(msg, out_dir, name):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "wb") as f:
        f.write(bytes(msg))
    return path


def main():
    ap = argparse.ArgumentParser(
        description="Generate synthetic, inert .eml test fixtures for PhishByte",
        epilog="All samples use RFC 2606/5737 reserved identifiers: inert, "
               "non-routable, safe for testing. Not a beacon, not for sending.")
    ap.add_argument("-o", "--out-dir", default="samples",
                    help="output directory (default: ./samples)")
    ap.add_argument("-k", "--kind", choices=["phishing", "clean", "mixed"],
                    default="phishing", help="kind of sample(s) to generate")
    ap.add_argument("-n", "--count", type=int, default=1,
                    help="how many samples to generate")
    ap.add_argument("--seed", type=int, help="RNG seed for reproducible output")
    ap.add_argument("-v", "--version", action="store_true")
    args = ap.parse_args()

    if args.version:
        print(f"samplegen (PhishByte) {__version__}")
        return
    if args.seed is not None:
        random.seed(args.seed)

    written = []
    for i in range(max(1, args.count)):
        kind = args.kind
        if kind == "mixed":
            kind = "phishing" if i % 2 == 0 else "clean"
        if kind == "phishing":
            msg = build_phishing_sample(i)
            name = f"phish_{i+1:02d}.eml"
        else:
            msg = build_clean_sample(i)
            name = f"clean_{i+1:02d}.eml"
        written.append(write_sample(msg, args.out_dir, name))

    for p in written:
        print(f"[+] {p}")
    print(f"\n{len(written)} sample(s) written to {args.out_dir}/")
    print("Try:  python3 phishbyte.py " + args.out_dir + "/")


if __name__ == "__main__":
    main()
