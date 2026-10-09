"""Usage:  python -m triage ../samples/credential_harvest.eml [more.eml ...] [--protect yourcompany.com]"""
from __future__ import annotations

import argparse
import json

from .scan import scan

COLOURS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "CLEAN": "\033[92m"}
RESET = "\033[0m"


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan .eml files for phishing signs (offline).")
    ap.add_argument("files", nargs="+", help=".eml files to scan")
    ap.add_argument("--protect", action="append", default=[], help="your own domain, to catch look-alikes")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    a = ap.parse_args()
    for path in a.files:
        with open(path, "rb") as fh:
            r = scan(fh.read(), a.protect)
        if a.json:
            print(json.dumps(r, indent=2))
            continue
        c = COLOURS[r["verdict"]]
        print(f"\n{path}")
        print(f"  {c}{r['verdict']}{RESET}  score {r['score']}/100   {r['subject']}")
        print(f"  from {r['from']}  |  SPF {r['auth']['spf']}  DKIM {r['auth']['dkim']}  DMARC {r['auth']['dmarc']}")
        for f in r["findings"][:6]:
            print(f"   +{f['points']:<3} {f['reason']}")
        for q in r["qr_urls"]:
            print(f"   QR code -> {q}")


if __name__ == "__main__":
    main()
