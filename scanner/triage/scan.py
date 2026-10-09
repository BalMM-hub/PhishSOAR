"""Offline scanner: parse -> inspect files and images -> rules -> verdict.

This is the local detection layer of the full system. In production it is combined with
threat-intel lookups and an LLM review, but everything here runs on your own machine with no API keys.
"""
from __future__ import annotations

from . import media, rules
from .parser import parse_email

MALICIOUS_AT = 70
SUSPICIOUS_AT = 40


def scan(raw: bytes, protected_domains: list[str] | None = None) -> dict:
    p = parse_email(raw)
    m = media.inspect_files(p["files"])
    ctx = {"protected_domains": [d.lower() for d in (protected_domains or [])], "first_time_sender": False}
    findings = rules.run_rules(p, m, {}, ctx)
    score = min(sum(f["points"] for f in findings), 100)
    verdict = "MALICIOUS" if score >= MALICIOUS_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "CLEAN"
    return {
        "verdict": verdict,
        "score": score,
        "from": p["from"],
        "subject": p["subject"],
        "auth": p["auth"],
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "qr_urls": m["qr_urls"],
        "urls": list(dict.fromkeys(m["extra_urls"] + p["urls"])),
        "attachments": [{k: a[k] for k in ("filename", "content_type", "size", "sha256")} for a in m["attachments"]],
    }
