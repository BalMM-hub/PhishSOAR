"""Rule-based checks. Every rule that fires adds points and a plain-English reason,
so an analyst (or a client) can see exactly why an email got its verdict."""
from __future__ import annotations

import re

from .parser import host_of

FREE_MAIL = {"gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com",
             "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
              "rebrand.ly", "t.ly", "s.id", "buff.ly", "tiny.cc"}
FREE_HOSTING = ("firebaseapp.com", "web.app", "pages.dev", "netlify.app", "vercel.app", "glitch.me", "repl.co",
                "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io", "workers.dev",
                "ngrok-free.app", "ngrok.io", "sites.google.com", "forms.gle", "docs.google.com/forms",
                "ipfs.io", "dweb.link", "r2.dev", "azurewebsites.net", "web.core.windows.net")
SUSPICIOUS_TLDS = (".zip", ".mov", ".xyz", ".top", ".click", ".live", ".icu", ".buzz", ".rest", ".cfd", ".sbs",
                   ".shop", ".support", ".country", ".gq", ".tk", ".ml", ".cf", ".ga", ".lol", ".mom", ".bond")
# Brands phishers impersonate most (global + Nigerian finance). Keyword -> legit domains.
BRANDS = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "sharepoint.com", "onmicrosoft.com"],
    "office365": ["office.com", "office365.com", "microsoft.com"],
    "outlook": ["outlook.com", "microsoft.com", "live.com"],
    "paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com", "amazonses.com", "amazon.co.uk"],
    "netflix": ["netflix.com"], "docusign": ["docusign.com", "docusign.net"], "dropbox": ["dropbox.com"],
    "wetransfer": ["wetransfer.com"], "linkedin": ["linkedin.com"], "facebook": ["facebook.com", "facebookmail.com"],
    "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"], "dhl": ["dhl.com"], "fedex": ["fedex.com"],
    "google": ["google.com", "accounts.google.com", "googleusercontent.com"],
    "gtbank": ["gtbank.com"], "firstbank": ["firstbanknigeria.com"], "accessbank": ["accessbankplc.com"],
    "zenithbank": ["zenithbank.com"], "opay": ["opayweb.com"], "palmpay": ["palmpay.com"],
    "moniepoint": ["moniepoint.com"], "kuda": ["kuda.com"], "flutterwave": ["flutterwave.com"], "paystack": ["paystack.com"],
}
PRESSURE = [
    "urgent", "immediately", "verify your account", "suspended", "unusual activity", "unusual sign-in", "confirm your",
    "password expires", "password will expire", "within 24 hours", "within 48 hours", "final notice", "action required",
    "click here", "update your payment", "update your details", "invoice attached", "overdue", "wire transfer",
    "gift card", "itunes card", "change of bank", "new bank details", "new account details", "change our bank",
    "kindly update", "kindly confirm", "account will be blocked", "account will be closed", "bvn", " nin ",
    "your mailbox is full", "storage is full", "shared a document with you", "voicemail", "secure message",
    "are you available", "keep this confidential", "do not tell", "won a", "lottery", "inheritance", "beneficiary",
    "crypto", "investment opportunity", "double your",
]
PAYMENT_WORDS = ["payment", "transfer", "bank", "invoice", "account number", "gift card", "wire", "remit"]


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "co", "org", "net", "gov", "edu", "ac", "sch"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _label(domain: str) -> str:
    return registered_domain(domain).split(".")[0]


def _normalize(s: str) -> str:
    s = s.lower()
    for a, b in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")):
        s = s.replace(a, b)
    return s.replace("-", "")


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_legit_for(domain: str, legit: list[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in legit)


def lookalike(domain: str, protected: dict[str, list[str]]) -> str | None:
    """Return the brand/protected name this domain imitates, or None."""
    if not domain:
        return None
    label = _label(domain)
    norm = _normalize(label)
    for brand, legit in protected.items():
        if _is_legit_for(domain, legit):
            continue
        b = _normalize(brand)
        if len(b) < 4:
            continue
        if norm == b and label != brand:                       # homoglyph: paypa1, rnicrosoft
            return brand
        max_d = 1 if len(b) <= 6 else 2
        if 0 < _distance(norm, b) <= max_d and len(norm) >= 4:  # typosquat: paypall, micros0ft
            return brand
        if re.search(rf"(^|-){re.escape(brand)}(-|$)", label) and label != brand:  # paypal-secure
            return brand
    return None


def run_rules(p: dict, media: dict, intel: dict, ctx: dict) -> list[dict]:
    findings: list[dict] = []

    def hit(points: int, cat: str, reason: str):
        findings.append({"points": points, "category": cat, "reason": reason})

    protected = dict(BRANDS)
    for d in ctx.get("protected_domains", []):
        protected[_label(d)] = [d]

    auth = p["auth"]
    if auth["spf"] in ("fail", "softfail"):
        hit(20, "auth", f"SPF {auth['spf']}: server not allowed to send for {p['from_domain']}")
    if auth["dkim"] == "fail":
        hit(15, "auth", "DKIM signature failed: message may be forged or altered")
    if auth["dmarc"] == "fail":
        hit(25, "auth", "DMARC failed: the From address is not who it claims to be")
    if p["reply_to_domain"] and p["reply_to_domain"] != p["from_domain"]:
        pts = 20 if p["reply_to_domain"] in FREE_MAIL else 15
        hit(pts, "header", f"Replies go to {p['reply_to_domain']}, not the sender's domain {p['from_domain']}")
    if p["return_path_domain"] and registered_domain(p["return_path_domain"]) != registered_domain(p["from_domain"] or "x"):
        hit(5, "header", f"Return-Path ({p['return_path_domain']}) differs from From ({p['from_domain']})")

    # Impersonation
    imitated = lookalike(p["from_domain"], protected)
    if imitated:
        hit(35, "impersonation", f"Sender domain {p['from_domain']} imitates '{imitated}'")
    name = (p["from_name"] or "").lower()
    for brand, legit in protected.items():
        if len(brand) >= 4 and re.search(rf"\b{re.escape(brand)}\b", name) and not _is_legit_for(p["from_domain"], legit):
            hit(25, "impersonation", f"Display name mentions '{brand}' but the email comes from {p['from_domain']}")
            break
    for d in ctx.get("protected_domains", []):
        # Someone outside the company using the company's own name/domain in the display name
        if d.split(".")[0] in name and not p["from_domain"].endswith(d):
            hit(20, "impersonation", f"Display name looks internal ('{p['from_name']}') but sender is external ({p['from_domain']})")
            break
    if p["from_domain"] in FREE_MAIL and re.search(r"(support|security|team|bank|admin|billing|service|helpdesk|it dept|hr|payroll|ceo|director|manager)", name):
        hit(15, "impersonation", f"Official-sounding name '{p['from_name']}' on a free webmail address")

    # Language
    text = (p["subject"] + " " + p["body_text"] + " " + media.get("image_text", "")).lower()
    words = [w.strip() for w in PRESSURE if w in text]
    if words:
        hit(min(5 * len(words), 25), "language", "Pressure/scam wording: " + ", ".join(words[:6]))
    if ctx.get("first_time_sender") and any(w in text for w in PAYMENT_WORDS):
        hit(15, "language", "First email ever from this sender, and it talks about money/payment")

    # Links
    for m in p["mismatched_links"]:
        hit(20, "link", f"Link text shows {m['shown']} but really goes to {m['actual']}")
    all_urls = p["urls"] + media.get("extra_urls", [])
    seen_hosts = set()
    for u in all_urls:
        h = host_of(u)
        if not h or h in seen_hosts:
            continue
        seen_hosts.add(h)
        if h in SHORTENERS:
            hit(10, "link", f"URL shortener hides the real destination: {h}")
        if h.endswith(SUSPICIOUS_TLDS):
            hit(10, "link", f"High-abuse domain ending: {h}")
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", h):
            hit(15, "link", f"Link goes to a raw IP address: {h}")
        if h.startswith("xn--") or ".xn--" in h:
            hit(15, "link", f"Punycode domain (possible look-alike characters): {h}")
        if any(h == f or h.endswith("." + f) or (f in u) for f in FREE_HOSTING):
            hit(10, "link", f"Link hosted on free/abusable hosting: {h}")
        lk = lookalike(h, protected)
        if lk:
            hit(30, "impersonation", f"Link domain {h} imitates '{lk}'")
        if "@" in re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0]:
            hit(15, "link", f"URL uses '@' to hide its real host: {u[:100]}")

    # Content shape
    if media.get("image_count", 0) and len(p["body_text"]) < 200:
        hit(15, "image", "Email is mostly image with almost no text (used to hide words from filters)")
    if p.get("html_forms"):
        hit(20, "content", "Email body contains a form (asks for data inside the email)")

    for pts, reason in media.get("flags", []):
        hit(pts, "attachment" if "QR" not in reason else "image", reason)

    # Threat intel
    for u, r in intel.get("urls", {}).items():
        if r.get("malicious", 0) >= 3:
            hit(45, "intel", f"VirusTotal: {r['malicious']} engines flag {u[:100]}")
        elif r.get("malicious", 0) or r.get("suspicious", 0):
            hit(20, "intel", f"VirusTotal: {r.get('malicious', 0)} malicious / {r.get('suspicious', 0)} suspicious for {u[:100]}")
    for h, r in intel.get("files", {}).items():
        if r.get("malicious", 0) >= 3:
            hit(60, "intel", f"VirusTotal: {r['malicious']} engines flag the attachment as malware")
        elif r.get("malicious", 0):
            hit(25, "intel", f"VirusTotal: {r['malicious']} engine(s) flag the attachment")
    for ip, r in intel.get("ips", {}).items():
        if r.get("abuse_score", 0) >= 50:
            hit(20, "intel", f"AbuseIPDB: sender IP {ip} has abuse score {r['abuse_score']}%")

    # Extra reputation (domain age + abuse.ch)
    rep = intel.get("rep", {})
    sender_reg = registered_domain(p["from_domain"]) if p["from_domain"] else ""
    for d, days in rep.get("ages", {}).items():
        if not isinstance(days, int):
            continue
        if d == sender_reg:
            if days < 7:
                hit(35, "reputation", f"Sender's domain {d} was registered only {days} day(s) ago")
            elif days < 30:
                hit(25, "reputation", f"Sender's domain {d} is brand new ({days} days old)")
            elif days < 90:
                hit(10, "reputation", f"Sender's domain {d} is only {days} days old")
        else:
            if days < 7:
                hit(30, "reputation", f"Link goes to {d}, a website registered only {days} day(s) ago")
            elif days < 30:
                hit(20, "reputation", f"Link goes to {d}, a brand-new website ({days} days old)")
    for u, r in rep.get("urlhaus_urls", {}).items():
        hit(50, "intel", f"URLhaus lists this link as a known {r.get('threat') or 'malicious'} site: {u[:100]}")
    for h, r in rep.get("urlhaus_hosts", {}).items():
        if r.get("online"):
            hit(40, "intel", f"URLhaus: {h} is currently serving malware ({r['online']} active report(s))")
        elif r.get("url_count"):
            hit(15, "intel", f"URLhaus: {h} has hosted malware before ({r['url_count']} report(s))")
    for h, r in rep.get("bazaar", {}).items():
        hit(60, "intel", f"MalwareBazaar: the attachment is known malware ({r.get('signature') or r.get('file_type') or 'unknown family'})")
    for ioc, r in rep.get("threatfox", {}).items():
        hit(40, "intel", f"ThreatFox: {ioc} is a known attacker indicator ({r.get('malware') or r.get('threat') or 'malware'})")
    return findings
