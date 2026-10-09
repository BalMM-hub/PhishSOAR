"""Parse a raw RFC 822 email into the fields a SOC analyst checks."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"""https?://[^\s"'<>\)\]]+""", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class _LinkExtractor(HTMLParser):
    """Collects <a href> targets with the text the reader actually sees, plus <img> counts."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self.img_count = 0
        self.forms = 0
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            self._href = a.get("href")
            self._text = []
        elif tag == "img":
            self.img_count += 1
        elif tag == "form":
            self.forms += 1

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href, "text": "".join(self._text).strip()})
            self._href = None


def domain_of(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def host_of(url: str) -> str:
    host = re.sub(r"^[a-z]+://", "", url.strip(), flags=re.I).split("/")[0].split("?")[0]
    host = host.rsplit("@", 1)[-1]  # strip userinfo tricks
    return host.split(":")[0].lower().strip(".")


def _public_ips(text: str) -> list[str]:
    out = []
    for raw in IPV4_RE.findall(text):
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if (ip.is_global or any(ip in n for n in DOC_NETS)) and raw not in out:
            out.append(raw)
    return out


def _auth_results(msg: EmailMessage) -> dict:
    header = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    received_spf = str(msg.get("Received-SPF", ""))
    res = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", header, re.IGNORECASE)
        res[mech] = m.group(1).lower() if m else "none"
    if res["spf"] == "none" and received_spf:
        res["spf"] = received_spf.split()[0].lower()
    return res


def _text_of(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


def html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&nbsp;?", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_email(raw: bytes) -> dict:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    from_hdr = str(msg.get("From", ""))
    from_name, from_addr = parseaddr(from_hdr)
    received = [str(h) for h in (msg.get_all("Received") or [])]

    text_parts, html_parts, files = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disp = part.get_content_disposition()
        is_file = bool(filename) or disp == "attachment" or ctype.startswith(("image/", "application/"))
        if ctype in ("text/plain", "text/html") and not filename and disp != "attachment":
            (text_parts if ctype == "text/plain" else html_parts).append(_text_of(part))
            continue
        if ctype == "message/rfc822":
            continue
        if is_file:
            data = part.get_payload(decode=True) or b""
            name = filename or f"inline.{ctype.split('/')[-1]}"
            files.append({
                "filename": name,
                "content_type": ctype,
                "inline": disp != "attachment" and not filename,
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "data": data,  # stripped before returning to callers
            })

    link_info = _LinkExtractor()
    for h in html_parts:
        link_info.feed(h)

    urls: list[str] = []
    for blob in text_parts + html_parts:
        for u in URL_RE.findall(blob):
            u = u.rstrip(".,;:!?")
            if u not in urls:
                urls.append(u)
    for link in link_info.links:
        href = (link["href"] or "").strip()
        if href.lower().startswith("http") and href not in urls:
            urls.append(href)

    mismatched = []
    for link in link_info.links:
        shown = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", link["text"] or "", re.I)
        if not shown or not link["href"] or not link["href"].lower().startswith("http"):
            continue
        shown_host = shown.group(1).lower()
        real = host_of(link["href"])
        if real and not (real == shown_host or real.endswith("." + shown_host) or shown_host.endswith("." + real)):
            mismatched.append({"shown": shown_host, "actual": real})

    body_text = "\n".join(text_parts).strip() or html_to_text("\n".join(html_parts))

    return {
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "from": from_hdr,
        "from_name": from_name,
        "from_address": from_addr.lower(),
        "from_domain": domain_of(from_hdr),
        "reply_to": str(msg.get("Reply-To", "")),
        "reply_to_domain": domain_of(str(msg.get("Reply-To", ""))),
        "return_path": str(msg.get("Return-Path", "")),
        "return_path_domain": domain_of(str(msg.get("Return-Path", ""))),
        "to": [a for _, a in getaddresses(msg.get_all("To") or [])],
        "auth": _auth_results(msg),
        "origin_ips": _public_ips(received[-1]) if received else [],
        "received_hops": len(received),
        "urls": urls,
        "mismatched_links": mismatched,
        "html_img_tags": link_info.img_count,
        "html_forms": link_info.forms,
        "body_text": body_text,
        "files": files,
        "headers": {k.lower(): str(v) for k, v in msg.items()},
    }
