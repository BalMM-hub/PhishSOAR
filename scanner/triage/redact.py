"""Masks personal details before anything is sent to the AI check.

The rules engine and threat-intel checks still see the original email on our own server,
so detection there is unchanged. Only the copy sent to the AI is masked.

What is masked (replaced with a tag the AI still understands):
  card numbers           -> [CARD-NUMBER]   (13-19 digits that pass the Luhn check)
  Nigerian phone numbers -> [PHONE]         (080..., 070..., 090..., 081..., +234...)
  other phone numbers    -> [PHONE]         (+country code and 8-15 digits)
  BVN / NIN (11 digits)  -> [ID-NUMBER]
  bank account (10 dig.) -> [ACCOUNT-NUMBER]
  email addresses        -> [EMAIL]@domain  (the domain is kept: look-alike domains are evidence)
  recipient addresses    -> [RECIPIENT]
The sender's own address is kept, because who really sent the email is the core of detection.
"""
from __future__ import annotations

import os
import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)\b")
CARD = re.compile(r"(?<![\d])(?:\d[ \-]?){12,18}\d(?![\d])")
NG_PHONE = re.compile(r"(?<![\d+])(?:\+?234[\s\-]?|0)[789][01]\d(?:[\s\-]?\d){7}(?![\d])")
INTL_PHONE = re.compile(r"(?<![\w+])\+\d{1,3}[\s\-]?(?:\(?\d{1,4}\)?[\s\-]?){2,5}\d{2,4}(?![\d])")
ELEVEN = re.compile(r"(?<![\d])\d{11}(?![\d])")
TEN = re.compile(r"(?<![\d])\d{10}(?![\d])")


def enabled() -> bool:
    return os.getenv("AI_REDACT", "on").lower() != "off"


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return "[CARD-NUMBER]" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)


def mask(text: str | None) -> str:
    """Mask personal details in free text (email body, subject, OCR text, links)."""
    if not text:
        return text or ""
    t = EMAIL.sub(lambda m: "[EMAIL]@" + m.group(1), text)
    t = CARD.sub(_card, t)
    t = NG_PHONE.sub("[PHONE]", t)
    t = INTL_PHONE.sub("[PHONE]", t)
    t = ELEVEN.sub("[ID-NUMBER]", t)
    t = TEN.sub("[ACCOUNT-NUMBER]", t)
    return t


def mask_recipients(addresses: list[str]) -> list[str]:
    return ["[RECIPIENT]" for _ in addresses]
