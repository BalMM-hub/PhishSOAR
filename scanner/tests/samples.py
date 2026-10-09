"""Builds lab test emails. All brands, domains and IPs are fictional or reserved for documentation.
Attachments are harmless stand-ins (no real malware)."""
from __future__ import annotations

import base64
import io
import zipfile
from email.message import EmailMessage

import cv2
from PIL import Image, ImageDraw


def _hdrs(m, frm, subject, ip, auth, reply_to=None, return_path=None):
    m["Return-Path"] = return_path or f"<{frm.split('<')[-1].strip('>')}>"
    m["Received"] = f"from sender.example (unknown [{ip}]) by mx.google.com; Wed, 7 Oct 2026 09:00:00 +0100"
    m["Authentication-Results"] = f"mx.google.com; {auth}"
    m["From"] = frm
    if reply_to:
        m["Reply-To"] = reply_to
    m["To"] = "staff@example.com"
    m["Subject"] = subject
    m["Date"] = "Wed, 7 Oct 2026 09:00:00 +0100"


def qr_image(url: str, text: str = "") -> bytes:
    q = cv2.QRCodeEncoder.create().encode(url)
    q = cv2.resize(q, (260, 260), interpolation=cv2.INTER_NEAREST)
    img = Image.new("RGB", (600, 420), "white")
    img.paste(Image.fromarray(q).convert("RGB"), (170, 120))
    d = ImageDraw.Draw(img)
    d.text((40, 30), text or "Scan to re-activate your mailbox", fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def credential_harvest() -> bytes:
    m = EmailMessage()
    _hdrs(m, "Microsoft Account Team <no-reply@rnicrosoft-support.xyz>", "URGENT: Unusual sign-in activity - verify your account",
          "203.0.113.45", "spf=fail smtp.mailfrom=rnicrosoft-support.xyz; dkim=none; dmarc=fail header.from=rnicrosoft-support.xyz",
          reply_to="secure-team@protonmail.com")
    m.set_content("We detected unusual sign-in activity. Verify your account within 24 hours or it will be suspended.")
    m.add_alternative("<p>We detected unusual sign-in activity. Verify your account within 24 hours or it will be suspended.</p>"
                      "<p><a href='http://login-microsoft365.top/verify'>https://account.microsoft.com/security</a></p>", subtype="html")
    return bytes(m)


def ceo_fraud() -> bytes:
    """No links, no attachments: only words. This is the one rules alone struggle with."""
    m = EmailMessage()
    _hdrs(m, "Adebayo Okafor CEO <adebayo.okafor.ceo@gmail.com>", "Quick favour",
          "198.51.100.7", "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com")
    m.set_content("Hi, are you available? I'm in a meeting and need you to process an urgent transfer to a new vendor today. "
                  "Their bank details changed, I'll send the new account number. Keep this confidential until I'm back.")
    return bytes(m)


def quishing_image() -> bytes:
    m = EmailMessage()
    _hdrs(m, "IT Helpdesk <helpdesk@mail-notice.example>", "Mailbox storage full",
          "203.0.113.80", "spf=pass smtp.mailfrom=mail-notice.example; dkim=none; dmarc=none")
    m.set_content("See below.")
    m.add_attachment(qr_image("http://mailbox-renew.click/login"), maintype="image", subtype="png", filename="notice.png")
    return bytes(m)


def pdf_qr() -> bytes:
    img = Image.open(io.BytesIO(qr_image("https://bit.ly/3payroll", "Payroll update: scan to confirm your salary details")))
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PDF")
    m = EmailMessage()
    _hdrs(m, "HR Department <hr@payroll-portal.example>", "Salary review document",
          "203.0.113.81", "spf=softfail smtp.mailfrom=payroll-portal.example; dkim=none; dmarc=none")
    m.set_content("Kindly confirm your details in the attached document.")
    m.add_attachment(buf.getvalue(), maintype="application", subtype="pdf", filename="Salary_Review_2026.pdf")
    return bytes(m)


def encrypted_zip() -> bytes:
    # A zip whose entry is flagged as encrypted (bit 0x1) -- stand-in, contents are harmless text.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("invoice_10421.pdf.exe")
        z.writestr(info, b"harmless lab placeholder")
    raw = bytearray(buf.getvalue())
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = raw.find(sig)
        off = 6 if sig == b"PK\x03\x04" else 8
        raw[i + off] |= 0x1
    m = EmailMessage()
    _hdrs(m, "Accounts <billing.dept.payments@gmail.com>", "Final notice: invoice attached",
          "198.51.100.23", "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com")
    m.set_content("Payment is overdue. Open the attached invoice immediately. Password: 4421")
    m.add_attachment(bytes(raw), maintype="application", subtype="zip", filename="Invoice_10421.zip")
    return bytes(m)


def newsletter() -> bytes:
    m = EmailMessage()
    _hdrs(m, "Northwind Weekly <news@updates.northwind-news.example>", "October security tips",
          "192.0.2.10", "spf=pass smtp.mailfrom=updates.northwind-news.example; dkim=pass header.d=updates.northwind-news.example; dmarc=pass header.from=updates.northwind-news.example")
    m.set_content("This month: turn on MFA, keep software updated, and report suspicious emails. https://updates.northwind-news.example/october")
    return bytes(m)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ALL = {
    "credential_harvest": credential_harvest, "ceo_fraud": ceo_fraud, "quishing_image": quishing_image,
    "pdf_qr": pdf_qr, "encrypted_zip": encrypted_zip, "newsletter": newsletter,
}
