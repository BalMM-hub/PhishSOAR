"""Inspect attachments and images: QR codes ("quishing"), text inside images (OCR),
PDFs, Office macros, archives and HTML smuggling. Nothing is ever executed or opened
in a viewer; files are only decoded as data."""
from __future__ import annotations

import base64
import io
import re
import shutil
import subprocess
import tempfile
import zipfile

import cv2
import numpy as np
from PIL import Image

from .parser import URL_RE

RISKY_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".lnk",
    ".iso", ".img", ".vhd", ".html", ".htm", ".shtml", ".svg", ".one", ".docm", ".xlsm", ".pptm",
    ".jar", ".msi", ".cab", ".zip", ".rar", ".7z", ".gz", ".ace", ".arj",
}
EXECUTABLE_EXT = {".exe", ".scr", ".js", ".vbs", ".hta", ".bat", ".cmd", ".ps1", ".lnk", ".msi", ".jar", ".wsf"}
MAX_IMAGES_FOR_AI = 3
MAX_PIXELS = 25_000_000


def ext_of(name: str) -> str:
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


def _decode_qr(img: Image.Image) -> list[str]:
    arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
    found: list[str] = []
    detector = cv2.QRCodeDetector()
    try:
        ok, texts, _, _ = detector.detectAndDecodeMulti(arr)
        if ok:
            found += [t for t in texts if t]
    except cv2.error:
        pass
    if not found:
        try:
            text, _, _ = detector.detectAndDecode(arr)
            if text:
                found.append(text)
        except cv2.error:
            pass
    return list(dict.fromkeys(found))


def _ocr(img: Image.Image) -> str:
    if not shutil.which("tesseract"):
        return ""
    with tempfile.NamedTemporaryFile(suffix=".png") as f:
        img.convert("L").save(f.name)
        try:
            out = subprocess.run(["tesseract", f.name, "-", "--psm", "6"], capture_output=True, timeout=30)
            return re.sub(r"\s+", " ", out.stdout.decode("utf-8", "replace")).strip()
        except (subprocess.TimeoutExpired, OSError):
            return ""


def _for_ai(img: Image.Image) -> dict:
    img = img.convert("RGB")
    img.thumbnail((800, 800))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=70)
    return {"media_type": "image/jpeg", "data": base64.b64encode(buf.getvalue()).decode()}


def _image_from_bytes(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:
            return None
        img.load()
        return img
    except Exception:
        return None


def _pdf_pages(data: bytes, max_pages: int = 2) -> tuple[list[Image.Image], str]:
    try:
        import pypdfium2 as pdfium
        pdf = pdfium.PdfDocument(data)
    except Exception:
        return [], ""
    images, text = [], []
    for i in range(min(len(pdf), max_pages)):
        page = pdf[i]
        try:
            text.append(page.get_textpage().get_text_range())
        except Exception:
            pass
        try:
            images.append(page.render(scale=1.5).to_pil())
        except Exception:
            pass
    return images, " ".join(text)


def inspect_files(files: list[dict]) -> dict:
    out = {
        "attachments": [],   # summary per file (no raw bytes)
        "qr_urls": [],
        "image_text": "",
        "ai_images": [],
        "image_count": 0,
        "flags": [],         # (points, reason)
        "extra_urls": [],
    }

    def flag(points: int, reason: str):
        out["flags"].append((points, reason))

    ocr_chunks = []
    for f in files:
        name, data, ctype = f["filename"], f["data"], f["content_type"]
        ext = ext_of(name)
        summary = {k: f[k] for k in ("filename", "content_type", "size", "sha256", "md5", "inline")}
        out["attachments"].append(summary)
        if not f["inline"]:
            if name.count(".") >= 2 and ext in RISKY_EXT:
                flag(25, f"Double extension trick: {name}")
            elif ext in EXECUTABLE_EXT:
                flag(35, f"Executable/script attachment: {name}")
            elif ext in RISKY_EXT:
                flag(15, f"Risky attachment type: {name}")

        images: list[Image.Image] = []
        if ctype.startswith("image/") or ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
            img = _image_from_bytes(data)
            if img is not None and img.width * img.height >= 80 * 80:  # skip tracking pixels/icons
                images.append(img)
        elif ctype == "application/pdf" or ext == ".pdf":
            pages, text = _pdf_pages(data)
            images += pages
            out["extra_urls"] += [u.rstrip(".,;)") for u in URL_RE.findall(text)]
            if text:
                ocr_chunks.append(text[:2000])
            low = data[:2_000_000]
            if re.search(rb"/(JavaScript|JS|Launch|EmbeddedFile|OpenAction)\b", low):
                flag(20, f"PDF contains active content (JavaScript/launch/embedded file): {name}")
            if b"/Encrypt" in low:
                flag(10, f"Password-protected PDF (hides content from scanners): {name}")
        elif ext in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".zip"} or ctype in ("application/zip", "application/x-zip-compressed"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    infos = z.infolist()
                    names = [i.filename for i in infos]
                    if any(i.flag_bits & 0x1 for i in infos):
                        flag(25, f"Password-protected archive (common way to dodge scanners): {name}")
                    if any(n.lower().endswith("vbaproject.bin") for n in names):
                        flag(30, f"Office document contains macros: {name}")
                    bad = [n for n in names if ext_of(n) in EXECUTABLE_EXT or ext_of(n) in {".iso", ".img", ".html", ".htm"}]
                    if bad:
                        flag(30, f"Archive {name} contains risky files: {', '.join(bad[:3])}")
                    for n in names:
                        if n.endswith(".rels") and not any(i.flag_bits & 0x1 for i in infos):
                            rel = z.read(n)[:200_000]
                            if re.search(rb'TargetMode="External"', rel) and re.search(rb"attachedTemplate|oleObject", rel):
                                flag(30, f"Office document loads a remote template/object: {name}")
                                break
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
                pass
        elif ext in {".html", ".htm", ".shtml", ".svg"} or ctype in ("text/html", "image/svg+xml"):
            txt = data[:500_000].decode("utf-8", "replace").lower()
            if 'type="password"' in txt or "type='password'" in txt or "<form" in txt:
                flag(30, f"HTML attachment contains a login/password form: {name}")
            if re.search(r"atob\(|fromcharcode|window\.location|document\.write\(unescape|msSaveOrOpenBlob", txt):
                flag(25, f"HTML attachment uses script tricks (possible HTML smuggling/redirect): {name}")
            out["extra_urls"] += [u.rstrip(".,;)") for u in URL_RE.findall(data[:500_000].decode("utf-8", "replace"))]

        for img in images:
            out["image_count"] += 1
            for q in _decode_qr(img):
                out["qr_urls"].append(q)
            text = _ocr(img)
            if text:
                ocr_chunks.append(text[:1500])
                out["extra_urls"] += [u.rstrip(".,;)") for u in URL_RE.findall(text)]
            if len(out["ai_images"]) < MAX_IMAGES_FOR_AI:
                out["ai_images"].append(_for_ai(img))

    for q in out["qr_urls"]:
        if re.match(r"https?://", q, re.I):
            flag(20, f"QR code hides a link: {q[:120]} (common 'quishing' trick to dodge link scanners)")
    out["image_text"] = " ".join(ocr_chunks)[:4000]
    out["extra_urls"] = list(dict.fromkeys(out["extra_urls"] + [q for q in out["qr_urls"] if q.lower().startswith("http")]))
    return out
