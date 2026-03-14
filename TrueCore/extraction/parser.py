"""
TrueCore Document Parser

Responsible for extracting readable text from supported
document types including PDF, DOCX, images, and TXT files.
"""

import os
import pdfplumber
import pytesseract
from PIL import Image, ImageEnhance
import docx


# -------------------------------------------------
# TEXT CLEANING
# -------------------------------------------------

def clean_text(text):

    lines = []

    for line in text.split("\n"):

        l = line.strip()

        if len(l) < 2:
            continue

        lines.append(l)

    return "\n".join(lines)


# -------------------------------------------------
# PDF READER
# -------------------------------------------------

def read_pdf(path):

    if not os.path.exists(path):
        return ""

    text = ""

    try:

        with pdfplumber.open(path) as pdf:

            for page in pdf.pages:

                page_text = page.extract_text()

                if page_text:
                    text += page_text + "\n"

    except Exception:
        return ""

    return clean_text(text)


# -------------------------------------------------
# DOCX READER
# -------------------------------------------------

def read_docx(path):

    if not os.path.exists(path):
        return ""

    text = ""

    try:

        document = docx.Document(path)

        for paragraph in document.paragraphs:
            text += paragraph.text + "\n"

    except Exception:
        return ""

    return clean_text(text)


# -------------------------------------------------
# IMAGE OCR
# -------------------------------------------------

def read_image(path):

    if not os.path.exists(path):
        return ""

    try:

        with Image.open(path) as img:
            img = img.convert("L")
            enhancer = ImageEnhance.Contrast(img)
            img = enhancer.enhance(2)
            img = img.point(lambda x: 0 if x < 140 else 255, '1')
            text = pytesseract.image_to_string(img)

        return clean_text(text)

    except Exception:
        return ""


# -------------------------------------------------
# MAIN DOCUMENT PARSER
# -------------------------------------------------

def parse_document(path):

    if not os.path.exists(path):
        return ""

    ext = os.path.splitext(path)[1].lower()

    if ext == ".pdf":
        return read_pdf(path)

    if ext == ".docx":
        return read_docx(path)

    if ext in [".png", ".jpg", ".jpeg", ".tiff", ".bmp"]:
        return read_image(path)

    if ext == ".txt":

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return clean_text(f.read())

        except Exception:
            return ""

    return ""