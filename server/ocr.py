# ocr.py
"""
OCR utilities using:
 - PyPDF2 for text-based (copyable) PDFs (fast)
 - pdf2image + EasyOCR for scanned PDFs and images (accurate)
Install requirements: easyocr, torch, numpy, pdf2image, PyPDF2, Pillow
Make sure Poppler is installed for pdf2image (and set POPPLER_PATH if needed).
"""

import os
import string
from typing import List

import PyPDF2
from pdf2image import convert_from_path
from PIL import Image

# EasyOCR
import easyocr

# Optional: default poppler path on Windows if you installed Poppler here.
# Change this if your Poppler is installed elsewhere or leave as None if poppler is in PATH.
POPPLER_PATH = r"C:\Program Files\poppler-24.08.0\Library\bin"


class OCR:
    def __init__(self, languages: List[str] = ["en"], poppler_path: str = POPPLER_PATH):
        """
        Create a single EasyOCR reader instance (reused for all operations).
        On first creation, model files are loaded (a few seconds on CPU).
        """
        # Use CPU-only (gpu=False). Change to gpu=True if you have a CUDA GPU configured.
        self.reader = easyocr.Reader(languages, gpu=False)
        self.poppler_path = poppler_path

    # ---------------- Helpers ----------------
    def _is_mostly_garbage(self, text: str) -> bool:
        """Heuristic to decide whether extracted text is garbage/encoded characters."""
        if not text:
            return True
        printable = set(string.printable)
        total = len(text)
        printable_count = sum(1 for ch in text if ch in printable)
        if total == 0:
            return True
        ratio = printable_count / total
        return ratio < 0.7  # less than 70% printable → likely garbage

    def _join_easyocr_result(self, result: List) -> str:
        """
        Convert EasyOCR output list -> joined text.
        result items are like: [bbox, text, confidence]
        We join recognized text pieces into lines.
        """
        pieces = []
        for item in result:
            if len(item) >= 2 and item[1].strip():
                pieces.append(item[1].strip())
        # join with newline to preserve rough structure
        return "\n".join(pieces).strip()

    # ---------------- Image OCR ----------------
    def extract_from_image(self, filename: str) -> str:
        """
        Run EasyOCR on an image file path.
        Accepts file path (PNG/JPG/TIFF/etc.).
        """
        try:
            result = self.reader.readtext(filename, detail=1, paragraph=True)
            text = self._join_easyocr_result(result)
            return text
        except Exception as e:
            print("EasyOCR image error:", e)
            return ""

    # ---------------- PyPDF2 (fast path) ----------------
    def _extract_pdf_with_pypdf2(self, filename: str) -> str:
        """
        Fast extraction for digital PDFs (copyable text).
        Returns combined text from pages or empty string on failure.
        """
        text_parts = []
        try:
            with open(filename, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for i, page in enumerate(reader.pages, start=1):
                    try:
                        page_text = page.extract_text()
                    except Exception:
                        page_text = None
                    if page_text:
                        text_parts.append(page_text)
        except Exception as e:
            print("PyPDF2 PDF extract error:", e)
            return ""
        return "\n".join(text_parts).strip()

    # ---------------- PDF OCR (scanned) ----------------
    def _extract_pdf_with_easyocr(self, filename: str, dpi: int = 300) -> str:
        """
        Convert PDF pages to images using pdf2image and run EasyOCR on each page.
        Requires Poppler (pdf2image) and numpy.
        """
        try:
            import numpy as np
        except Exception:
            print("numpy is required for PDF OCR fallback. Please install numpy.")
            return ""

        all_text = []
        try:
            pages = convert_from_path(filename, dpi=dpi, poppler_path=self.poppler_path)
            for i, page in enumerate(pages, start=1):
                try:
                    # Convert PIL Image to numpy array and run EasyOCR
                    arr = np.array(page)
                    result = self.reader.readtext(arr, detail=1, paragraph=True)
                    page_text = self._join_easyocr_result(result)
                except Exception as inner_e:
                    # Fallback: save page to temp file and run reader on file path
                    tmp_path = f"__tmp_page_{i}.png"
                    try:
                        page.save(tmp_path)
                        result = self.reader.readtext(tmp_path, detail=1, paragraph=True)
                        page_text = self._join_easyocr_result(result)
                    finally:
                        try:
                            if os.path.exists(tmp_path):
                                os.remove(tmp_path)
                        except Exception:
                            pass
                if page_text:
                    all_text.append(page_text)
        except Exception as e:
            print("PDF (EasyOCR) error:", e)
            return ""
        return "\n\n".join(all_text).strip()

    # ---------------- Public PDF method ----------------
    def extract_from_pdf(self, filename: str) -> str:
        """
        Try PyPDF2 first; if result is empty or garbage, fallback to pdf2image+EasyOCR.
        """
        text = self._extract_pdf_with_pypdf2(filename)
        if not text or self._is_mostly_garbage(text):
            print("PyPDF2 result empty/garbage -> falling back to EasyOCR on PDF pages.")
            text = self._extract_pdf_with_easyocr(filename)
        return text.strip()

    # ---------------- Main entry ----------------
    def extract(self, filename: str) -> str:
        """
        Unified extractor: chooses based on file extension.
        """
        ext = os.path.splitext(filename)[1].lower()
        if ext in [".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"]:
            return self.extract_from_image(filename)
        elif ext == ".pdf":
            return self.extract_from_pdf(filename)
        else:
            return "Unsupported file type. Please use an image or PDF."


if __name__ == "__main__":
    # quick manual test
    ocr = OCR()
    sample = "kgf.png"  # change to a local sample image/pdf to test
    print("Extracting:", sample)
    print(ocr.extract(sample))
