# run_summary.py
"""
Command-line helper to test OCR -> Summarization pipeline.
Usage:
    python run_summary.py --file path/to/document.pdf
"""

import argparse
from ocr import OCR
from summarization import summarize_with_groq

def main():
    parser = argparse.ArgumentParser(description="Run OCR and summarization on a file")
    parser.add_argument("--file", "-f", required=True, help="Path to image or PDF file")
    args = parser.parse_args()

    file_path = args.file

    ocr = OCR()
    print(f"Running OCR on: {file_path}")
    extracted_text = ocr.extract(file_path)

    print("\n----- EXTRACTED TEXT (first 2000 chars) -----\n")
    if extracted_text:
        print(extracted_text[:2000])
    else:
        print("[No text extracted]")

    print("\n----- SUMMARY -----\n")
    summary = summarize_with_groq(extracted_text)
    print(summary)


if __name__ == "__main__":
    main()
