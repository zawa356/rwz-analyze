#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def collect_images(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    images = []
    for ext in ("*.png", "*.jpg", "*.jpeg", "*.bmp", "*.tif", "*.tiff"):
        images.extend(path.rglob(ext))
    return sorted(images)


def run_tesseract(image: Path, lang: str) -> str:
    cmd = ["tesseract", str(image), "stdout", "-l", lang]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"tesseract failed on {image}")
    return res.stdout


def clean_lines(text: str, min_len: int) -> list[str]:
    lines = []
    for raw in text.splitlines():
        s = " ".join(raw.split())
        if len(s) >= min_len:
            lines.append(s)
    return lines


def extract_tokens(lines: list[str], min_len: int) -> list[str]:
    tokens = []
    for line in lines:
        for part in re.split(r"[|/]", line):
            s = part.strip()
            if len(s) >= min_len:
                tokens.append(s)
    return tokens


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="OCR Outlook rule screenshots to JSON")
    ap.add_argument("path", type=Path, help="image file or directory")
    ap.add_argument("--lang", default="jpn+eng", help="tesseract language (default: jpn+eng)")
    ap.add_argument("--line-min", type=int, default=3, help="minimum cleaned line length")
    ap.add_argument("--token-min", type=int, default=3, help="minimum token length")
    ap.add_argument("--limit", type=int, default=0, help="limit number of images (0 = no limit)")
    ap.add_argument("--out", type=Path, help="write output JSON to file (UTF-8)")
    args = ap.parse_args(argv)

    if not shutil.which("tesseract"):
        print("tesseract not found. Install it or provide OCR text manually.", file=sys.stderr)
        return 2

    images = collect_images(args.path)
    if args.limit:
        images = images[: args.limit]
    if not images:
        print("no images found", file=sys.stderr)
        return 1

    payload = {"source": str(args.path), "images": []}
    for img in images:
        try:
            text = run_tesseract(img, args.lang)
        except Exception as exc:
            payload["images"].append(
                {
                    "file": str(img),
                    "error": str(exc),
                    "lines": [],
                    "tokens": [],
                    "emails": [],
                }
            )
            continue
        lines = clean_lines(text, args.line_min)
        tokens = extract_tokens(lines, args.token_min)
        emails = sorted({e for line in lines for e in EMAIL_RE.findall(line)})
        payload["images"].append(
            {
                "file": str(img),
                "lines": lines,
                "tokens": tokens,
                "emails": emails,
            }
        )

    out_text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
