#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TRANSPORT_TOKENS = {"SMTP", "MSMTP", "PSMTP"}


def extract_utf16le_strings(data: bytes, min_chars: int = 3):
    # UTF-16LE printable ASCII (space through tilde)
    pat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_chars)
    items = []
    for m in pat.finditer(data):
        s = m.group().decode("utf-16le", "ignore")
        items.append({"offset": m.start(), "text": s})
    return items


def extract_ascii_strings(data: bytes, min_chars: int = 3):
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_chars)
    items = []
    for m in pat.finditer(data):
        s = m.group().decode("ascii", "ignore")
        items.append({"offset": m.start(), "text": s})
    return items


def group_by_headers(items):
    header_re = re.compile(r"^\[[^\]]+\]")
    groups = []
    current = None
    for item in items:
        if header_re.match(item["text"]):
            if current:
                groups.append(current)
            current = {
                "header": item["text"],
                "start_offset": item["offset"],
                "items": [],
            }
        if current:
            current["items"].append(item)
    if current:
        groups.append(current)
    return groups


def dedup_preserve(seq):
    seen = set()
    out = []
    for s in seq:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def normalize_email(raw: str, known: set[str]) -> str:
    if len(raw) > 2 and raw[0].isupper():
        tail = raw[1:]
        if tail.lower() in known:
            return tail.lower()
    if EMAIL_RE.fullmatch(raw):
        return raw.lower()
    return raw.lower()


def summarize_group(g):
    raw_emails = []
    other = []
    for item in g["items"]:
        s = item["text"].strip()
        if not s:
            continue
        if s == g["header"]:
            continue
        if s.upper() in TRANSPORT_TOKENS:
            continue
        found = EMAIL_RE.findall(s)
        if found:
            raw_emails.extend(found)
            continue
        other.append(s)
    known = {e.lower() for e in raw_emails}
    return {
        "header": g["header"],
        "start_offset": g["start_offset"],
        "emails": dedup_preserve([normalize_email(e, known) for e in raw_emails]),
        "other": dedup_preserve(other),
    }


def main():
    ap = argparse.ArgumentParser(description="Best-effort RWZ (Outlook rules) string extractor")
    ap.add_argument("path", type=Path, help="RWZ file path")
    ap.add_argument("--min-len", type=int, default=3, help="minimum UTF-16LE string length")
    ap.add_argument("--include-ascii", action="store_true", help="also extract ASCII strings")
    ap.add_argument("--mode", choices=["grouped", "raw", "summary", "json"], default="summary")
    ap.add_argument("--limit", type=int, default=0, help="limit groups/items (0 = no limit)")
    ap.add_argument("--out", type=Path, help="write output to a file (UTF-8)")
    args = ap.parse_args()

    data = args.path.read_bytes()
    items = extract_utf16le_strings(data, min_chars=args.min_len)
    if args.include_ascii:
        items.extend(extract_ascii_strings(data, min_chars=args.min_len))
        items.sort(key=lambda x: x["offset"])

    out = sys.stdout
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        out = args.out.open("w", encoding="utf-8", newline="")
    try:
        if args.mode == "raw":
            count = 0
            for item in items:
                print(f"0x{item['offset']:08x} {item['text']}", file=out)
                count += 1
                if args.limit and count >= args.limit:
                    break
            return

        groups = group_by_headers(items)

        if args.mode == "json":
            print(json.dumps({"groups": groups}, ensure_ascii=False, indent=2), file=out)
            return

        if args.mode == "grouped":
            count = 0
            for g in groups:
                print(f"{g['header']} @ 0x{g['start_offset']:08x}", file=out)
                for item in g["items"]:
                    print(f"  0x{item['offset']:08x} {item['text']}", file=out)
                count += 1
                if args.limit and count >= args.limit:
                    break
            return

        # summary
        count = 0
        for g in groups:
            s = summarize_group(g)
            print(f"{s['header']} @ 0x{s['start_offset']:08x}", file=out)
            if s["emails"]:
                print("  emails:", file=out)
                for e in s["emails"]:
                    print(f"    - {e}", file=out)
            if s["other"]:
                print("  other:", file=out)
                for o in s["other"]:
                    print(f"    - {o}", file=out)
            count += 1
            if args.limit and count >= args.limit:
                break
    finally:
        if out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    main()
