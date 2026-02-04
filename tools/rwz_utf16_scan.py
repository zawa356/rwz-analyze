#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path


def is_printable(codepoint: int) -> bool:
    if codepoint == 0:
        return False
    # basic printable ranges, exclude surrogates
    if 0x20 <= codepoint <= 0xD7FF:
        return True
    if 0xE000 <= codepoint <= 0xFFFD:
        return True
    return False


def scan_utf16(data: bytes, endian: str, min_chars: int, max_chars: int):
    results = []
    step = 2
    offsets = [0, 1]
    for base in offsets:
        i = base
        while i + 1 < len(data):
            start = i
            chars = []
            while i + 1 < len(data) and len(chars) < max_chars:
                if endian == 'le':
                    cp = data[i] | (data[i + 1] << 8)
                else:
                    cp = (data[i] << 8) | data[i + 1]
                if not is_printable(cp):
                    break
                chars.append(cp)
                i += step
            if len(chars) >= min_chars:
                try:
                    if endian == 'le':
                        s = bytes(sum(([cp & 0xFF, (cp >> 8) & 0xFF] for cp in chars), [])).decode('utf-16le', errors='ignore')
                    else:
                        s = bytes(sum(([(cp >> 8) & 0xFF, cp & 0xFF] for cp in chars), [])).decode('utf-16be', errors='ignore')
                except Exception:
                    s = ''
                results.append((start, endian, len(chars), s))
            i = max(start + step, i + step)
    results.sort(key=lambda x: x[0])
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Scan RWZ for UTF-16 strings (non-ASCII)')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--min-chars', type=int, default=4, help='Minimum UTF-16 chars')
    ap.add_argument('--max-chars', type=int, default=200, help='Maximum UTF-16 chars per run')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    ap.add_argument('--limit', type=int, default=0, help='Limit output entries (0 = all)')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()
    results = []
    results.extend(scan_utf16(data, 'le', args.min_chars, args.max_chars))
    results.extend(scan_utf16(data, 'be', args.min_chars, args.max_chars))
    results.sort(key=lambda x: (x[0], x[1]))

    if args.limit:
        results = results[: args.limit]

    lines = []
    lines.append(f'# UTF-16 Scan Report: {args.path.name}')
    lines.append('')
    lines.append(f'- Results: {len(results)}')
    lines.append('')
    lines.append('| Offset | Endian | Length | Text |')
    lines.append('|--------|--------|--------|------|')
    for offset, endian, length, text in results:
        t = text.replace('|', '\\|')
        lines.append(f'| 0x{offset:08x} | {endian} | {length} | {t} |')
    lines.append('')

    report = '\n'.join(lines) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding='utf-8')
    else:
        print(report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
