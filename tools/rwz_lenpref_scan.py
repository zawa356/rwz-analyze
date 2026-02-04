#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path


def is_printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def is_printable_utf16(cp: int) -> bool:
    if cp == 0:
        return False
    if 0x20 <= cp <= 0xD7FF:
        return True
    if 0xE000 <= cp <= 0xFFFD:
        return True
    return False


def scan_lenpref_utf16le(data: bytes, min_len: int, max_len: int, step: int):
    results = []
    for i in range(0, len(data) - 2, step):
        length = int.from_bytes(data[i:i + 2], 'little')
        if length < min_len or length > max_len:
            continue
        start = i + 2
        end = start + length * 2
        if end > len(data):
            continue
        ok = 0
        for j in range(start, end, 2):
            cp = data[j] | (data[j + 1] << 8)
            if is_printable_utf16(cp):
                ok += 1
        ratio = ok / length if length else 0
        if ratio >= 0.9:
            try:
                s = data[start:end].decode('utf-16le', errors='ignore')
            except Exception:
                s = ''
            results.append((i, length, ratio, s))
    return results


def scan_lenpref_ascii(data: bytes, min_len: int, max_len: int, step: int):
    results = []
    for i in range(0, len(data) - 2, step):
        length = int.from_bytes(data[i:i + 2], 'little')
        if length < min_len or length > max_len:
            continue
        start = i + 2
        end = start + length
        if end > len(data):
            continue
        ok = sum(1 for b in data[start:end] if is_printable_ascii(b))
        ratio = ok / length if length else 0
        if ratio >= 0.9:
            try:
                s = data[start:end].decode('ascii', errors='ignore')
            except Exception:
                s = ''
            results.append((i, length, ratio, s))
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Scan RWZ for length-prefixed strings')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--min-len', type=int, default=3, help='Minimum length')
    ap.add_argument('--max-len', type=int, default=200, help='Maximum length')
    ap.add_argument('--step', type=int, default=1, help='Scan step (bytes)')
    ap.add_argument('--limit', type=int, default=200, help='Limit output entries per type')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()
    u16 = scan_lenpref_utf16le(data, args.min_len, args.max_len, args.step)
    asc = scan_lenpref_ascii(data, args.min_len, args.max_len, args.step)

    u16 = u16[: args.limit]
    asc = asc[: args.limit]

    lines = []
    lines.append(f'# Length-Prefixed Scan Report: {args.path.name}')
    lines.append('')
    lines.append(f'- UTF-16LE hits: {len(u16)}')
    lines.append(f'- ASCII hits: {len(asc)}')
    lines.append('')

    if u16:
        lines.append('## UTF-16LE')
        lines.append('| Offset | Length | Ratio | Text |')
        lines.append('|--------|--------|-------|------|')
        for off, length, ratio, text in u16:
            t = text.replace('|', '\\|')
            lines.append(f'| 0x{off:08x} | {length} | {ratio:.2f} | {t} |')
        lines.append('')

    if asc:
        lines.append('## ASCII')
        lines.append('| Offset | Length | Ratio | Text |')
        lines.append('|--------|--------|-------|------|')
        for off, length, ratio, text in asc:
            t = text.replace('|', '\\|')
            lines.append(f'| 0x{off:08x} | {length} | {ratio:.2f} | {t} |')
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
