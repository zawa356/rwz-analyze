#!/usr/bin/env python3
import argparse
import math
import re
import sys
import zlib
from pathlib import Path


UTF16LE_RE = re.compile(rb'(?:[\x20-\x7e]\x00){2,}')
UTF16BE_RE = re.compile(rb'(?:\x00[\x20-\x7e]){2,}')
ASCII_RE = re.compile(rb'[\x20-\x7e]{2,}')
GUID_RE = re.compile(rb'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
MAGIC = [
    (b'\x1f\x8b', 'gzip'),
    (b'\x78\x01', 'zlib (no/low compression)'),
    (b'\x78\x9c', 'zlib (default)'),
    (b'\x78\xda', 'zlib (max)'),
    (b'PK\x03\x04', 'zip'),
    (b'Rar!\x1a\x07\x00', 'rar'),
    (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'%PDF', 'pdf'),
    (b'\x89PNG', 'png'),
    (b'JFIF', 'jpeg (jfif)'),
    (b'Exif', 'jpeg (exif)'),
]


def merge_ranges(ranges):
    if not ranges:
        return []
    ranges.sort()
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        last = merged[-1]
        if start <= last[1]:
            if end > last[1]:
                last[1] = end
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    entropy = 0.0
    n = len(buf)
    for c in counts:
        if c:
            p = c / n
            entropy -= p * (math.log(p) / math.log(2))
    return entropy


def ratio_printable(buf: bytes) -> float:
    if not buf:
        return 0.0
    printable = sum(1 for b in buf if 0x20 <= b <= 0x7e)
    return printable / len(buf)


def ratio_zero(buf: bytes) -> float:
    if not buf:
        return 0.0
    zeros = buf.count(0)
    return zeros / len(buf)


def utf16le_likeness(buf: bytes) -> float:
    if len(buf) < 2:
        return 0.0
    even_zeros = sum(1 for i in range(0, len(buf), 2) if buf[i] == 0)
    odd_zeros = sum(1 for i in range(1, len(buf), 2) if buf[i] == 0)
    even_ratio = even_zeros / max(1, (len(buf) + 1) // 2)
    odd_ratio = odd_zeros / max(1, len(buf) // 2)
    return max(odd_ratio, even_ratio)


def find_ascii_runs(buf: bytes, limit: int):
    runs = []
    for m in ASCII_RE.finditer(buf):
        s = m.group().decode('ascii', errors='ignore')
        runs.append(s)
        if limit and len(runs) >= limit:
            break
    return runs


def find_utf16le_runs(buf: bytes, limit: int):
    runs = []
    for m in UTF16LE_RE.finditer(buf):
        s = m.group().decode('utf-16le', errors='ignore')
        runs.append(s)
        if limit and len(runs) >= limit:
            break
    return runs


def find_utf16be_runs(buf: bytes, limit: int):
    runs = []
    for m in UTF16BE_RE.finditer(buf):
        s = m.group().decode('utf-16be', errors='ignore')
        runs.append(s)
        if limit and len(runs) >= limit:
            break
    return runs


def hex_preview(buf: bytes, length: int) -> str:
    chunk = buf[:length]
    return ' '.join(f'{b:02x}' for b in chunk)


def detect_magic(buf: bytes) -> list[str]:
    hits = []
    for sig, name in MAGIC:
        if buf.startswith(sig):
            hits.append(name)
    return hits


def try_zlib(buf: bytes) -> str | None:
    # Best-effort: try small window from start
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            out = zlib.decompress(buf[:4096], wbits)
            if out:
                return f'zlib_ok({len(out)} bytes)'
        except Exception:
            continue
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Analyze RWZ gaps (uncovered byte regions)')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--min-chars', type=int, default=2, help='Minimum characters for extraction')
    ap.add_argument('--gap-limit', type=int, default=80, help='Number of largest gaps to analyze')
    ap.add_argument('--sample-limit', type=int, default=8, help='Max sample runs per gap')
    ap.add_argument('--preview-bytes', type=int, default=96, help='Hex preview bytes')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()

    ranges = []
    for m in UTF16LE_RE.finditer(data):
        if len(m.group()) // 2 >= args.min_chars:
            ranges.append((m.start(), m.end()))
    for m in UTF16BE_RE.finditer(data):
        if len(m.group()) // 2 >= args.min_chars:
            ranges.append((m.start(), m.end()))
    for m in ASCII_RE.finditer(data):
        if len(m.group()) >= args.min_chars:
            ranges.append((m.start(), m.end()))

    merged = merge_ranges(ranges)

    # build gaps
    gaps = []
    last = 0
    for start, end in merged:
        if start > last:
            gaps.append((last, start))
        last = max(last, end)
    if last < len(data):
        gaps.append((last, len(data)))

    gaps.sort(key=lambda x: x[1] - x[0], reverse=True)
    gaps = gaps[: args.gap_limit]

    out_lines = []
    out_lines.append(f'# RWZ Gap Deep Report: {args.path.name}')
    out_lines.append('')
    out_lines.append(f'- File size: {len(data)} bytes')
    out_lines.append(f'- Gaps analyzed: {len(gaps)}')
    out_lines.append('')

    for idx, (start, end) in enumerate(gaps, start=1):
        buf = data[start:end]
        size = end - start
        ent = shannon_entropy(buf)
        zratio = ratio_zero(buf)
        pratio = ratio_printable(buf)
        u16like = utf16le_likeness(buf)
        guid_matches = [m.group().decode('ascii', errors='ignore') for m in GUID_RE.finditer(buf)][: args.sample_limit]
        magic = detect_magic(buf)
        zlib_note = try_zlib(buf)

        out_lines.append(f'## Gap {idx}')
        out_lines.append(f'- Range: 0x{start:08x} .. 0x{end:08x} (size {size})')
        out_lines.append(f'- Entropy: {ent:.3f}')
        out_lines.append(f'- Zero ratio: {zratio:.3f}')
        out_lines.append(f'- Printable ASCII ratio: {pratio:.3f}')
        out_lines.append(f'- UTF-16-like ratio: {u16like:.3f}')
        if magic:
            out_lines.append(f'- Magic: {", ".join(magic)}')
        if zlib_note:
            out_lines.append(f'- Zlib probe: {zlib_note}')
        out_lines.append(f'- Hex head ({args.preview_bytes} bytes): `{hex_preview(buf, args.preview_bytes)}`')
        out_lines.append('')

        ascii_runs = find_ascii_runs(buf, args.sample_limit)
        u16le_runs = find_utf16le_runs(buf, args.sample_limit)
        u16be_runs = find_utf16be_runs(buf, args.sample_limit)

        if ascii_runs:
            out_lines.append('### ASCII runs')
            for s in ascii_runs:
                out_lines.append(f'- {s}')
            out_lines.append('')

        if u16le_runs:
            out_lines.append('### UTF-16LE runs')
            for s in u16le_runs:
                out_lines.append(f'- {s}')
            out_lines.append('')

        if u16be_runs:
            out_lines.append('### UTF-16BE runs')
            for s in u16be_runs:
                out_lines.append(f'- {s}')
            out_lines.append('')

        if guid_matches:
            out_lines.append('### GUID-like')
            for s in guid_matches:
                out_lines.append(f'- {s}')
            out_lines.append('')

    report = '\n'.join(out_lines) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding='utf-8')
    else:
        print(report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
