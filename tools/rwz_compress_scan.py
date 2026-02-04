#!/usr/bin/env python3
import argparse
import math
import re
import sys
from pathlib import Path

try:
    import lz4.frame
    import lz4.block
except Exception:
    lz4 = None
try:
    import zstandard as zstd
except Exception:
    zstd = None
try:
    import snappy
except Exception:
    snappy = None
try:
    import lznt1
except Exception:
    lznt1 = None


UTF16LE_RE = re.compile(rb'(?:[\x20-\x7e]\x00){2,}')
UTF16BE_RE = re.compile(rb'(?:\x00[\x20-\x7e]){2,}')
ASCII_RE = re.compile(rb'[\x20-\x7e]{2,}')

MAGIC_ZSTD = b'\x28\xb5\x2f\xfd'
MAGIC_LZ4F = b'\x04\x22\x4d\x18'
MAGIC_SNAP = b'\xff\x06\x00\x00sNaPpY'


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


def build_gaps(data: bytes):
    ranges = []
    for m in UTF16LE_RE.finditer(data):
        ranges.append((m.start(), m.end()))
    for m in UTF16BE_RE.finditer(data):
        ranges.append((m.start(), m.end()))
    for m in ASCII_RE.finditer(data):
        ranges.append((m.start(), m.end()))
    merged = merge_ranges(ranges)
    gaps = []
    last = 0
    for start, end in merged:
        if start > last:
            gaps.append((last, start))
        last = max(last, end)
    if last < len(data):
        gaps.append((last, len(data)))
    gaps.sort(key=lambda x: x[1] - x[0], reverse=True)
    return gaps


def printable_ratio(buf: bytes) -> float:
    if not buf:
        return 0.0
    return sum(1 for b in buf if 0x20 <= b <= 0x7e) / len(buf)


def sample_ascii(buf: bytes, limit: int = 6):
    out = []
    for m in ASCII_RE.finditer(buf):
        out.append(m.group().decode('ascii', errors='ignore'))
        if len(out) >= limit:
            break
    return out


def try_lz4_frame(buf: bytes):
    if not lz4:
        return None
    try:
        return lz4.frame.decompress(buf)
    except Exception:
        return None


def try_lz4_block(buf: bytes):
    if not lz4:
        return None
    for size in (64 * 1024, 256 * 1024, 1024 * 1024):
        try:
            return lz4.block.decompress(buf, uncompressed_size=size)
        except Exception:
            continue
    return None


def try_zstd(buf: bytes):
    if not zstd:
        return None
    try:
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(buf)
    except Exception:
        return None


def try_snappy(buf: bytes):
    if not snappy:
        return None
    try:
        return snappy.uncompress(buf)
    except Exception:
        return None


def try_lznt1(buf: bytes):
    if not lznt1:
        return None
    try:
        return lznt1.decompress(buf)
    except Exception:
        return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Scan RWZ gaps for compressed streams')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--gap-limit', type=int, default=200, help='Number of largest gaps to scan')
    ap.add_argument('--max-out', type=int, default=2_000_000, help='Max decompressed bytes to keep')
    ap.add_argument('--min-out', type=int, default=128, help='Min decompressed bytes to report')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    ap.add_argument('--dump-dir', type=Path, help='Dump decompressed candidates here')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()
    gaps = build_gaps(data)[: args.gap_limit]

    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append(f'# Compression Scan Report: {args.path.name}')
    lines.append('')
    lines.append(f'- Gaps scanned: {len(gaps)}')
    lines.append('')

    hit_count = 0

    for gidx, (start, end) in enumerate(gaps, start=1):
        buf = data[start:end]
        size = end - start
        candidates = []

        # Magic-based checks
        if MAGIC_ZSTD in buf:
            off = buf.find(MAGIC_ZSTD)
            out = try_zstd(buf[off:])
            if out and len(out) >= args.min_out:
                candidates.append(('zstd', start + off, out))

        if MAGIC_LZ4F in buf:
            off = buf.find(MAGIC_LZ4F)
            out = try_lz4_frame(buf[off:])
            if out and len(out) >= args.min_out:
                candidates.append(('lz4_frame', start + off, out))

        if MAGIC_SNAP in buf:
            # framed snappy; keep marker only
            candidates.append(('snappy_framed_magic', start + buf.find(MAGIC_SNAP), b''))  # no decode

        # Heuristic attempts from gap start (may fail)
        for name, fn in (
            ('lz4_block', try_lz4_block),
            ('snappy_raw', try_snappy),
            ('lznt1', try_lznt1),
        ):
            out = fn(buf)
            if out and len(out) >= args.min_out:
                candidates.append((name, start, out))

        if not candidates:
            continue

        lines.append(f'## Gap {gidx}')
        lines.append(f'- Range: 0x{start:08x} .. 0x{end:08x} (size {size})')
        for cidx, (name, off, out) in enumerate(candidates, start=1):
            if out:
                clipped = out[: args.max_out]
                ratio = printable_ratio(clipped)
                lines.append(f'- Candidate {cidx}: {name} at 0x{off:08x}, size {len(out)}, printable {ratio:.2f}')
                samples = sample_ascii(clipped, limit=6)
                if samples:
                    lines.append('  - ASCII samples:')
                    for s in samples:
                        lines.append(f'    - {s}')
                if args.dump_dir:
                    out_path = args.dump_dir / f'{name}_{gidx:03d}_0x{off:08x}.bin'
                    out_path.write_bytes(clipped)
                hit_count += 1
            else:
                lines.append(f'- Candidate {cidx}: {name} magic at 0x{off:08x} (no decode)')
        lines.append('')

    lines.insert(3, f'- Candidates found: {hit_count}')

    report = '\n'.join(lines) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding='utf-8')
    else:
        print(report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
