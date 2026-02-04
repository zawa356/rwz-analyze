#!/usr/bin/env python3
import argparse
import re
import sys
import zlib
from pathlib import Path


ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')
UTF16LE_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def is_zlib_header(cmf: int, flg: int) -> bool:
    if cmf & 0x0F != 8:
        return False
    if ((cmf << 8) + flg) % 31 != 0:
        return False
    return True


def extract_ascii(data: bytes, limit: int = 10):
    out = []
    for m in ASCII_RE.finditer(data):
        out.append(m.group().decode('ascii', errors='ignore'))
        if limit and len(out) >= limit:
            break
    return out


def extract_utf16le(data: bytes, limit: int = 10):
    out = []
    for m in UTF16LE_RE.finditer(data):
        out.append(m.group().decode('utf-16le', errors='ignore'))
        if limit and len(out) >= limit:
            break
    return out


def try_zlib(data: bytes, offset: int, max_out: int):
    try:
        out = zlib.decompress(data[offset:], wbits=zlib.MAX_WBITS, bufsize=max_out)
        return out
    except Exception:
        return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Scan RWZ for embedded zlib streams')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--max-out', type=int, default=2_000_000, help='Max decompressed bytes')
    ap.add_argument('--min-out', type=int, default=64, help='Min decompressed bytes to report')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    ap.add_argument('--dump-dir', type=Path, help='Dump decompressed streams here')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()
    hits = []
    for i in range(len(data) - 2):
        cmf = data[i]
        flg = data[i + 1]
        if not is_zlib_header(cmf, flg):
            continue
        out = try_zlib(data, i, args.max_out)
        if out and len(out) >= args.min_out:
            hits.append((i, out))

    lines = []
    lines.append(f'# Zlib Scan Report: {args.path.name}')
    lines.append('')
    lines.append(f'- Candidates found: {len(hits)}')
    lines.append('')

    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)

    for idx, (offset, out) in enumerate(hits, start=1):
        ascii_samples = extract_ascii(out, limit=10)
        utf16_samples = extract_utf16le(out, limit=10)
        lines.append(f'## Stream {idx}')
        lines.append(f'- Offset: 0x{offset:08x}')
        lines.append(f'- Decompressed size: {len(out)}')
        if ascii_samples:
            lines.append('- ASCII samples:')
            for s in ascii_samples:
                lines.append(f'  - {s}')
        if utf16_samples:
            lines.append('- UTF-16LE samples:')
            for s in utf16_samples:
                lines.append(f'  - {s}')
        lines.append('')

        if args.dump_dir:
            out_path = args.dump_dir / f'stream_{idx:02d}_0x{offset:08x}.bin'
            out_path.write_bytes(out)

    report = '\n'.join(lines) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding='utf-8')
    else:
        print(report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
