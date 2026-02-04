#!/usr/bin/env python3
import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import List, Tuple


UTF16LE_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
UTF16BE_RE = re.compile(rb'(?:\x00[\x20-\x7e]){4,}')
ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def scan_strings(data: bytes, min_chars: int, include_ascii: bool, include_utf16be: bool):
    entries = []

    for m in UTF16LE_RE.finditer(data):
        s = m.group().decode('utf-16le', errors='ignore')
        if len(s) >= min_chars:
            entries.append({'offset': m.start(), 'kind': 'utf16le', 'text': s, 'byte_len': len(m.group())})

    if include_utf16be:
        for m in UTF16BE_RE.finditer(data):
            s = m.group().decode('utf-16be', errors='ignore')
            if len(s) >= min_chars:
                entries.append({'offset': m.start(), 'kind': 'utf16be', 'text': s, 'byte_len': len(m.group())})

    if include_ascii:
        for m in ASCII_RE.finditer(data):
            s = m.group().decode('ascii', errors='ignore')
            if len(s) >= min_chars:
                entries.append({'offset': m.start(), 'kind': 'ascii', 'text': s, 'byte_len': len(m.group())})

    entries.sort(key=lambda x: (x['offset'], x['kind']))
    return entries


def is_rule_header(s: str) -> bool:
    if not s.startswith('['):
        return False
    close = s.find(']')
    return close != -1 and close < 80


def merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges.sort()
    merged = [ranges[0]]
    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def hex_preview(data: bytes, start: int, length: int) -> str:
    chunk = data[start:start + length]
    return ' '.join(f'{b:02x}' for b in chunk)


def ascii_preview(data: bytes, start: int, length: int) -> str:
    chunk = data[start:start + length]
    out = []
    for b in chunk:
        if 0x20 <= b <= 0x7e:
            out.append(chr(b))
        else:
            out.append('.')
    return ''.join(out)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            # log2(p) = ln(p) / ln(2)
            entropy -= p * (math.log(p) / math.log(2))
    return entropy


def build_rules(entries):
    rules = []
    preamble = []
    current = None

    for e in entries:
        s = e['text']
        if is_rule_header(s):
            if current is not None:
                rules.append(current)
            current = {'title': s, 'entries': [e]}
            continue
        if current is None:
            preamble.append(e)
        else:
            current['entries'].append(e)

    if current is not None:
        rules.append(current)
    return rules, preamble


def summarize_rule(rule):
    emails = set()
    for e in rule['entries']:
        emails.update(EMAIL_RE.findall(e['text']))
    return {
        'title': rule['title'],
        'start': rule['entries'][0]['offset'],
        'end': rule['entries'][-1]['offset'],
        'strings': len(rule['entries']),
        'emails': sorted(emails),
    }


def coverage_for_kind(entries, kind: str, data_len: int) -> tuple[int, float]:
    ranges = [(e['offset'], e['offset'] + e['byte_len']) for e in entries if e['kind'] == kind]
    merged = merge_ranges(ranges)
    covered = sum(end - start for start, end in merged)
    pct = (covered / data_len) * 100 if data_len else 0.0
    return covered, pct


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Deep RWZ analysis report (human readable)')
    ap.add_argument('path', type=Path, help='Path to .rwz file')
    ap.add_argument('--min-chars', type=int, default=4, help='Minimum characters for extracted strings')
    ap.add_argument('--include-ascii', action='store_true', help='Also extract ASCII strings')
    ap.add_argument('--include-utf16be', action='store_true', help='Also extract UTF-16BE strings')
    ap.add_argument('--hex-bytes', type=int, default=0, help='Hex preview bytes for rule range (0 = off)')
    ap.add_argument('--gap-bytes', type=int, default=96, help='Hex/ASCII preview bytes for gaps')
    ap.add_argument('--gap-limit', type=int, default=50, help='Number of largest gaps to show')
    ap.add_argument('--out', type=Path, help='Write report to file (UTF-8)')
    args = ap.parse_args(argv)

    data = args.path.read_bytes()
    entries = scan_strings(data, args.min_chars, args.include_ascii, args.include_utf16be)
    rules, preamble = build_rules(entries)

    # coverage
    ranges = [(e['offset'], e['offset'] + e['byte_len']) for e in entries]
    merged = merge_ranges(ranges)
    covered = sum(end - start for start, end in merged)
    coverage = (covered / len(data)) * 100 if data else 0.0

    # gaps (largest)
    gaps = []
    last = 0
    for start, end in merged:
        if start > last:
            gaps.append((last, start))
        last = max(last, end)
    if last < len(data):
        gaps.append((last, len(data)))
    gaps.sort(key=lambda x: x[1] - x[0], reverse=True)

    out_lines = []
    out_lines.append(f'# RWZ Report: {args.path.name}')
    out_lines.append('')
    out_lines.append('## File Summary')
    out_lines.append(f'- Size: {len(data)} bytes')
    out_lines.append(f'- Strings: {len(entries)}')
    out_lines.append(f'- Rules: {len(rules)}')
    out_lines.append(f'- Coverage by extracted strings: {coverage:.2f}%')
    if entries:
        cov_le, pct_le = coverage_for_kind(entries, 'utf16le', len(data))
        cov_be, pct_be = coverage_for_kind(entries, 'utf16be', len(data))
        cov_ascii, pct_ascii = coverage_for_kind(entries, 'ascii', len(data))
        out_lines.append(f'- Coverage utf16le: {cov_le} bytes ({pct_le:.2f}%)')
        if args.include_utf16be:
            out_lines.append(f'- Coverage utf16be: {cov_be} bytes ({pct_be:.2f}%)')
        if args.include_ascii:
            out_lines.append(f'- Coverage ascii: {cov_ascii} bytes ({pct_ascii:.2f}%)')
    out_lines.append('')

    out_lines.append('## Rules (Index)')
    out_lines.append('| # | Title | Start | End | Strings | Emails |')
    out_lines.append('|---|-------|-------|-----|---------|--------|')
    for idx, r in enumerate(rules, start=1):
        s = summarize_rule(r)
        out_lines.append(f"| {idx} | {s['title']} | 0x{s['start']:08x} | 0x{s['end']:08x} | {s['strings']} | {len(s['emails'])} |")
    out_lines.append('')

    out_lines.append('## Largest Gaps (Bytes not covered by strings)')
    out_lines.append('| # | Start | End | Size |')
    out_lines.append('|---|-------|-----|------|')
    for i, (start, end) in enumerate(gaps[: args.gap_limit], start=1):
        out_lines.append(f"| {i} | 0x{start:08x} | 0x{end:08x} | {end-start} |")
    out_lines.append('')

    if gaps:
        out_lines.append('## Gap Previews')
        for i, (start, end) in enumerate(gaps[: args.gap_limit], start=1):
            size = end - start
            length = min(args.gap_bytes, size)
            head_hex = hex_preview(data, start, length)
            head_ascii = ascii_preview(data, start, length)
            tail_start = max(start, end - length)
            tail_hex = hex_preview(data, tail_start, length)
            tail_ascii = ascii_preview(data, tail_start, length)
            entropy = shannon_entropy(data[start:end])
            out_lines.append(f'### Gap {i}')
            out_lines.append(f'- Range: 0x{start:08x} .. 0x{end:08x} (size {size})')
            out_lines.append(f'- Entropy: {entropy:.3f}')
            out_lines.append(f'- Head Hex ({length} bytes): `{head_hex}`')
            out_lines.append(f'- Head ASCII: `{head_ascii}`')
            out_lines.append(f'- Tail Hex ({length} bytes): `{tail_hex}`')
            out_lines.append(f'- Tail ASCII: `{tail_ascii}`')
            out_lines.append('')

    out_lines.append('## Rule Details')
    for idx, r in enumerate(rules, start=1):
        out_lines.append(f'### [{idx}] {r["title"]}')
        out_lines.append(f'- Range: 0x{r["entries"][0]["offset"]:08x} .. 0x{r["entries"][-1]["offset"]:08x}')
        if args.hex_bytes > 0:
            start = r['entries'][0]['offset']
            end = min(len(data), r['entries'][-1]['offset'] + r['entries'][-1]['byte_len'])
            out_lines.append(f'- Hex (head {args.hex_bytes} bytes): `{hex_preview(data, start, args.hex_bytes)}`')
            tail_start = max(start, end - args.hex_bytes)
            out_lines.append(f'- Hex (tail {args.hex_bytes} bytes): `{hex_preview(data, tail_start, args.hex_bytes)}`')
        out_lines.append('')
        out_lines.append('| Offset | Kind | Text |')
        out_lines.append('|--------|------|------|')
        for e in r['entries']:
            text = e['text'].replace('|', '\\|')
            out_lines.append(f"| 0x{e['offset']:08x} | {e['kind']} | {text} |")
        out_lines.append('')

    if preamble:
        out_lines.append('## Preamble (Before first rule)')
        out_lines.append('| Offset | Kind | Text |')
        out_lines.append('|--------|------|------|')
        for e in preamble:
            text = e['text'].replace('|', '\\|')
            out_lines.append(f"| 0x{e['offset']:08x} | {e['kind']} | {text} |")
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
