#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from pathlib import Path


RULE_ROW_RE = re.compile(r'^\|\s*(\d+)\s*\|\s*(.+?)\s*\|\s*(0x[0-9a-fA-F]+)\s*\|\s*(0x[0-9a-fA-F]+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|')
GAP_HEADER_RE = re.compile(r'^##\s+Gap\s+(\d+)')
GAP_RANGE_RE = re.compile(r'^- Range:\s+(0x[0-9a-fA-F]+)\s+\.\.\s+(0x[0-9a-fA-F]+)\s+\(size\s+(\d+)\)')
GAP_ENT_RE = re.compile(r'^- Entropy:\s+([0-9.]+)')
GAP_ZERO_RE = re.compile(r'^- Zero ratio:\s+([0-9.]+)')
GAP_PRINT_RE = re.compile(r'^- Printable ASCII ratio:\s+([0-9.]+)')
GAP_UTF16_RE = re.compile(r'^- UTF-16-like ratio:\s+([0-9.]+)')
COMP_CAND_RE = re.compile(r'^- Candidate\s+\d+:\s+([a-zA-Z0-9_]+)\s+at\s+(0x[0-9a-fA-F]+),\s+size\s+(\d+),\s+printable\s+([0-9.]+)')


def read_rules_index(md_path: Path):
    rules = []
    if not md_path.exists():
        return rules
    in_table = False
    for line in md_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.startswith('## Rules (Index)'):
            in_table = True
            continue
        if in_table:
            if not line.startswith('|'):
                if line.strip() == '':
                    break
                continue
            m = RULE_ROW_RE.match(line)
            if not m:
                continue
            idx, title, start, end, strings, emails = m.groups()
            rules.append({
                'rule_index': idx,
                'title': title.strip(),
                'rule_start': start,
                'rule_end': end,
                'strings': strings,
                'email_count': emails,
            })
    return rules


def read_rules_csv(csv_path: Path):
    rules = {}
    if not csv_path.exists():
        return rules
    with csv_path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            title = row.get('title', '').strip()
            rules[title] = {
                'emails': row.get('emails', ''),
                'keywords': row.get('keywords', ''),
            }
    return rules


def read_gap_report(md_path: Path):
    gaps = []
    if not md_path.exists():
        return gaps
    cur = None
    for line in md_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        m = GAP_HEADER_RE.match(line)
        if m:
            if cur:
                gaps.append(cur)
            cur = {'gap_index': m.group(1)}
            continue
        if not cur:
            continue
        m = GAP_RANGE_RE.match(line)
        if m:
            cur['gap_start'], cur['gap_end'], cur['gap_size'] = m.groups()
            continue
        m = GAP_ENT_RE.match(line)
        if m:
            cur['entropy'] = m.group(1)
            continue
        m = GAP_ZERO_RE.match(line)
        if m:
            cur['zero_ratio'] = m.group(1)
            continue
        m = GAP_PRINT_RE.match(line)
        if m:
            cur['printable_ratio'] = m.group(1)
            continue
        m = GAP_UTF16_RE.match(line)
        if m:
            cur['utf16_ratio'] = m.group(1)
            continue
    if cur:
        gaps.append(cur)
    return gaps


def read_compress_report(md_path: Path):
    rows = []
    if not md_path.exists():
        return rows
    cur_gap = None
    for line in md_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        m = GAP_HEADER_RE.match(line)
        if m:
            cur_gap = m.group(1)
            continue
        if cur_gap:
            m = COMP_CAND_RE.match(line)
            if m:
                algo, off, size, printable = m.groups()
                rows.append({
                    'gap_index': cur_gap,
                    'compress_algo': algo,
                    'compress_offset': off,
                    'compress_size': size,
                    'compress_printable': printable,
                })
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Create unified CSV report from multiple outputs')
    ap.add_argument('--rules-csv', type=Path, default=Path('out_rules.csv'))
    ap.add_argument('--report-md', type=Path, default=Path('out_report_deep.md'))
    ap.add_argument('--gap-md', type=Path, default=Path('out_gap_report.md'))
    ap.add_argument('--compress-md', type=Path, default=Path('out_compress_report.md'))
    ap.add_argument('--out', type=Path, default=Path('out_unified.csv'))
    args = ap.parse_args(argv)

    rules_index = read_rules_index(args.report_md)
    rules_csv = read_rules_csv(args.rules_csv)
    gaps = read_gap_report(args.gap_md)
    comp = read_compress_report(args.compress_md)

    rows = []

    # Rules
    for r in rules_index:
        extra = rules_csv.get(r['title'], {})
        rows.append({
            'type': 'rule',
            'rule_index': r.get('rule_index', ''),
            'title': r.get('title', ''),
            'emails': extra.get('emails', ''),
            'keywords': extra.get('keywords', ''),
            'rule_start': r.get('rule_start', ''),
            'rule_end': r.get('rule_end', ''),
            'strings': r.get('strings', ''),
            'email_count': r.get('email_count', ''),
            'gap_index': '',
            'gap_start': '',
            'gap_end': '',
            'gap_size': '',
            'entropy': '',
            'zero_ratio': '',
            'printable_ratio': '',
            'utf16_ratio': '',
            'compress_algo': '',
            'compress_offset': '',
            'compress_size': '',
            'compress_printable': '',
            'source': 'out_report_deep.md + out_rules.csv',
        })

    # Gaps
    for g in gaps:
        rows.append({
            'type': 'gap',
            'rule_index': '',
            'title': '',
            'emails': '',
            'keywords': '',
            'rule_start': '',
            'rule_end': '',
            'strings': '',
            'email_count': '',
            'gap_index': g.get('gap_index', ''),
            'gap_start': g.get('gap_start', ''),
            'gap_end': g.get('gap_end', ''),
            'gap_size': g.get('gap_size', ''),
            'entropy': g.get('entropy', ''),
            'zero_ratio': g.get('zero_ratio', ''),
            'printable_ratio': g.get('printable_ratio', ''),
            'utf16_ratio': g.get('utf16_ratio', ''),
            'compress_algo': '',
            'compress_offset': '',
            'compress_size': '',
            'compress_printable': '',
            'source': 'out_gap_report.md',
        })

    # Compression candidates
    for c in comp:
        rows.append({
            'type': 'compress',
            'rule_index': '',
            'title': '',
            'emails': '',
            'keywords': '',
            'rule_start': '',
            'rule_end': '',
            'strings': '',
            'email_count': '',
            'gap_index': c.get('gap_index', ''),
            'gap_start': '',
            'gap_end': '',
            'gap_size': '',
            'entropy': '',
            'zero_ratio': '',
            'printable_ratio': '',
            'utf16_ratio': '',
            'compress_algo': c.get('compress_algo', ''),
            'compress_offset': c.get('compress_offset', ''),
            'compress_size': c.get('compress_size', ''),
            'compress_printable': c.get('compress_printable', ''),
            'source': 'out_compress_report.md',
        })

    header = [
        'type',
        'rule_index',
        'title',
        'emails',
        'keywords',
        'rule_start',
        'rule_end',
        'strings',
        'email_count',
        'gap_index',
        'gap_start',
        'gap_end',
        'gap_size',
        'entropy',
        'zero_ratio',
        'printable_ratio',
        'utf16_ratio',
        'compress_algo',
        'compress_offset',
        'compress_size',
        'compress_printable',
        'source',
    ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
