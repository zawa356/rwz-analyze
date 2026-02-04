#!/usr/bin/env python3
import argparse
import csv
import json
import re
import sys
from pathlib import Path

UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
NORMALIZE_RE = re.compile(r'[\W_]+', re.UNICODE)
OCR_RULE_RE = re.compile(r'\[[^\]]+\][^\s]*')
OCR_QUOTE_RE = re.compile(r'[\"“”\'‘’]([^\"“”\'‘’]{2,})[\"“”\'‘’]')
TRANSPORT_TOKENS = {'SMTP', 'MSMTP', 'PSMTP'}


def extract_utf16_strings(data: bytes, min_chars: int):
    for m in UTF16_RE.finditer(data):
        s = m.group().decode('utf-16le', errors='ignore')
        if len(s) >= min_chars:
            yield (m.start(), s)


def extract_ascii_strings(data: bytes, min_chars: int):
    for m in ASCII_RE.finditer(data):
        s = m.group().decode('ascii', errors='ignore')
        if len(s) >= min_chars:
            yield (m.start(), s)


def is_rule_header(s: str) -> bool:
    if not s.startswith('['):
        return False
    close = s.find(']')
    return close != -1 and close < 80


def normalize_email(raw: str, known: set[str]) -> str:
    # Some strings appear with a single leading uppercase letter prefix.
    if len(raw) > 2 and raw[0].isupper():
        tail = raw[1:]
        if tail.lower() in known:
            return tail.lower()
    if EMAIL_RE.fullmatch(raw):
        return raw.lower()
    return raw.lower()


def summarize_rule(title, entries, include_strings, max_keywords):
    strings = [s for _, s in entries]

    raw_emails = set()
    for s in strings:
        for e in EMAIL_RE.findall(s):
            raw_emails.add(e)
    known = {e.lower() for e in raw_emails}
    emails = sorted({normalize_email(e, known) for e in raw_emails})

    keywords = []
    seen = set()
    for s in strings:
        s = s.strip()
        if not s:
            continue
        if s == title:
            continue
        if s.upper() in TRANSPORT_TOKENS:
            continue
        if EMAIL_RE.fullmatch(s):
            continue
        if len(s) > 1 and s[0].isupper() and EMAIL_RE.fullmatch(s[1:]):
            continue
        if len(s) < 3:
            continue
        if s in seen:
            continue
        seen.add(s)
        keywords.append(s)
        if max_keywords and len(keywords) >= max_keywords:
            break

    summary = {
        'title': title,
        'emails': emails,
        'keywords': keywords,
    }
    if include_strings:
        summary['strings'] = strings
    return summary


def normalize_token(s: str) -> str:
    return NORMALIZE_RE.sub('', s).lower()


def load_extra_strings(path: Path) -> list[str]:
    extra = []
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        s = line.strip()
        if s:
            extra.append(s)
    return extra


def load_extra_from_ocr(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
    extra = []
    if isinstance(payload, dict) and 'images' in payload:
        for img in payload.get('images', []):
            for key in ('tokens', 'lines'):
                for s in img.get(key, []):
                    if isinstance(s, str) and s.strip():
                        extra.append(s.strip())
            for e in img.get('emails', []):
                if isinstance(e, str) and e.strip():
                    extra.append(e.strip())
    return extra


def extract_rule_name(line: str) -> str | None:
    m = OCR_RULE_RE.search(line)
    if m:
        return m.group(0)
    m = re.search(r'\[[^\]]+\]', line)
    if m:
        return m.group(0)
    return None


def extract_folder(line: str) -> str | None:
    if 'フォルダー' not in line or '移動' not in line:
        return None
    m = re.search(r'フォルダー\s*[「\'"“”‘’]?(.+?)\s*(?:にメッセージを移動|にメッセージを移動する|へ移動|に移動|$)', line)
    if not m:
        return None
    folder = m.group(1).strip(" '\"“”‘’")
    return folder if folder else None


def parse_ocr_rules(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
    lines: list[str] = []
    if isinstance(payload, dict) and 'images' in payload:
        for img in payload.get('images', []):
            lines.extend(img.get('lines', []))
    rules = []
    current = None
    for line in lines:
        name = extract_rule_name(line)
        if name:
            if current:
                rules.append(current)
            current = {
                'name': name,
                'lines': [],
                'emails': [],
                'from_emails': [],
                'to_emails': [],
                'folders': [],
                'subject_keywords': [],
                'stop_processing': False,
            }
        if current is None:
            continue
        current['lines'].append(line)
        emails = EMAIL_RE.findall(line)
        if emails:
            current['emails'].extend(emails)
            if 'から受信' in line or '差出人' in line or '送信者' in line:
                current['from_emails'].extend(emails)
            if '送信された' in line or '宛先' in line or 'に送信' in line:
                current['to_emails'].extend(emails)
        folder = extract_folder(line)
        if folder:
            current['folders'].append(folder)
        for q in OCR_QUOTE_RE.findall(line):
            q = q.strip()
            if q:
                current['subject_keywords'].append(q)
        if '処理を停止' in line:
            current['stop_processing'] = True
    if current:
        rules.append(current)

    for r in rules:
        def dedup(seq):
            seen = set()
            out = []
            for s in seq:
                if s in seen:
                    continue
                seen.add(s)
                out.append(s)
            return out
        for key in ('emails', 'from_emails', 'to_emails', 'folders', 'subject_keywords'):
            r[key] = dedup([s.strip() for s in r[key] if s.strip()])
    return rules


def match_ocr_rules(rules: list[dict], ocr_rules: list[dict]) -> tuple[list[dict], list[dict]]:
    def norm(s: str) -> str:
        return normalize_token(s)

    ocr_norm = [norm(r['name']) for r in ocr_rules]
    unmatched = set(range(len(ocr_rules)))

    for rule in rules:
        title = rule.get('title', '')
        tnorm = norm(title)
        best_idx = None
        best_score = 0
        for i, ocr in enumerate(ocr_rules):
            score = 0
            onorm = ocr_norm[i]
            if tnorm and (tnorm == onorm or tnorm in onorm or onorm in tnorm):
                score += 10
            ocr_emails = set(ocr.get('emails', []))
            rule_emails = set(rule.get('emails', []))
            score += 2 * len(ocr_emails & rule_emails)
            ocr_keywords = set(ocr.get('subject_keywords', []))
            rule_keywords = set(rule.get('keywords', []))
            score += len({norm(s) for s in ocr_keywords} & {norm(s) for s in rule_keywords})
            if score > best_score:
                best_score = score
                best_idx = i
        if best_idx is not None and best_score > 0:
            rule['ocr'] = ocr_rules[best_idx]
            rule['ocr_match_score'] = best_score
            if best_idx in unmatched:
                unmatched.remove(best_idx)

    return rules, [ocr_rules[i] for i in sorted(unmatched)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='Analyze Outlook .rwz rule export files')
    parser.add_argument('path', help='Path to .rwz file')
    parser.add_argument('--min-chars', type=int, default=4, help='Minimum characters for extracted strings')
    parser.add_argument('--include-ascii', action='store_true', help='Also extract ASCII strings (default: UTF-16LE only)')
    parser.add_argument('--dump-strings', action='store_true', help='Dump extracted strings with offsets (TSV)')
    parser.add_argument('--json', action='store_true', help='Output JSON summary (compat; use --format json)')
    parser.add_argument('--include-strings', action='store_true', help='Include raw strings per rule in JSON')
    parser.add_argument('--max-keywords', type=int, default=0, help='Limit keywords per rule (0 = no limit)')
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'yaml'], default='text',
                        help='Output format when not using --dump-strings')
    parser.add_argument('--out', type=Path, help='Write output to a file (UTF-8)')
    parser.add_argument('--extra-strings', type=Path,
                        help='Path to newline-separated strings to help matching (e.g., OCR output)')
    parser.add_argument('--extra-ocr-json', type=Path,
                        help='Path to OCR JSON created by rwz_ocr.py (uses tokens/lines/emails)')
    parser.add_argument('--merge-ocr-json', type=Path,
                        help='Path to OCR JSON created by rwz_ocr.py (use only for matching; not output)')
    args = parser.parse_args(argv)

    path = Path(args.path)
    data = path.read_bytes()

    entries = list(extract_utf16_strings(data, args.min_chars))
    if args.include_ascii:
        entries.extend(extract_ascii_strings(data, args.min_chars))
    entries.sort(key=lambda x: x[0])

    if args.dump_strings:
        out = sys.stdout
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            out = args.out.open('w', encoding='utf-8', newline='')
        try:
            for offset, s in entries:
                print(f"{offset}\t{s}", file=out)
        finally:
            if out is not sys.stdout:
                out.close()
        return 0

    rules = []
    preamble = []
    current = None

    for offset, s in entries:
        if is_rule_header(s):
            if current is not None:
                rules.append(current)
            current = {'title': s, 'entries': [(offset, s)]}
            continue
        if current is None:
            preamble.append((offset, s))
        else:
            current['entries'].append((offset, s))

    if current is not None:
        rules.append(current)

    max_keywords = args.max_keywords if args.max_keywords > 0 else None
    extra_tokens: list[str] = []
    if args.extra_strings:
        extra_tokens.extend(load_extra_strings(args.extra_strings))
    if args.extra_ocr_json:
        extra_tokens.extend(load_extra_from_ocr(args.extra_ocr_json))
    summary = {
        'file': str(path),
        'rule_count': len(rules),
        'rules': [
            summarize_rule(r['title'], r['entries'], args.include_strings, max_keywords)
            for r in rules
        ],
    }
    if preamble:
        summary['preamble'] = [s for _, s in preamble]

    if extra_tokens:
        norm_to_rules: dict[str, set[int]] = {}
        for idx, r in enumerate(summary['rules']):
            for s in r.get('keywords', []) + r.get('emails', []) + [r.get('title', '')]:
                n = normalize_token(s)
                if not n:
                    continue
                norm_to_rules.setdefault(n, set()).add(idx)

        unmatched = []
        for s in extra_tokens:
            n = normalize_token(s)
            if not n:
                continue
            if n in norm_to_rules:
                for rule_idx in sorted(norm_to_rules[n]):
                    summary['rules'][rule_idx].setdefault('extra_matches', []).append(s)
            else:
                unmatched.append(s)
        if unmatched:
            summary['extra_unmatched'] = unmatched

    if args.merge_ocr_json:
        ocr_rules = parse_ocr_rules(args.merge_ocr_json)
        summary['rules'], _ = match_ocr_rules(summary['rules'], ocr_rules)
        # Do not emit OCR-derived data in output; keep for internal matching only.
        for rule in summary['rules']:
            rule.pop('ocr', None)
            rule.pop('ocr_match_score', None)

    out_format = 'json' if args.json and args.format == 'text' else args.format
    if out_format == 'json':
        payload = json.dumps(summary, ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding='utf-8')
        else:
            print(payload)
        return 0

    if out_format == 'csv':
        out = sys.stdout
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            out = args.out.open('w', encoding='utf-8', newline='')
        try:
            writer = csv.writer(out)
            writer.writerow(['title', 'emails', 'keywords'])
            for rule in summary['rules']:
                writer.writerow([
                    rule['title'],
                    '\n'.join(rule['emails']),
                    '\n'.join(rule['keywords']),
                ])
        finally:
            if out is not sys.stdout:
                out.close()
        return 0

    if out_format == 'yaml':
        try:
            import yaml  # type: ignore
        except Exception:
            print('YAML output requires PyYAML. Install it or use --format json/csv/text.', file=sys.stderr)
            return 2
        payload = yaml.safe_dump(summary, allow_unicode=True, sort_keys=False)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding='utf-8')
        else:
            print(payload)
        return 0

    out = sys.stdout
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        out = args.out.open('w', encoding='utf-8', newline='')
    try:
        print(f"File: {path}", file=out)
        print(f"Rules: {len(rules)}", file=out)
        for idx, rule in enumerate(summary['rules'], start=1):
            print(f"\n[{idx}] {rule['title']}", file=out)
            if rule['emails']:
                print("  emails:", file=out)
                for e in rule['emails']:
                    print(f"    - {e}", file=out)
            if rule['keywords']:
                print("  keywords:", file=out)
                for k in rule['keywords']:
                    print(f"    - {k}", file=out)
    finally:
        if out is not sys.stdout:
            out.close()

    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
