#!/usr/bin/env python3
"""
RWZ Gap Detail Analyzer
=======================
Author: GitHub Copilot (Session: 2026-02-03, Phase 2)
Purpose: Deep analysis of gaps between data structures

This tool performs:
1. Identification and measurement of all gaps
2. Entropy analysis per gap
3. Pattern detection within gaps
4. Gap classification by characteristics
5. Sample extraction for manual review
"""

import argparse
import json
import struct
import sys
import math
from pathlib import Path
from typing import List, Dict, Tuple, Optional


def find_all_gaps(data: bytes, min_gap_size: int = 4) -> List[Dict]:
    """Find all gaps (null or sparse regions) in the data."""
    gaps = []
    in_gap = False
    gap_start = 0
    
    for offset in range(len(data)):
        byte_val = data[offset]
        
        # Consider it a gap if mostly null
        is_sparse = byte_val == 0
        
        if is_sparse and not in_gap:
            gap_start = offset
            in_gap = True
        elif not is_sparse and in_gap:
            gap_size = offset - gap_start
            if gap_size >= min_gap_size:
                gaps.append({
                    'start': gap_start,
                    'start_hex': f'0x{gap_start:08x}',
                    'end': offset,
                    'end_hex': f'0x{offset:08x}',
                    'size': gap_size,
                })
            in_gap = False
    
    # Handle gap at end
    if in_gap:
        gap_size = len(data) - gap_start
        if gap_size >= min_gap_size:
            gaps.append({
                'start': gap_start,
                'start_hex': f'0x{gap_start:08x}',
                'end': len(data),
                'end_hex': f'0x{len(data):08x}',
                'size': gap_size,
            })
    
    return sorted(gaps, key=lambda x: -x['size'])


def analyze_gap_content(data: bytes, gap: Dict) -> Dict:
    """Detailed analysis of a gap's content."""
    start = gap['start']
    end = gap['end']
    region = data[start:end]
    
    analysis = {
        'start': gap['start'],
        'size': gap['size'],
        'byte_distribution': {},
        'entropy': 0.0,
        'null_ratio': 0.0,
        'patterns': [],
    }
    
    # Byte distribution
    counts = [0] * 256
    for b in region:
        counts[b] += 1
    
    analysis['byte_distribution'] = {
        'null_bytes': counts[0],
        'common_bytes': sorted(
            [(b, counts[b]) for b in range(256) if counts[b] > 0],
            key=lambda x: -x[1]
        )[:10]
    }
    
    # Entropy
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / len(region)
            entropy -= p * math.log2(p)
    analysis['entropy'] = entropy
    analysis['null_ratio'] = counts[0] / len(region)
    
    # Look for patterns
    # Repeating bytes
    if len(region) > 1:
        for byte_val in [b for b in range(256) if counts[b] > len(region) * 0.1]:
            analysis['patterns'].append(f"Byte 0x{byte_val:02x} repeats {counts[byte_val]} times")
    
    # Look for strings
    strings = _extract_strings_from_gap(region)
    if strings:
        analysis['patterns'].append(f"Found {len(strings)} embedded strings")
        analysis['strings'] = strings[:5]
    
    # Look for repeating sequences
    repeat_patterns = _find_repeating_sequences(region)
    if repeat_patterns:
        analysis['patterns'].extend(repeat_patterns[:3])
    
    return analysis


def _extract_strings_from_gap(region: bytes) -> List[str]:
    """Extract printable strings from a gap."""
    strings = []
    current = []
    
    for b in region:
        if 32 <= b <= 126:  # Printable ASCII
            current.append(chr(b))
        else:
            if current and len(''.join(current)) > 3:
                strings.append(''.join(current))
            current = []
    
    if current and len(''.join(current)) > 3:
        strings.append(''.join(current))
    
    return strings


def _find_repeating_sequences(data: bytes, min_length: int = 4, max_length: int = 16) -> List[str]:
    """Find repeating byte sequences."""
    patterns = []
    
    for length in range(min_length, min(max_length + 1, len(data) // 2)):
        for start in range(len(data) - length * 2):
            pattern = data[start:start+length]
            count = 0
            pos = start
            
            while pos + length <= len(data):
                if data[pos:pos+length] == pattern:
                    count += 1
                    pos += length
                else:
                    pos += 1
            
            if count >= 3:
                patterns.append(f"Sequence repeats {count}x: {pattern[:8].hex()}...")
                break
    
    return patterns


def classify_gaps(gaps: List[Dict], data: bytes) -> Dict:
    """Classify gaps by their characteristics."""
    classification = {
        'pure_null': [],
        'sparse': [],
        'structured': [],
        'unknown': [],
    }
    
    for gap in gaps:
        start = gap['start']
        end = gap['end']
        region = data[start:end]
        
        null_ratio = region.count(0) / len(region)
        entropy = 0.0
        
        counts = [0] * 256
        for b in region:
            counts[b] += 1
        
        for count in counts:
            if count > 0:
                p = count / len(region)
                entropy -= p * math.log2(p)
        
        if null_ratio > 0.95:
            classification['pure_null'].append({
                'start': start,
                'size': end - start,
            })
        elif null_ratio > 0.5:
            classification['sparse'].append({
                'start': start,
                'size': end - start,
                'entropy': entropy,
            })
        elif entropy > 3.0:
            classification['structured'].append({
                'start': start,
                'size': end - start,
                'entropy': entropy,
            })
        else:
            classification['unknown'].append({
                'start': start,
                'size': end - start,
                'entropy': entropy,
            })
    
    return classification


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Analyze gaps in RWZ file'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown file')
    parser.add_argument('--min-size', type=int, default=10,
                       help='Minimum gap size to analyze')
    parser.add_argument('--max-gaps', type=int, default=30,
                       help='Maximum gaps to analyze in detail')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Find all gaps
    print(f"  - Finding gaps (min size: {args.min_size})...", file=sys.stderr)
    all_gaps = find_all_gaps(data, args.min_size)
    print(f"    Found {len(all_gaps)} gaps", file=sys.stderr)
    
    # Analyze top gaps
    print(f"  - Analyzing top {min(args.max_gaps, len(all_gaps))} gaps...", file=sys.stderr)
    analyzed_gaps = []
    for gap in all_gaps[:args.max_gaps]:
        analysis = analyze_gap_content(data, gap)
        gap_with_analysis = {**gap, **analysis}
        analyzed_gaps.append(gap_with_analysis)
    
    # Classify gaps
    print("  - Classifying gaps...", file=sys.stderr)
    classification = classify_gaps(all_gaps, data)
    
    results = {
        'file': str(rwz_path),
        'total_gaps': len(all_gaps),
        'analyzed_gaps': len(analyzed_gaps),
        'total_gap_size': sum(g['size'] for g in all_gaps),
        'gap_percentage': (sum(g['size'] for g in all_gaps) / len(data)) * 100,
        'classification': {
            'pure_null': len(classification['pure_null']),
            'sparse': len(classification['sparse']),
            'structured': len(classification['structured']),
            'unknown': len(classification['unknown']),
        },
        'top_gaps': analyzed_gaps[:20],
    }
    
    # Output JSON
    if args.out:
        out_path = Path(args.out)
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON output: {out_path}", file=sys.stderr)
    
    # Output Markdown
    if args.out_md:
        md_path = Path(args.out_md)
        with open(md_path, 'w') as f:
            f.write(f"# RWZ Gap Analysis\n\n")
            
            f.write("## Summary\n")
            f.write(f"- Total gaps: {len(all_gaps)}\n")
            f.write(f"- Analyzed: {len(analyzed_gaps)}\n")
            f.write(f"- Total gap size: {sum(g['size'] for g in all_gaps)} bytes ")
            f.write(f"({results['gap_percentage']:.1f}% of file)\n\n")
            
            # Classification
            f.write("## Gap Classification\n")
            f.write(f"- Pure null: {len(classification['pure_null'])}\n")
            f.write(f"- Sparse: {len(classification['sparse'])}\n")
            f.write(f"- Structured: {len(classification['structured'])}\n")
            f.write(f"- Unknown: {len(classification['unknown'])}\n\n")
            
            # Top gaps
            f.write(f"## Top 10 Gaps\n\n")
            for i, gap in enumerate(all_gaps[:10], 1):
                f.write(f"### Gap {i}\n")
                f.write(f"- Location: {gap['start_hex']}..{gap['end_hex']}\n")
                f.write(f"- Size: {gap['size']} bytes\n")
                if i <= len(analyzed_gaps):
                    analyzed = analyzed_gaps[i-1]
                    f.write(f"- Null ratio: {analyzed.get('null_ratio', 0):.1%}\n")
                    f.write(f"- Entropy: {analyzed.get('entropy', 0):.2f}\n")
                    if analyzed.get('patterns'):
                        f.write(f"- Patterns: {', '.join(analyzed['patterns'][:2])}\n")
                f.write("\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Total gaps: {len(all_gaps)}")
    print(f"Total gap size: {sum(g['size'] for g in all_gaps)} bytes ({results['gap_percentage']:.1f}%)")
    print(f"Classification: pure_null={len(classification['pure_null'])}, sparse={len(classification['sparse'])}, structured={len(classification['structured'])}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
