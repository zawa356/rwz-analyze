#!/usr/bin/env python3
"""
RWZ Binary Structure Analyzer
==============================
Author: GitHub Copilot (Session: 2026-02-03)
Purpose: Deep binary structure analysis of RWZ files

This tool performs multi-level analysis of RWZ files:
1. Byte frequency distribution (entropy profiling)
2. Block structure detection (patterns, offsets)
3. Null byte distribution analysis
4. Repeating pattern detection
5. Probable structure sections (header, body, footer)
6. DWORD/QWORD alignment analysis
"""

import argparse
import json
import math
import re
import sys
from pathlib import Path
from collections import Counter
from typing import List, Tuple, Dict


def shannon_entropy(buf: bytes) -> float:
    """Calculate Shannon entropy of a buffer."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / len(buf)
            entropy -= p * math.log2(p)
    return entropy


def analyze_entropy_by_block(data: bytes, block_size: int = 256) -> List[Dict]:
    """Analyze entropy of data in fixed-size blocks."""
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        ent = shannon_entropy(block)
        null_ratio = block.count(0) / len(block) if block else 0
        results.append({
            'offset': i,
            'offset_hex': f'0x{i:08x}',
            'size': len(block),
            'entropy': ent,
            'null_ratio': null_ratio,
            'type': 'low_entropy' if ent < 2.0 else 'medium' if ent < 6.0 else 'high_entropy'
        })
    return results


def detect_repeating_patterns(data: bytes, pattern_size: int = 4, min_repeats: int = 3) -> List[Dict]:
    """Detect repeating patterns in data."""
    patterns = {}
    for i in range(len(data) - pattern_size + 1):
        pattern = data[i:i+pattern_size]
        if pattern not in patterns:
            patterns[pattern] = []
        patterns[pattern].append(i)
    
    results = []
    for pattern, offsets in patterns.items():
        if len(offsets) >= min_repeats:
            # Calculate spacing between occurrences
            spacings = [offsets[j+1] - offsets[j] for j in range(len(offsets)-1)]
            avg_spacing = sum(spacings) / len(spacings) if spacings else 0
            
            results.append({
                'pattern': pattern.hex(),
                'count': len(offsets),
                'offsets': [f'0x{o:08x}' for o in offsets[:10]],  # First 10
                'avg_spacing': avg_spacing,
                'min_spacing': min(spacings) if spacings else 0,
                'max_spacing': max(spacings) if spacings else 0,
            })
    
    # Sort by frequency
    results.sort(key=lambda x: x['count'], reverse=True)
    return results[:20]  # Top 20


def analyze_null_bytes(data: bytes, block_size: int = 128) -> Dict:
    """Analyze null byte distribution."""
    total_nulls = data.count(0)
    
    # Null byte density by block
    null_blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        null_count = block.count(0)
        null_density = null_count / len(block) if block else 0
        if null_density > 0.5:  # Blocks with >50% nulls
            null_blocks.append({
                'offset': f'0x{i:08x}',
                'size': len(block),
                'null_count': null_count,
                'null_density': null_density,
            })
    
    return {
        'total_nulls': total_nulls,
        'null_ratio': total_nulls / len(data) if data else 0,
        'high_density_blocks': null_blocks[:10],
    }


def detect_probable_structure(data: bytes) -> Dict:
    """Detect probable structure sections."""
    size = len(data)
    
    # Analyze first, middle, and last sections
    sections = [
        ('header', data[:512]),
        ('middle', data[size//2-256:size//2+256]),
        ('footer', data[-512:]),
    ]
    
    results = {}
    for name, section in sections:
        results[name] = {
            'size': len(section),
            'entropy': shannon_entropy(section),
            'null_ratio': section.count(0) / len(section),
            'null_bytes': section.count(0),
            'ascii_printable': sum(1 for b in section if 32 <= b < 127),
            'utf16_like': len([b for b in section if b in (0x00, 0x30) or (0x20 <= b <= 0x7e)]),
        }
    
    return results


def analyze_alignment_patterns(data: bytes) -> Dict:
    """Analyze DWORD (4-byte) and QWORD (8-byte) alignment."""
    dword_pattern = []
    qword_pattern = []
    
    for i in range(0, min(len(data)-4, 1000), 4):
        dword = int.from_bytes(data[i:i+4], 'little')
        if dword == 0:
            dword_pattern.append(('null', i))
        elif dword < 1000:
            dword_pattern.append(('small_int', i))
        elif dword > 0x7fffffff:
            dword_pattern.append(('negative_int', i))
        else:
            dword_pattern.append(('other', i))
    
    dword_dist = Counter(t for t, _ in dword_pattern)
    
    return {
        'dword_distribution': dict(dword_dist),
        'null_dwords': sum(1 for t, _ in dword_pattern if t == 'null'),
        'small_int_dwords': sum(1 for t, _ in dword_pattern if t == 'small_int'),
    }


def analyze_string_density(data: bytes) -> Dict:
    """Analyze density of string-like regions."""
    utf16le_re = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
    ascii_re = re.compile(rb'[\x20-\x7e]{4,}')
    
    utf16_matches = list(utf16le_re.finditer(data))
    ascii_matches = list(ascii_re.finditer(data))
    
    # Find gaps between string regions
    string_starts = sorted([m.start() for m in utf16_matches + ascii_matches])
    gaps = []
    for i in range(len(string_starts) - 1):
        gap_size = string_starts[i+1] - string_starts[i] - 4
        if gap_size > 0:
            gaps.append(gap_size)
    
    return {
        'utf16_regions': len(utf16_matches),
        'ascii_regions': len(ascii_matches),
        'total_string_regions': len(utf16_matches) + len(ascii_matches),
        'avg_gap_between_strings': sum(gaps) / len(gaps) if gaps else 0,
        'min_gap': min(gaps) if gaps else 0,
        'max_gap': max(gaps) if gaps else 0,
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Deep binary structure analysis of RWZ files'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--block-size', type=int, default=256, help='Block size for analysis (default: 256)')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown report')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Run all analyses
    entropy_blocks = analyze_entropy_by_block(data, args.block_size)
    repeating = detect_repeating_patterns(data)
    nulls = analyze_null_bytes(data, args.block_size)
    structure = detect_probable_structure(data)
    alignment = analyze_alignment_patterns(data)
    strings = analyze_string_density(data)
    
    results = {
        'file': str(rwz_path),
        'size': len(data),
        'entropy_overall': shannon_entropy(data),
        'entropy_by_block': entropy_blocks,
        'repeating_patterns': repeating,
        'null_byte_analysis': nulls,
        'probable_structure': structure,
        'alignment_analysis': alignment,
        'string_density': strings,
    }
    
    # Output JSON
    if args.out:
        out_path = Path(args.out)
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"JSON output: {out_path}", file=sys.stderr)
    
    # Output Markdown
    if args.out_md:
        md_path = Path(args.out_md)
        with open(md_path, 'w') as f:
            f.write(f"# RWZ Binary Structure Report: {rwz_path.name}\n\n")
            f.write(f"## Summary\n")
            f.write(f"- File size: {len(data):,} bytes\n")
            f.write(f"- Overall entropy: {shannon_entropy(data):.3f}\n")
            f.write(f"- Total null bytes: {nulls['total_nulls']:,} ({100*nulls['null_ratio']:.2f}%)\n")
            f.write(f"- UTF-16 string regions: {strings['utf16_regions']}\n")
            f.write(f"- ASCII string regions: {strings['ascii_regions']}\n")
            f.write("\n")
            
            # Entropy distribution
            f.write("## Entropy Distribution by Block\n")
            low_ent = [b for b in entropy_blocks if b['type'] == 'low_entropy']
            high_ent = [b for b in entropy_blocks if b['type'] == 'high_entropy']
            f.write(f"- Low entropy blocks: {len(low_ent)}\n")
            f.write(f"- High entropy blocks: {len(high_ent)}\n")
            if low_ent:
                f.write("\nLowest entropy regions:\n")
                for b in sorted(low_ent, key=lambda x: x['entropy'])[:5]:
                    f.write(f"  - {b['offset_hex']}: entropy={b['entropy']:.3f}, nulls={b['null_ratio']:.2%}\n")
            
            # Repeating patterns
            f.write("\n## Top Repeating Patterns\n")
            for pattern in repeating[:10]:
                f.write(f"- Pattern `{pattern['pattern']}`: {pattern['count']} occurrences")
                f.write(f", avg spacing {pattern['avg_spacing']:.0f} bytes\n")
            
            # Probable structure
            f.write("\n## Probable File Structure\n")
            for name, sec_info in structure.items():
                f.write(f"- **{name.upper()}**: entropy={sec_info['entropy']:.3f}, ")
                f.write(f"nulls={sec_info['null_ratio']:.2%}, ascii={sec_info['ascii_printable']}\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    # Console summary
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Low entropy blocks: {len([b for b in entropy_blocks if b['type'] == 'low_entropy'])}")
    print(f"High entropy blocks: {len([b for b in entropy_blocks if b['type'] == 'high_entropy'])}")
    print(f"Repeating patterns found: {len(repeating)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
