#!/usr/bin/env python3
"""
RWZ Size Field String Extraction
==================================
Author: GitHub Copilot (Session: 2026-02-03, Phase 2)
Purpose: Extract strings using identified size field patterns

This tool performs:
1. Identification of size fields at specific offsets
2. Extraction of strings bounded by size fields
3. UTF-8 and UTF-16 decoding attempts
4. String validation and confidence scoring
5. Cross-referencing with extracted pointers
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict


def detect_size_fields(data: bytes) -> List[Dict]:
    """Detect fields that look like size fields."""
    size_fields = []
    
    for offset in range(0, len(data) - 4, 4):
        value = struct.unpack('<I', data[offset:offset+4])[0]
        
        # Size field heuristics:
        # 1. Value is reasonable size (10-50000 bytes)
        if not (10 < value < 50000):
            continue
        
        # 2. There's data ahead that matches the size
        if offset + 4 + value > len(data):
            continue
        
        # 3. Check if that data region looks valid
        region = data[offset+4:offset+4+value]
        
        # Can decode as UTF-8 or UTF-16?
        utf8_valid = is_valid_utf8(region)
        utf16_valid = is_valid_utf16(region)
        
        # Has content (not mostly null)
        null_ratio = region.count(0) / len(region) if region else 0
        
        if utf8_valid or utf16_valid or null_ratio < 0.5:
            confidence = 0.0
            if utf8_valid:
                confidence += 0.5
            if utf16_valid:
                confidence += 0.5
            if null_ratio < 0.3:
                confidence += 0.2
            
            size_fields.append({
                'size_offset': offset,
                'size_offset_hex': f'0x{offset:08x}',
                'size_value': value,
                'data_offset': offset + 4,
                'data_offset_hex': f'0x{offset+4:08x}',
                'data_length': value,
                'confidence': min(1.0, confidence),
                'utf8_valid': utf8_valid,
                'utf16_valid': utf16_valid,
                'null_ratio': null_ratio,
            })
    
    return size_fields


def is_valid_utf8(data: bytes) -> bool:
    """Check if data is valid UTF-8."""
    try:
        data.decode('utf-8')
        return True
    except:
        return False


def is_valid_utf16(data: bytes) -> bool:
    """Check if data is valid UTF-16."""
    try:
        if len(data) % 2 != 0:
            return False
        data.decode('utf-16-le')
        return True
    except:
        return False


def extract_strings_from_size_fields(data: bytes, size_fields: List[Dict]) -> List[Dict]:
    """Extract actual strings from size field regions."""
    strings = []
    
    for sf in size_fields:
        start = sf['data_offset']
        length = sf['data_length']
        region = data[start:start+length]
        
        if not region:
            continue
        
        extracted = {
            'size_offset': sf['size_offset'],
            'size_offset_hex': sf['size_offset_hex'],
            'size_value': sf['size_value'],
            'data_offset': sf['data_offset'],
            'data_offset_hex': sf['data_offset_hex'],
            'strings': [],
        }
        
        # Try UTF-8
        if sf['utf8_valid']:
            try:
                text = region.decode('utf-8', errors='ignore')
                if text.strip():
                    extracted['strings'].append({
                        'encoding': 'utf-8',
                        'text': text[:200],  # Limit for output
                        'length': len(text),
                    })
            except:
                pass
        
        # Try UTF-16 LE
        if sf['utf16_valid']:
            try:
                text = region.decode('utf-16-le', errors='ignore')
                if text.strip():
                    extracted['strings'].append({
                        'encoding': 'utf-16-le',
                        'text': text[:200],
                        'length': len(text),
                    })
            except:
                pass
        
        # Try null-terminated extraction
        null_positions = [i for i, b in enumerate(region) if b == 0]
        if null_positions:
            for null_pos in null_positions[:3]:  # First 3 nulls
                if null_pos > 0:
                    text = region[:null_pos].decode('utf-8', errors='ignore')
                    if text.strip() and text not in [s.get('text', '') for s in extracted['strings']]:
                        extracted['strings'].append({
                            'encoding': 'utf-8 (null-terminated)',
                            'text': text[:200],
                            'length': len(text),
                        })
        
        if extracted['strings']:
            strings.append(extracted)
    
    return strings


def find_size_field_patterns(size_fields: List[Dict]) -> Dict:
    """Analyze patterns in size field locations."""
    patterns = {
        'spacing': [],
        'most_common_offset': None,
        'clustering': [],
    }
    
    if not size_fields:
        return patterns
    
    offsets = [sf['size_offset'] for sf in size_fields]
    offsets.sort()
    
    # Spacing analysis
    spacings = []
    for i in range(len(offsets) - 1):
        spacing = offsets[i+1] - offsets[i]
        spacings.append(spacing)
    
    if spacings:
        patterns['spacing'] = {
            'min': min(spacings),
            'max': max(spacings),
            'avg': sum(spacings) / len(spacings),
            'mode': max(set(spacings), key=spacings.count) if spacings else 0,
        }
    
    # Most common offset patterns
    remainder_counts = defaultdict(int)
    for offset in offsets:
        remainder_counts[offset % 192] += 1  # 192-byte block size
    
    if remainder_counts:
        patterns['most_common_offset'] = max(remainder_counts, key=remainder_counts.get)
        patterns['offset_distribution'] = dict(remainder_counts)
    
    return patterns


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Extract strings using size fields'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown file')
    parser.add_argument('--min-confidence', type=float, default=0.5,
                       help='Minimum size field confidence (0-1)')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Detect size fields
    print("  - Detecting size fields...", file=sys.stderr)
    all_size_fields = detect_size_fields(data)
    print(f"    Found {len(all_size_fields)} potential size fields", file=sys.stderr)
    
    # Filter by confidence
    size_fields = [sf for sf in all_size_fields if sf['confidence'] >= args.min_confidence]
    print(f"    {len(size_fields)} above confidence threshold {args.min_confidence}", file=sys.stderr)
    
    # Extract strings
    print("  - Extracting strings from size fields...", file=sys.stderr)
    strings = extract_strings_from_size_fields(data, size_fields)
    print(f"    Extracted strings from {len(strings)} size field regions", file=sys.stderr)
    
    # Analyze patterns
    print("  - Analyzing patterns...", file=sys.stderr)
    patterns = find_size_field_patterns(size_fields)
    
    results = {
        'file': str(rwz_path),
        'total_size_fields': len(all_size_fields),
        'size_fields_analyzed': len(size_fields),
        'strings_extracted': len(strings),
        'patterns': patterns,
        'sample_strings': strings[:50],
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
            f.write(f"# RWZ Size Field String Extraction\n\n")
            
            f.write("## Summary\n")
            f.write(f"- Total size fields: {len(all_size_fields)}\n")
            f.write(f"- Analyzed: {len(size_fields)}\n")
            f.write(f"- Strings extracted: {len(strings)}\n\n")
            
            # Patterns
            if patterns.get('spacing'):
                f.write("## Size Field Spacing\n")
                spacing = patterns['spacing']
                f.write(f"- Min: {spacing['min']} bytes\n")
                f.write(f"- Max: {spacing['max']} bytes\n")
                f.write(f"- Avg: {spacing['avg']:.1f} bytes\n")
                f.write(f"- Mode: {spacing['mode']} bytes\n\n")
            
            # Sample strings
            f.write(f"## Sample Extracted Strings (First 20)\n\n")
            for i, item in enumerate(strings[:20], 1):
                f.write(f"### String {i}\n")
                f.write(f"- Size field offset: {item['size_offset_hex']}\n")
                f.write(f"- Size value: {item['size_value']}\n")
                f.write(f"- Data offset: {item['data_offset_hex']}\n")
                for s in item['strings']:
                    f.write(f"- **{s['encoding']}**: `{s['text']}`\n")
                f.write("\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Size fields detected: {len(size_fields)}")
    print(f"Strings extracted: {len(strings)}")
    print(f"Total extractions: {sum(len(x['strings']) for x in strings)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
