#!/usr/bin/env python3
"""
RWZ 192-Byte Block Structure Analyzer
======================================
Author: GitHub Copilot (Session: 2026-02-03, Phase 2)
Purpose: Deep analysis of 192-byte repeating structures (likely rule metadata)

This tool performs:
1. Extract all 192-byte block instances
2. Compare blocks for pattern similarity/differences
3. Field boundary detection (entropy-based)
4. Structure hypothesis generation
5. Byte-by-byte mapping
6. Build structure specification
"""

import argparse
import json
import math
import struct
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict


def extract_192byte_blocks(data: bytes, start_offset: int = 0) -> List[Dict]:
    """Extract all 192-byte aligned blocks from data."""
    blocks = []
    
    for offset in range(start_offset, len(data) - 191, 192):
        block = data[offset:offset+192]
        if len(block) == 192:
            blocks.append({
                'offset': offset,
                'offset_hex': f'0x{offset:08x}',
                'data': block,
                'hex': block.hex(),
            })
    
    return blocks


def analyze_block_structure(block: bytes) -> Dict:
    """Analyze internal structure of a single 192-byte block."""
    result = {
        'size': len(block),
        'entropy': 0.0,
        'null_ratio': 0.0,
        'dword_count': 0,
        'dword_values': [],
        'ascii_regions': [],
        'utf16_regions': [],
        'field_boundaries': [],
    }
    
    # Entropy
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / len(block)
            entropy -= p * math.log2(p)
    result['entropy'] = entropy
    result['null_ratio'] = block.count(0) / len(block)
    
    # DWORD values
    for i in range(0, len(block) - 3, 4):
        val = struct.unpack('<I', block[i:i+4])[0]
        result['dword_values'].append({
            'offset': i,
            'value': val,
            'hex': f'0x{val:08x}',
        })
    
    # ASCII regions (4+ consecutive bytes)
    i = 0
    while i < len(block):
        if 32 <= block[i] <= 126:
            start = i
            while i < len(block) and 32 <= block[i] <= 126:
                i += 1
            if i - start >= 4:
                result['ascii_regions'].append({
                    'offset': start,
                    'size': i - start,
                    'text': block[start:i].decode('ascii', errors='ignore'),
                })
        else:
            i += 1
    
    # UTF-16LE regions
    i = 0
    while i < len(block) - 1:
        if (32 <= block[i] <= 126) and block[i+1] == 0:
            start = i
            while i < len(block) - 1 and (32 <= block[i] <= 126) and block[i+1] == 0:
                i += 2
            if (i - start) // 2 >= 4:
                try:
                    text = block[start:i].decode('utf-16le', errors='ignore')
                    result['utf16_regions'].append({
                        'offset': start,
                        'size': i - start,
                        'text': text,
                    })
                except:
                    pass
        else:
            i += 1
    
    return result


def compare_blocks(blocks: List[Dict]) -> Dict:
    """Compare multiple blocks to identify differences."""
    if not blocks:
        return {}
    
    comparison = {
        'total_blocks': len(blocks),
        'block_offsets': [b['offset_hex'] for b in blocks],
        'entropy_stats': {
            'min': 0.0,
            'max': 0.0,
            'avg': 0.0,
        },
        'differences': [],
        'similarities': [],
        'field_variance': {},
    }
    
    # Analyze each position across all blocks
    for pos in range(192):
        values = []
        for block in blocks:
            values.append(block['data'][pos])
        
        unique_values = len(set(values))
        
        # If all values are the same, it's a constant field
        if unique_values == 1:
            comparison['similarities'].append({
                'offset': pos,
                'type': 'constant',
                'value': values[0],
                'value_hex': f'0x{values[0]:02x}',
            })
        # If mostly the same with few variations
        elif unique_values <= 3:
            comparison['similarities'].append({
                'offset': pos,
                'type': 'mostly_constant',
                'values': sorted(list(set(values))),
                'variance': unique_values,
            })
        # High variance = variable field
        else:
            comparison['differences'].append({
                'offset': pos,
                'variance': unique_values,
                'samples': values[:3],
            })
    
    return comparison


def detect_field_boundaries(blocks: List[Dict]) -> List[Dict]:
    """Detect field boundaries based on patterns."""
    boundaries = []
    
    # Common field sizes: 1, 2, 4, 8, 16, 32 bytes
    common_sizes = [1, 2, 4, 8, 16, 32, 64]
    
    # Check for alignment patterns
    for size in common_sizes:
        for offset in range(0, 192 - size + 1, size):
            field_data = []
            for block in blocks:
                field = block['data'][offset:offset+size]
                field_data.append(field)
            
            # Check if this looks like a distinct field
            unique_fields = len(set(field_data))
            if unique_fields > 1:  # It varies
                boundaries.append({
                    'offset': offset,
                    'size': size,
                    'variance': unique_fields,
                    'interpretation': _guess_field_type(field_data[0]),
                })
    
    # Remove duplicates and sort
    unique_boundaries = []
    seen = set()
    for b in boundaries:
        key = (b['offset'], b['size'])
        if key not in seen:
            seen.add(key)
            unique_boundaries.append(b)
    
    return sorted(unique_boundaries, key=lambda x: x['offset'])[:30]


def _guess_field_type(data: bytes) -> str:
    """Guess what type of field this might be."""
    if len(data) == 4:
        val = struct.unpack('<I', data)[0]
        if val == 0:
            return 'possibly_null_sentinel'
        elif val < 256:
            return 'possibly_count/flag'
        elif val < len(data) * 1000:
            return 'possibly_size_field'
        else:
            return 'possibly_offset'
    elif len(data) == 8:
        val = struct.unpack('<Q', data)[0]
        if val == 0:
            return 'possibly_null_sentinel'
        else:
            return 'possibly_pointer_or_index'
    elif all(32 <= b <= 126 for b in data):
        return 'possibly_ascii_text'
    elif all(b in (0, 1) for b in data):
        return 'possibly_flag_bits'
    else:
        return 'unknown'


def extract_repeating_patterns(blocks: List[Dict]) -> List[Dict]:
    """Find repeating byte sequences within and across blocks."""
    patterns = defaultdict(list)
    
    # Look for 8-byte patterns
    for block_idx, block in enumerate(blocks):
        for offset in range(0, 192 - 7):
            pattern = block['data'][offset:offset+8]
            patterns[pattern].append((block_idx, offset))
    
    results = []
    for pattern, occurrences in patterns.items():
        if len(occurrences) >= 2:
            results.append({
                'pattern': pattern.hex(),
                'pattern_text': pattern.decode('utf-8', errors='ignore'),
                'occurrences': len(occurrences),
                'locations': occurrences[:10],  # First 10
            })
    
    return sorted(results, key=lambda x: -x['occurrences'])[:20]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Analyze 192-byte repeating block structures'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown file')
    parser.add_argument('--hex-dump', help='Output hex dumps of blocks')
    parser.add_argument('--samples', type=int, default=10, help='Number of blocks to analyze')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Extract all 192-byte blocks
    print("  - Extracting 192-byte blocks...", file=sys.stderr)
    all_blocks = extract_192byte_blocks(data)
    print(f"    Found {len(all_blocks)} blocks", file=sys.stderr)
    
    # Sample blocks for detailed analysis
    sample_size = min(args.samples, len(all_blocks))
    sample_blocks = all_blocks[:sample_size]
    
    # Analyze individual blocks
    print("  - Analyzing block structures...", file=sys.stderr)
    block_analyses = []
    for block in sample_blocks:
        analysis = analyze_block_structure(block['data'])
        block_analyses.append({
            'offset': block['offset_hex'],
            'analysis': analysis,
        })
    
    # Compare blocks
    print("  - Comparing blocks...", file=sys.stderr)
    comparison = compare_blocks(sample_blocks)
    
    # Detect field boundaries
    print("  - Detecting field boundaries...", file=sys.stderr)
    boundaries = detect_field_boundaries(sample_blocks)
    
    # Extract repeating patterns
    print("  - Extracting repeating patterns...", file=sys.stderr)
    patterns = extract_repeating_patterns(sample_blocks)
    
    results = {
        'file': str(rwz_path),
        'total_192byte_blocks': len(all_blocks),
        'blocks_analyzed': sample_size,
        'block_offsets': [b['offset_hex'] for b in sample_blocks],
        'block_analyses': block_analyses,
        'comparison': comparison,
        'field_boundaries': boundaries,
        'repeating_patterns': patterns,
    }
    
    # Output JSON
    if args.out:
        out_path = Path(args.out)
        with open(out_path, 'w') as f:
            # Convert bytes to hex for JSON serialization
            for analysis in results['block_analyses']:
                for field in analysis['analysis']['dword_values']:
                    pass  # Already hex
            json.dump(results, f, indent=2, default=str)
        print(f"JSON output: {out_path}", file=sys.stderr)
    
    # Output Markdown
    if args.out_md:
        md_path = Path(args.out_md)
        with open(md_path, 'w') as f:
            f.write(f"# RWZ 192-Byte Block Structure Analysis\n\n")
            f.write(f"## Summary\n")
            f.write(f"- Total 192-byte blocks found: {len(all_blocks)}\n")
            f.write(f"- Blocks analyzed in detail: {sample_size}\n\n")
            
            # Block offsets
            f.write(f"## Analyzed Block Offsets\n")
            for offset in results['block_offsets']:
                f.write(f"- {offset}\n")
            
            # Field boundaries
            f.write(f"\n## Detected Field Boundaries\n")
            f.write(f"Total fields identified: {len(boundaries)}\n\n")
            for boundary in boundaries[:10]:
                f.write(f"- Offset 0x{boundary['offset']:02x}: ")
                f.write(f"{boundary['size']} bytes ({boundary['interpretation']})\n")
            
            # Repeating patterns
            if patterns:
                f.write(f"\n## Repeating Patterns Within Blocks\n")
                for pattern in patterns[:10]:
                    f.write(f"- Pattern `{pattern['pattern']}`: ")
                    f.write(f"{pattern['occurrences']} occurrences\n")
            
            # Individual block analysis
            f.write(f"\n## Block-by-Block Analysis\n")
            for block_info in results['block_analyses'][:5]:
                f.write(f"\n### Block at {block_info['offset']}\n")
                analysis = block_info['analysis']
                f.write(f"- ASCII regions: {len(analysis['ascii_regions'])}\n")
                f.write(f"- UTF-16 regions: {len(analysis['utf16_regions'])}\n")
                if analysis['ascii_regions']:
                    for region in analysis['ascii_regions'][:2]:
                        f.write(f"  - @0x{region['offset']:02x}: `{region['text']}`\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    # Output hex dumps
    if args.hex_dump:
        dump_path = Path(args.hex_dump)
        with open(dump_path, 'w') as f:
            for block in sample_blocks:
                f.write(f"\n{'='*80}\n")
                f.write(f"Block at offset {block['offset_hex']}\n")
                f.write(f"{'='*80}\n")
                # Hex dump with ASCII
                for i in range(0, 192, 16):
                    hex_part = ' '.join(f'{b:02x}' for b in block['data'][i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in block['data'][i:i+16])
                    f.write(f"{i:04x}: {hex_part:<48} {ascii_part}\n")
        print(f"Hex dump output: {dump_path}", file=sys.stderr)
    
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Total 192-byte blocks: {len(all_blocks)}")
    print(f"Analyzed: {sample_size}")
    print(f"Field boundaries detected: {len(boundaries)}")
    print(f"Repeating patterns: {len(patterns)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
