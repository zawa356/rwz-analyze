#!/usr/bin/env python3
"""
RWZ Metadata & Object Extractor
================================
Author: GitHub Copilot (Session: 2026-02-03)
Purpose: Extract structured metadata, pointers, and object references from RWZ

This tool performs:
1. DWORD/QWORD pointer detection and tracking
2. Size field recognition (common size patterns)
3. Offset/reference resolution
4. Embedded object catalog
5. Likely data structure mapping
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict


def extract_dwords(data: bytes, min_offset: int = 0, max_offset: Optional[int] = None) -> List[Dict]:
    """Extract all DWORD values at 4-byte alignment."""
    if max_offset is None:
        max_offset = len(data)
    
    dwords = []
    for i in range(min_offset, max_offset - 4, 4):
        val_le = struct.unpack('<I', data[i:i+4])[0]
        val_be = struct.unpack('>I', data[i:i+4])[0]
        
        # Classify DWORD
        classification = 'other'
        if val_le == 0:
            classification = 'null'
        elif val_le == 1:
            classification = 'marker_1'
        elif 1 < val_le < 256:
            classification = 'small_value'
        elif val_le == 0xffffffff:
            classification = 'all_ones'
        elif 256 <= val_le < len(data):
            classification = 'possible_offset'
        elif val_le > len(data):
            classification = 'out_of_bounds'
        
        dwords.append({
            'offset': i,
            'offset_hex': f'0x{i:08x}',
            'value_le': val_le,
            'value_be': val_be,
            'value_hex': f'0x{val_le:08x}',
            'classification': classification,
            'is_valid_offset': 0 <= val_le < len(data),
        })
    
    return dwords


def identify_size_fields(data: bytes) -> List[Dict]:
    """Identify likely size fields based on proximity to string data."""
    # Find UTF-16 string regions
    string_regions = []
    i = 0
    while i < len(data) - 4:
        # Look for UTF-16LE ASCII pattern (char followed by 0x00)
        if (0x20 <= data[i] <= 0x7e) and data[i+1] == 0:
            start = i
            while i < len(data) - 1 and ((0x20 <= data[i] <= 0x7e) and data[i+1] == 0):
                i += 2
            length = i - start
            string_regions.append({
                'start': start,
                'length': length,
                'start_hex': f'0x{start:08x}',
            })
        else:
            i += 1
    
    # Now look for DWORD values that precede strings
    likely_sizes = []
    for region in string_regions[:100]:  # Top 100
        # Look 1-16 bytes before string
        for lookback in [4, 8, 12, 16]:
            offset = region['start'] - lookback
            if offset >= 0 and (offset % 4 == 0):
                val = struct.unpack('<I', data[offset:offset+4])[0]
                # Check if this value is close to actual string length
                char_count = region['length'] // 2  # UTF-16, 2 bytes per char
                if abs(val - char_count) < 10 or abs(val - region['length']) < 20:
                    likely_sizes.append({
                        'field_offset': offset,
                        'field_offset_hex': f'0x{offset:08x}',
                        'value': val,
                        'string_start': region['start'],
                        'string_length': region['length'],
                        'match_type': 'char_count' if abs(val - char_count) < 5 else 'byte_length',
                    })
    
    # Deduplicate and sort
    seen = set()
    unique = []
    for item in likely_sizes:
        key = (item['field_offset'], item['value'])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    
    return sorted(unique, key=lambda x: x['field_offset'])[:100]


def find_pointer_chains(data: bytes, max_chain_length: int = 5) -> List[Dict]:
    """Find chains of pointers (offset -> offset -> offset...)."""
    dwords = extract_dwords(data)
    valid_offsets = {d['offset']: d for d in dwords if d['is_valid_offset']}
    
    chains = []
    for start_offset, dword in valid_offsets.items():
        chain = [start_offset]
        current = dword['value_le']
        
        for _ in range(max_chain_length - 1):
            if current in valid_offsets:
                chain.append(current)
                current = valid_offsets[current]['value_le']
                if current in chain:  # Cycle detected
                    break
            else:
                break
        
        if len(chain) >= 2:
            chains.append({
                'chain': [f'0x{o:08x}' for o in chain],
                'length': len(chain),
                'terminates_at': f'0x{chain[-1]:08x}',
            })
    
    return sorted(chains, key=lambda x: -x['length'])[:50]


def analyze_repeating_structures(data: bytes, struct_size: int = 192) -> List[Dict]:
    """Identify repeating data structures."""
    # Look for identical or similar blocks
    blocks = defaultdict(list)
    
    for i in range(0, len(data) - struct_size, struct_size):
        block = data[i:i+struct_size]
        # Use first few bytes as signature
        sig = block[:16]
        blocks[sig].append(i)
    
    repeating = []
    for sig, offsets in blocks.items():
        if len(offsets) >= 3:
            repeating.append({
                'signature': sig.hex(),
                'count': len(offsets),
                'offsets': [f'0x{o:08x}' for o in offsets[:10]],
                'struct_size': struct_size,
            })
    
    return sorted(repeating, key=lambda x: -x['count'])[:20]


def detect_vtable_patterns(data: bytes) -> List[Dict]:
    """Detect possible vtable or function pointer tables."""
    # Look for aligned sequences of pointers
    patterns = []
    
    for alignment in [4, 8, 16]:
        for start in range(0, len(data) - 32, alignment):
            if start % alignment != 0:
                continue
            
            # Try to read 8 consecutive pointers
            try:
                ptrs = []
                for i in range(8):
                    offset = start + i * 4
                    if offset + 4 <= len(data):
                        val = struct.unpack('<I', data[offset:offset+4])[0]
                        if 0 < val < len(data):
                            ptrs.append(val)
                        else:
                            break
                
                if len(ptrs) >= 4:
                    # This might be a vtable
                    patterns.append({
                        'offset': start,
                        'offset_hex': f'0x{start:08x}',
                        'alignment': alignment,
                        'pointer_count': len(ptrs),
                        'pointers': [f'0x{p:08x}' for p in ptrs],
                    })
            except:
                pass
    
    return patterns[:20]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Extract metadata and objects from RWZ file'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown report')
    parser.add_argument('--dwords', action='store_true', help='Include all DWORD analysis')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Run analyses
    print("  - Extracting DWORD values...", file=sys.stderr)
    dwords = extract_dwords(data)
    
    print("  - Identifying size fields...", file=sys.stderr)
    sizes = identify_size_fields(data)
    
    print("  - Finding pointer chains...", file=sys.stderr)
    chains = find_pointer_chains(data)
    
    print("  - Detecting repeating structures...", file=sys.stderr)
    structs = analyze_repeating_structures(data, 192)
    
    print("  - Finding vtable patterns...", file=sys.stderr)
    vtables = detect_vtable_patterns(data)
    
    results = {
        'file': str(rwz_path),
        'size': len(data),
        'dword_summary': {
            'total_dwords': len(dwords),
            'valid_offsets': sum(1 for d in dwords if d['is_valid_offset']),
            'null_values': sum(1 for d in dwords if d['classification'] == 'null'),
            'marker_1_count': sum(1 for d in dwords if d['classification'] == 'marker_1'),
        },
        'size_fields': sizes,
        'pointer_chains': chains,
        'repeating_structures': structs,
        'vtable_patterns': vtables,
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
            f.write(f"# RWZ Metadata & Object Analysis: {rwz_path.name}\n\n")
            
            # DWORD Summary
            f.write("## DWORD Values Analysis\n")
            f.write(f"- Total DWORD-aligned values: {results['dword_summary']['total_dwords']}\n")
            f.write(f"- Valid file offsets: {results['dword_summary']['valid_offsets']}\n")
            f.write(f"- Null values (0x00000000): {results['dword_summary']['null_values']}\n")
            f.write(f"- Marker values (0x00000001): {results['dword_summary']['marker_1_count']}\n")
            
            # Size fields
            if sizes:
                f.write(f"\n## Identified Size Fields\n")
                f.write(f"Found {len(sizes)} likely size field candidates:\n")
                for size in sizes[:10]:
                    f.write(f"- {size['field_offset_hex']}: value={size['value']} ")
                    f.write(f"({size['match_type']})\n")
                    f.write(f"  - Points to: {size['string_start']}\n")
            
            # Pointer chains
            if chains:
                f.write(f"\n## Pointer Chains\n")
                f.write(f"Found {len(chains)} pointer chains (max length {max(c['length'] for c in chains)}):\n")
                for chain in chains[:10]:
                    f.write(f"- Chain (length {chain['length']}): {' → '.join(chain['chain'][:5])}\n")
            
            # Repeating structures
            if structs:
                f.write(f"\n## Repeating Structures (192-byte blocks)\n")
                for struct in structs[:10]:
                    f.write(f"- Pattern `{struct['signature'][:16]}...`: {struct['count']} occurrences\n")
                    f.write(f"  - Offsets: {', '.join(struct['offsets'][:3])}\n")
            
            # VTables
            if vtables:
                f.write(f"\n## VTable Candidates\n")
                for vtable in vtables[:10]:
                    f.write(f"- {vtable['offset_hex']} (alignment {vtable['alignment']}): ")
                    f.write(f"{vtable['pointer_count']} pointers\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Size fields found: {len(sizes)}")
    print(f"Pointer chains found: {len(chains)}")
    print(f"Repeating structures: {len(structs)}")
    print(f"VTable patterns: {len(vtables)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
