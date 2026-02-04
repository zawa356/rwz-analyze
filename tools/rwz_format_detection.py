#!/usr/bin/env python3
"""
RWZ Format Signature & Container Detection
===========================================
Author: GitHub Copilot (Session: 2026-02-03)
Purpose: Identify RWZ file format, signatures, and container structure

This tool attempts to:
1. Detect known file format signatures
2. Analyze RWZ-specific header/container structure
3. Find potential embedded objects
4. Detect Unicode BOM markers
5. Analyze version/metadata indicators
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional


# Known signatures for file formats and containers
SIGNATURES = {
    # Archives
    b'PK\x03\x04': ('ZIP', 'Common archive format'),
    b'PK\x05\x06': ('ZIP', 'ZIP end of central directory'),
    b'\x1f\x8b': ('GZIP', 'GNU ZIP compression'),
    b'Rar!\x1a\x07': ('RAR', 'RAR5 archive'),
    b'7z\xbc\xaf\x27\x1c': ('7Z', '7-Zip archive'),
    b'BZh': ('BZIP2', 'BZIP2 compression'),
    
    # Document formats
    b'%PDF': ('PDF', 'PDF document'),
    b'%!\x04': ('POSTSCRIPT', 'PostScript file'),
    
    # Image formats
    b'\x89PNG': ('PNG', 'PNG image'),
    b'\xff\xd8\xff': ('JPEG', 'JPEG image'),
    b'GIF8': ('GIF', 'GIF image'),
    
    # Compression algorithms
    b'\x78\x01': ('ZLIB', 'ZLIB compression (no/low)'),
    b'\x78\x9c': ('ZLIB', 'ZLIB compression (default)'),
    b'\x78\xda': ('ZLIB', 'ZLIB compression (max)'),
    b'\x28\xb5\x2f\xfd': ('ZSTD', 'Zstandard compression'),
    b'\x04\x22\x4d\x18': ('LZ4', 'LZ4 frame format'),
    b'\xff\x06\x00\x00sNaPpY': ('SNAPPY', 'Snappy compression'),
    
    # Microsoft formats
    b'MZ': ('PE', 'Windows PE/EXE'),
    b'\xd0\xcf\x11\xe0': ('OLE2', 'OLE2/Compound document'),
    
    # Text encodings
    b'\xff\xfe': ('UTF16LE', 'UTF-16 Little Endian BOM'),
    b'\xfe\xff': ('UTF16BE', 'UTF-16 Big Endian BOM'),
    b'\xef\xbb\xbf': ('UTF8', 'UTF-8 BOM'),
}

# RWZ-specific signatures (research)
RWZ_SIGNATURES = {
    b'[': 'Rule header (likely)',
    b'\x00\x00\x00\x00\x00\x00\x00\x01': 'Boundary marker (8 null + 01)',
    b'\x01\x00\x00\x00': 'DWORD alignment marker (little-endian 1)',
    b'\x00\x01\x00\x00': 'DWORD alignment marker (0x0100)',
}


def find_all_signatures(data: bytes, max_results: int = 100) -> List[Dict]:
    """Find all known signatures in data."""
    findings = []
    
    for sig, (format_name, description) in SIGNATURES.items():
        pos = 0
        count = 0
        while count < max_results:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            findings.append({
                'offset': idx,
                'offset_hex': f'0x{idx:08x}',
                'signature': sig.hex(),
                'format': format_name,
                'description': description,
                'context': data[max(0, idx-4):idx+len(sig)+4].hex(),
            })
            pos = idx + 1
            count += 1
    
    # Sort by offset
    findings.sort(key=lambda x: x['offset'])
    return findings


def detect_unicode_patterns(data: bytes) -> Dict:
    """Detect Unicode text encoding patterns."""
    # Check for UTF-16LE patterns (common in Windows)
    utf16le_pattern = re.compile(rb'([\x20-\x7e])\x00([\x20-\x7e])\x00', re.MULTILINE)
    
    # Check for UTF-16BE patterns
    utf16be_pattern = re.compile(rb'\x00([\x20-\x7e])\x00([\x20-\x7e])', re.MULTILINE)
    
    utf16le_matches = list(utf16le_pattern.finditer(data))
    utf16be_matches = list(utf16be_pattern.finditer(data))
    
    return {
        'utf16le_regions': len(utf16le_matches),
        'utf16be_regions': len(utf16be_matches),
        'likely_utf16le': len(utf16le_matches) > len(utf16be_matches),
        'first_utf16le_at': f'0x{utf16le_matches[0].start():08x}' if utf16le_matches else None,
        'first_utf16be_at': f'0x{utf16be_matches[0].start():08x}' if utf16be_matches else None,
    }


def analyze_header_structure(data: bytes, header_size: int = 512) -> Dict:
    """Analyze file header structure."""
    header = data[:header_size]
    
    # Check for common header patterns
    results = {
        'size': len(header),
        'entropy': 0,  # Would calculate shannon entropy
        'null_prefix': 0,
        'printable_prefix_bytes': 0,
    }
    
    # Count leading null bytes
    for b in header:
        if b == 0:
            results['null_prefix'] += 1
        else:
            break
    
    # Count printable bytes in first 100 bytes
    first_100 = header[:100]
    results['printable_prefix_bytes'] = sum(1 for b in first_100 if 32 <= b <= 126 or b in (9, 10, 13))
    
    # Detect magic bytes
    results['detected_formats'] = [
        (sig_hex, fmt) for sig, (fmt, _) in SIGNATURES.items()
        if header.startswith(sig)
    ]
    
    return results


def find_structure_boundaries(data: bytes) -> List[Dict]:
    """Find potential structure boundaries based on patterns."""
    boundaries = []
    
    # Look for sequences of null DWORDS (common boundaries)
    null_dword = b'\x00\x00\x00\x00'
    pos = 0
    while True:
        idx = data.find(null_dword, pos)
        if idx == -1:
            break
        
        # Check if there are consecutive null DWORDS
        null_count = 0
        for i in range(idx, min(idx + 100, len(data)), 4):
            if data[i:i+4] == null_dword:
                null_count += 1
            else:
                break
        
        if null_count >= 2:
            boundaries.append({
                'offset': idx,
                'offset_hex': f'0x{idx:08x}',
                'type': 'null_dword_sequence',
                'consecutive_nulls': null_count,
                'byte_span': null_count * 4,
            })
        
        pos = idx + 4
    
    return boundaries[:50]  # Top 50


def detect_container_structure(data: bytes) -> Dict:
    """Attempt to detect RWZ container structure."""
    # This is speculative - RWZ format is proprietary
    # Look for markers observed in gap analysis
    
    markers = {
        # From gap analysis: 0x01 00 00 00 00 00 00 00 pattern appears frequently
        'likely_metadata_markers': 0,
        'likely_rule_boundaries': 0,
        'likely_size_indicators': 0,
    }
    
    # Count patterns that might indicate metadata
    metadata_pattern = b'\x01\x00\x00\x00\x00\x00\x00\x00'
    markers['likely_metadata_markers'] = data.count(metadata_pattern)
    
    # Look for ASCII strings followed by 4-byte values (common pattern)
    rule_header_pattern = re.compile(rb'\[([^\]]+)\][\x00\x01\x02\x03]')
    markers['likely_rule_boundaries'] = len(list(rule_header_pattern.finditer(data)))
    
    # Look for 4-byte little-endian values that might be sizes
    # (values between 100-50000 bytes)
    potential_size_count = 0
    for i in range(0, len(data) - 4, 4):
        val = int.from_bytes(data[i:i+4], 'little')
        if 100 < val < 50000:
            potential_size_count += 1
    markers['likely_size_indicators'] = potential_size_count
    
    return markers


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Detect RWZ format signatures and container structure'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--depth', type=int, default=100, help='Max signatures per type (default: 100)')
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
    
    # Run analyses
    signatures = find_all_signatures(data, args.depth)
    unicode_info = detect_unicode_patterns(data)
    header_info = analyze_header_structure(data)
    boundaries = find_structure_boundaries(data)
    container = detect_container_structure(data)
    
    results = {
        'file': str(rwz_path),
        'size': len(data),
        'signatures_found': signatures,
        'unicode_analysis': unicode_info,
        'header_analysis': header_info,
        'structure_boundaries': boundaries,
        'container_markers': container,
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
            f.write(f"# RWZ Format Detection Report: {rwz_path.name}\n\n")
            
            # Summary
            f.write("## Summary\n")
            f.write(f"- File size: {len(data):,} bytes\n")
            f.write(f"- Signatures found: {len(signatures)}\n")
            f.write(f"- Structure boundaries detected: {len(boundaries)}\n")
            
            # Detected formats
            if signatures:
                f.write("\n## Detected Format Signatures\n")
                seen_formats = set()
                for sig in signatures:
                    fmt = sig['format']
                    if fmt not in seen_formats:
                        f.write(f"- **{fmt}**: {sig['description']}\n")
                        f.write(f"  - First occurrence: {sig['offset_hex']}\n")
                        f.write(f"  - Signature: `{sig['signature']}`\n")
                        seen_formats.add(fmt)
            
            # Unicode analysis
            f.write(f"\n## Text Encoding Analysis\n")
            f.write(f"- UTF-16 LE regions: {unicode_info['utf16le_regions']}\n")
            f.write(f"- UTF-16 BE regions: {unicode_info['utf16be_regions']}\n")
            if unicode_info['likely_utf16le']:
                f.write("- **Likely encoding: UTF-16 Little Endian**\n")
            
            # Header
            f.write(f"\n## Header Analysis\n")
            f.write(f"- Leading null bytes: {header_info['null_prefix']}\n")
            f.write(f"- Printable bytes in first 100: {header_info['printable_prefix_bytes']}\n")
            
            # Container markers
            f.write(f"\n## RWZ Container Markers\n")
            f.write(f"- Metadata marker sequences: {container['likely_metadata_markers']}\n")
            f.write(f"- Rule boundary indicators: {container['likely_rule_boundaries']}\n")
            f.write(f"- Size indicator patterns: {container['likely_size_indicators']}\n")
            
            # Structure boundaries
            if boundaries:
                f.write(f"\n## Structure Boundaries\n")
                f.write("Top boundaries by offset:\n")
                for b in boundaries[:10]:
                    f.write(f"- {b['offset_hex']}: {b['type']} ({b['byte_span']} bytes)\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== FINDINGS ===", file=sys.stderr)
    print(f"Signatures detected: {len(set(s['format'] for s in signatures))}")
    print(f"Structure boundaries: {len(boundaries)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
