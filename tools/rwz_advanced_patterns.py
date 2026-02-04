#!/usr/bin/env python3
"""
RWZ Advanced Pattern & Compression Scanner
===========================================
Author: GitHub Copilot (Session: 2026-02-03)
Purpose: Deep scanning for patterns, compression signatures, and data streams

This tool performs:
1. ZLIB stream detection and decompression
2. Advanced compression pattern analysis (LZ77, etc.)
3. Embedded OLE/compound document detection
4. Likely data stream boundaries
5. Entropy-based data classification
6. Hex patterns for reverse engineering
"""

import argparse
import json
import math
import re
import struct
import sys
import zlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple


def find_zlib_streams(data: bytes) -> List[Dict]:
    """Find and validate ZLIB streams."""
    results = []
    
    # ZLIB magic bytes + compression method
    zlib_sigs = [
        (b'\x78\x01', 'no compression'),
        (b'\x78\x5e', 'fast compression'),
        (b'\x78\x9c', 'default compression'),
        (b'\x78\xda', 'maximum compression'),
    ]
    
    for sig, desc in zlib_sigs:
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            
            # Try to decompress
            try:
                decompressed = zlib.decompress(data[idx:])
                results.append({
                    'offset': idx,
                    'offset_hex': f'0x{idx:08x}',
                    'signature': sig.hex(),
                    'description': desc,
                    'compressed_size': len(data[idx:]),
                    'decompressed_size': len(decompressed),
                    'compression_ratio': len(decompressed) / len(data[idx:]) if len(data[idx:]) > 0 else 0,
                    'decompressed_preview': decompressed[:100].hex(),
                    'decompressed_text': decompressed[:100].decode('utf-8', errors='ignore'),
                })
                # Only first successful occurrence per offset
                break
            except Exception as e:
                # Try next occurrence
                pass
            
            pos = idx + 1
    
    return results


def scan_lz77_patterns(data: bytes) -> List[Dict]:
    """Detect LZ77-like compression patterns (backreferences)."""
    # Look for patterns of repeated bytes/short sequences
    # which are characteristic of LZ77 compression
    
    patterns = []
    
    # Scan for sequences with high repetition
    for i in range(0, len(data) - 16):
        window = data[max(0, i-4096):i+8]
        
        # Look for repeated 4-byte sequences
        pattern = data[i:i+4]
        count = window.count(pattern)
        
        if count >= 3:  # Pattern repeated in recent window
            patterns.append({
                'offset': i,
                'offset_hex': f'0x{i:08x}',
                'pattern': pattern.hex(),
                'pattern_str': pattern.decode('utf-8', errors='ignore'),
                'count_in_window': count,
                'window_size': len(window),
            })
    
    return patterns[:100]


def detect_entropy_anomalies(data: bytes, block_size: int = 512) -> List[Dict]:
    """Detect blocks with unusual entropy patterns."""
    results = []
    
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        
        # Calculate entropy
        counts = [0] * 256
        for b in block:
            counts[b] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / len(block)
                entropy -= p * math.log2(p)
        
        # Anomalies: very low or very high entropy
        is_anomaly = entropy < 1.5 or entropy > 7.0
        
        if is_anomaly:
            results.append({
                'offset': i,
                'offset_hex': f'0x{i:08x}',
                'size': len(block),
                'entropy': entropy,
                'type': 'very_low' if entropy < 1.5 else 'very_high',
                'null_ratio': block.count(0) / len(block),
                'unique_bytes': len(set(block)),
            })
    
    return results


def find_hex_dumps(data: bytes) -> List[Dict]:
    """Find regions that look like hex dumps or encoded data."""
    results = []
    
    # Look for sequences of valid hex ASCII characters: 0-9a-fA-F and spaces
    hex_pattern = re.compile(rb'[ 0-9a-fA-F]{32,}')
    
    for m in hex_pattern.finditer(data):
        text = m.group()
        hex_chars = len([c for c in text if c in b'0123456789abcdefABCDEF'])
        if hex_chars > 16:
            results.append({
                'offset': m.start(),
                'offset_hex': f'0x{m.start():08x}',
                'size': len(text),
                'hex_char_count': hex_chars,
                'sample': text[:64].decode('utf-8', errors='ignore'),
            })
    
    return results[:50]


def analyze_byte_distribution_patterns(data: bytes, block_size: int = 256) -> Dict:
    """Analyze patterns in byte distribution."""
    blocks_by_entropy = {'low': [], 'medium': [], 'high': []}
    
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        
        counts = [0] * 256
        for b in block:
            counts[b] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / len(block)
                entropy -= p * math.log2(p)
        
        category = 'low' if entropy < 2.0 else 'medium' if entropy < 5.0 else 'high'
        blocks_by_entropy[category].append({
            'offset': i,
            'entropy': entropy,
        })
    
    return {
        'low_entropy_blocks': len(blocks_by_entropy['low']),
        'medium_entropy_blocks': len(blocks_by_entropy['medium']),
        'high_entropy_blocks': len(blocks_by_entropy['high']),
        'lowest_entropy': min(b['entropy'] for b in blocks_by_entropy['low']) if blocks_by_entropy['low'] else None,
        'highest_entropy': max(b['entropy'] for b in blocks_by_entropy['high']) if blocks_by_entropy['high'] else None,
    }


def scan_for_ole2_signatures(data: bytes) -> Optional[Dict]:
    """Check for OLE2 (Compound Document) signatures."""
    if data.startswith(b'\xd0\xcf\x11\xe0'):
        try:
            # Try to extract header info
            header_sig = data[22:24]
            return {
                'found': True,
                'offset': 0,
                'signature': 'OLE2/Compound Document',
                'byte_order': 'Little-endian' if data[28] == 0xfe else 'Big-endian',
            }
        except:
            pass
    return None


def find_potential_file_headers(data: bytes) -> List[Dict]:
    """Find potential embedded file headers."""
    headers = {
        b'PK\x03\x04': 'ZIP/DOCX',
        b'\x1f\x8b': 'GZIP',
        b'%PDF': 'PDF',
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF8': 'GIF',
        b'BM': 'BMP',
        b'II\x2a\x00': 'TIFF (LE)',
        b'MM\x00\x2a': 'TIFF (BE)',
    }
    
    results = []
    for sig, fmt in headers.items():
        idx = 0
        while idx < len(data):
            pos = data.find(sig, idx)
            if pos == -1:
                break
            results.append({
                'offset': pos,
                'offset_hex': f'0x{pos:08x}',
                'format': fmt,
                'signature': sig.hex(),
            })
            idx = pos + 1
    
    return results


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Advanced pattern and compression scanning'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
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
    
    print("  - Scanning for ZLIB streams...", file=sys.stderr)
    zlib_streams = find_zlib_streams(data)
    
    print("  - Detecting entropy anomalies...", file=sys.stderr)
    anomalies = detect_entropy_anomalies(data)
    
    print("  - Finding potential file headers...", file=sys.stderr)
    file_headers = find_potential_file_headers(data)
    
    print("  - Analyzing byte distribution...", file=sys.stderr)
    distribution = analyze_byte_distribution_patterns(data)
    
    print("  - Checking for OLE2 signatures...", file=sys.stderr)
    ole2 = scan_for_ole2_signatures(data)
    
    print("  - Scanning LZ77 patterns...", file=sys.stderr)
    lz77 = scan_lz77_patterns(data)
    
    results = {
        'file': str(rwz_path),
        'size': len(data),
        'zlib_streams': zlib_streams,
        'entropy_anomalies': anomalies,
        'file_headers': file_headers,
        'byte_distribution': distribution,
        'ole2_detected': ole2,
        'lz77_patterns': lz77,
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
            f.write(f"# Advanced Pattern Analysis: {rwz_path.name}\n\n")
            
            # ZLIB Streams
            f.write("## ZLIB Compression Streams\n")
            if zlib_streams:
                f.write(f"Found {len(zlib_streams)} ZLIB stream(s):\n")
                for stream in zlib_streams:
                    f.write(f"- Offset {stream['offset_hex']}: {stream['description']}\n")
                    f.write(f"  - Compressed: {stream['compressed_size']} bytes\n")
                    f.write(f"  - Decompressed: {stream['decompressed_size']} bytes\n")
                    f.write(f"  - Ratio: {stream['compression_ratio']:.2f}x\n")
                    f.write(f"  - Text preview: {stream['decompressed_text']}\n")
            else:
                f.write("No ZLIB streams found.\n")
            
            # Entropy
            f.write(f"\n## Entropy Distribution\n")
            f.write(f"- Low entropy blocks: {distribution['low_entropy_blocks']}\n")
            f.write(f"- Medium entropy blocks: {distribution['medium_entropy_blocks']}\n")
            f.write(f"- High entropy blocks: {distribution['high_entropy_blocks']}\n")
            
            # Anomalies
            if anomalies:
                f.write(f"\n## Entropy Anomalies\n")
                f.write(f"Found {len(anomalies)} anomalous blocks:\n")
                for anom in anomalies[:10]:
                    f.write(f"- {anom['offset_hex']}: {anom['type']} (entropy={anom['entropy']:.3f})\n")
            
            # File headers
            if file_headers:
                f.write(f"\n## Embedded File Signatures\n")
                f.write(f"Found {len(file_headers)} file header(s):\n")
                for hdr in file_headers:
                    f.write(f"- {hdr['offset_hex']}: {hdr['format']}\n")
            
            # OLE2
            if ole2:
                f.write(f"\n## OLE2 Document\n")
                f.write("This file is an OLE2/Compound Document container.\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== FINDINGS ===", file=sys.stderr)
    print(f"ZLIB streams: {len(zlib_streams)}")
    print(f"Entropy anomalies: {len(anomalies)}")
    print(f"File headers: {len(file_headers)}")
    print(f"OLE2 detected: {ole2 is not None}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
