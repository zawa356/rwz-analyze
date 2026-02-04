#!/usr/bin/env python3
"""
RWZ Detailed Hex Inspector & Validator
=======================================
Author: GitHub Copilot (Session: 2026-02-03)
Purpose: Detailed inspection of specific offsets and validation of suspected structures

This tool provides:
1. Detailed hex dumps with context
2. Decode attempts (UTF-16, ASCII, UTF-8)
3. ZLIB signature validation and false positive analysis
4. Structure boundary analysis
5. Sample data extraction for manual review
"""

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path
from typing import List, Dict, Tuple


def hex_dump(data: bytes, start: int = 0, size: int = 256, width: int = 16) -> str:
    """Create a formatted hex dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{start+i:08x}: {hex_part:<{width*3}} {ascii_part}')
    return '\n'.join(lines)


def validate_zlib_signature(data: bytes, offset: int) -> Dict:
    """Validate if ZLIB signature at offset is a real stream."""
    result = {
        'offset': offset,
        'offset_hex': f'0x{offset:08x}',
        'signature': data[offset:offset+2].hex(),
        'is_valid': False,
        'error': None,
        'decompressed_size': 0,
        'decompressed_preview': '',
        'decompressed_text': '',
    }
    
    try:
        # Try to decompress with a size limit
        stream = data[offset:]
        decompressed = zlib.decompress(stream)
        result['is_valid'] = True
        result['decompressed_size'] = len(decompressed)
        result['decompressed_preview'] = decompressed[:64].hex()
        result['decompressed_text'] = decompressed[:64].decode('utf-8', errors='ignore')
        return result
    except zlib.error as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = f"Unexpected error: {type(e).__name__}: {e}"
    
    return result


def analyze_context_around_offset(data: bytes, offset: int, context_size: int = 128) -> Dict:
    """Analyze what's before and after a given offset."""
    start = max(0, offset - context_size)
    end = min(len(data), offset + context_size)
    
    before = data[start:offset]
    at = data[offset:min(offset+16, len(data))]
    after = data[min(offset+16, len(data)):end]
    
    result = {
        'offset': offset,
        'offset_hex': f'0x{offset:08x}',
        'before_hex': before.hex() if before else '',
        'at_hex': at.hex(),
        'after_hex': after.hex() if after else '',
        'before_text': before.decode('utf-8', errors='ignore')[-40:] if before else '',
        'at_text': at.decode('utf-8', errors='ignore'),
        'after_text': after[:40].decode('utf-8', errors='ignore') if after else '',
    }
    
    return result


def extract_structure_samples(data: bytes) -> List[Dict]:
    """Extract samples of what might be structures."""
    samples = []
    
    # Sample 1: Header (first 256 bytes)
    samples.append({
        'name': 'File Header',
        'offset': 0,
        'size': min(256, len(data)),
        'hex': hex_dump(data[0:min(256, len(data))]),
    })
    
    # Sample 2: First rule (from gap report, typically starts at 0x33)
    if len(data) > 0x33 + 256:
        samples.append({
            'name': 'First Rule (0x33)',
            'offset': 0x33,
            'size': 256,
            'hex': hex_dump(data[0x33:0x33+256]),
        })
    
    # Sample 3: Footer (last 256 bytes)
    footer_start = max(0, len(data) - 256)
    samples.append({
        'name': 'File Footer',
        'offset': footer_start,
        'size': min(256, len(data) - footer_start),
        'hex': hex_dump(data[footer_start:], start=footer_start, size=256),
    })
    
    # Sample 4: Low entropy region (0x15300)
    if len(data) > 0x15300 + 256:
        samples.append({
            'name': 'Low Entropy Region (0x15300)',
            'offset': 0x15300,
            'size': 256,
            'hex': hex_dump(data[0x15300:0x15300+256], start=0x15300),
        })
    
    return samples


def validate_rule_headers(data: bytes) -> List[Dict]:
    """Validate detected rule headers."""
    import re
    
    results = []
    
    # Find all rule headers
    rule_pattern = re.compile(rb'\[([^\]]+)\]')
    
    for m in rule_pattern.finditer(data):
        offset = m.start()
        rule_name = m.group(1).decode('utf-16le', errors='ignore') if b'\x00' in m.group(1) else m.group(1).decode('utf-8', errors='ignore')
        
        # Get context
        context_start = max(0, offset - 32)
        context_end = min(len(data), offset + 128)
        context = data[context_start:context_end]
        
        results.append({
            'offset': offset,
            'offset_hex': f'0x{offset:08x}',
            'rule_name': rule_name.strip(),
            'header_bytes': m.group(0).hex(),
            'context': context.hex(),
            'context_text': context.decode('utf-8', errors='ignore'),
        })
    
    return results[:20]


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Detailed hex inspection and validation'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--inspect', type=str, help='Inspect specific offset (hex, e.g., 0x1000)')
    parser.add_argument('--validate-zlib', type=str, help='Validate ZLIB at offset')
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
    
    results = {
        'file': str(rwz_path),
        'size': len(data),
    }
    
    # Detailed inspection
    if args.inspect:
        offset = int(args.inspect, 16)
        print(f"Inspecting offset {args.inspect}...", file=sys.stderr)
        results['inspection'] = analyze_context_around_offset(data, offset, 256)
        results['hex_dump'] = hex_dump(data[max(0, offset-128):min(len(data), offset+256)], 
                                       start=max(0, offset-128))
    
    # ZLIB validation
    if args.validate_zlib:
        offset = int(args.validate_zlib, 16)
        print(f"Validating ZLIB at offset {args.validate_zlib}...", file=sys.stderr)
        results['zlib_validation'] = validate_zlib_signature(data, offset)
    
    # Sample structures
    print("Extracting structure samples...", file=sys.stderr)
    results['structure_samples'] = extract_structure_samples(data)
    
    # Validate rule headers
    print("Validating rule headers...", file=sys.stderr)
    results['rule_headers'] = validate_rule_headers(data)
    
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
            f.write(f"# RWZ Hex Inspection Report: {rwz_path.name}\n\n")
            
            # Inspection result
            if 'inspection' in results:
                insp = results['inspection']
                f.write("## Context Analysis\n")
                f.write(f"- Offset: {insp['offset_hex']}\n")
                f.write(f"- Before: `{insp['before_text']}`\n")
                f.write(f"- At: `{insp['at_text']}`\n")
                f.write(f"- After: `{insp['after_text']}`\n\n")
                if 'hex_dump' in results:
                    f.write("## Hex Dump\n")
                    f.write("```\n")
                    f.write(results['hex_dump'])
                    f.write("\n```\n\n")
            
            # ZLIB validation
            if 'zlib_validation' in results:
                zlib_val = results['zlib_validation']
                f.write("## ZLIB Signature Validation\n")
                f.write(f"- Valid: {zlib_val['is_valid']}\n")
                if zlib_val['error']:
                    f.write(f"- Error: {zlib_val['error']}\n")
                else:
                    f.write(f"- Decompressed size: {zlib_val['decompressed_size']}\n")
                    f.write(f"- Preview: `{zlib_val['decompressed_text']}`\n")
            
            # Rule headers
            if results['rule_headers']:
                f.write(f"\n## Rule Headers Found\n")
                f.write(f"Total: {len(results['rule_headers'])}\n\n")
                for rule in results['rule_headers'][:5]:
                    f.write(f"- {rule['offset_hex']}: `{rule['rule_name']}`\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
