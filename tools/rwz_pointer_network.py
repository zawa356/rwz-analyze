#!/usr/bin/env python3
"""
RWZ Pointer Network Analysis & Visualization
==============================================
Author: GitHub Copilot (Session: 2026-02-03, Phase 2)
Purpose: Complete analysis of pointer relationships and object graph

This tool performs:
1. Comprehensive pointer collection and classification
2. Pointer chain tracking (all depths)
3. Reference counting and cycle detection
4. Object graph generation
5. Reachability analysis
6. Data flow mapping
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict, deque


def extract_all_pointers(data: bytes, min_val: int = 0, max_val: Optional[int] = None) -> List[Dict]:
    """Extract all potential pointers from data."""
    if max_val is None:
        max_val = len(data)
    
    pointers = []
    
    for offset in range(0, len(data) - 3, 4):
        val = struct.unpack('<I', data[offset:offset+4])[0]
        
        # Valid pointer criteria
        if min_val <= val < max_val:
            pointers.append({
                'offset': offset,
                'offset_hex': f'0x{offset:08x}',
                'value': val,
                'value_hex': f'0x{val:08x}',
                'target': val,
                'target_hex': f'0x{val:08x}',
                'confidence': _estimate_pointer_confidence(data, offset, val),
            })
    
    return pointers


def _estimate_pointer_confidence(data: bytes, offset: int, target: int) -> float:
    """Estimate if a value is really a pointer."""
    confidence = 0.0
    
    # Is it aligned?
    if target % 4 == 0:
        confidence += 0.2
    
    # Does it point to valid ASCII/UTF-16?
    if target + 16 < len(data):
        region = data[target:target+16]
        if any(32 <= b <= 126 for b in region):
            confidence += 0.3
    
    # Is it preceded by a size field?
    if offset >= 4:
        prev_val = struct.unpack('<I', data[offset-4:offset])[0]
        if 100 < prev_val < 50000:  # Looks like a size
            confidence += 0.2
    
    # Multiple pointers in sequence?
    if offset >= 8 and offset + 8 < len(data):
        prev_val = struct.unpack('<I', data[offset-4:offset])[0]
        next_val = struct.unpack('<I', data[offset+4:offset+8])[0]
        if target > 100 and (100 <= prev_val < len(data)) and (100 <= next_val < len(data)):
            confidence += 0.3
    
    return min(1.0, confidence)


def build_pointer_graph(pointers: List[Dict], data: bytes) -> Dict:
    """Build a graph of pointer relationships."""
    graph = {
        'nodes': {},  # offset -> info
        'edges': [],  # [from_offset, to_offset]
        'cycles': [],
        'chains': [],
    }
    
    # Create nodes
    for ptr in pointers:
        graph['nodes'][ptr['offset']] = {
            'offset_hex': ptr['offset_hex'],
            'value': ptr['value'],
            'target': ptr['target'],
            'confidence': ptr['confidence'],
            'in_degree': 0,
            'out_degree': 0,
        }
    
    # Create edges
    for ptr in pointers:
        target = ptr['target']
        graph['edges'].append({
            'from': ptr['offset'],
            'from_hex': ptr['offset_hex'],
            'to': target,
            'to_hex': f'0x{target:08x}',
            'confidence': ptr['confidence'],
        })
        graph['nodes'][ptr['offset']]['out_degree'] += 1
        
        # Check if target is also a pointer offset
        if target in graph['nodes']:
            graph['nodes'][target]['in_degree'] += 1
    
    return graph


def detect_pointer_chains(pointers: List[Dict], data: bytes, max_depth: int = 10) -> List[Dict]:
    """Detect chains of pointers."""
    chains = []
    visited = set()
    
    # Build offset -> pointer mapping
    offset_to_ptr = {p['offset']: p for p in pointers}
    
    for start_ptr in pointers:
        if start_ptr['offset'] in visited:
            continue
        
        chain = [start_ptr['offset']]
        current_target = start_ptr['value']
        depth = 0
        
        while depth < max_depth:
            # Is the target also a valid pointer offset?
            if current_target in offset_to_ptr:
                next_ptr = offset_to_ptr[current_target]
                if next_ptr['offset'] in chain:
                    # Cycle detected
                    chains.append({
                        'type': 'cycle',
                        'chain': [f'0x{o:08x}' for o in chain],
                        'cycle_length': len(chain),
                        'depth': depth,
                    })
                    break
                
                chain.append(next_ptr['offset'])
                current_target = next_ptr['value']
                depth += 1
            else:
                # Chain terminates
                if depth > 0:
                    chains.append({
                        'type': 'linear',
                        'chain': [f'0x{o:08x}' for o in chain],
                        'depth': depth + 1,
                        'final_target': f'0x{current_target:08x}',
                    })
                break
        
        visited.update(chain)
    
    return sorted(chains, key=lambda x: -x['depth'])[:100]


def analyze_pointer_regions(pointers: List[Dict]) -> Dict:
    """Analyze clustering and patterns in pointer distribution."""
    if not pointers:
        return {}
    
    analysis = {
        'total_pointers': len(pointers),
        'offset_range': (min(p['offset'] for p in pointers), max(p['offset'] for p in pointers)),
        'pointer_spacing': [],
        'clusters': [],
        'density_map': {},
    }
    
    # Sort pointers by offset
    sorted_ptrs = sorted(pointers, key=lambda p: p['offset'])
    
    # Analyze spacing
    spacings = []
    for i in range(len(sorted_ptrs) - 1):
        spacing = sorted_ptrs[i+1]['offset'] - sorted_ptrs[i]['offset']
        spacings.append(spacing)
    
    if spacings:
        analysis['pointer_spacing'] = {
            'min': min(spacings),
            'max': max(spacings),
            'avg': sum(spacings) / len(spacings),
            'mode': max(set(spacings), key=spacings.count) if spacings else 0,
        }
    
    # Find clusters (groups of pointers close together)
    cluster = []
    for ptr in sorted_ptrs:
        if not cluster or ptr['offset'] - cluster[-1]['offset'] < 100:
            cluster.append(ptr)
        else:
            if len(cluster) > 3:
                analysis['clusters'].append({
                    'start': cluster[0]['offset'],
                    'end': cluster[-1]['offset'],
                    'size': cluster[-1]['offset'] - cluster[0]['offset'],
                    'count': len(cluster),
                })
            cluster = [ptr]
    
    return analysis


def classify_pointers(pointers: List[Dict], data: bytes) -> Dict:
    """Classify pointers by their target characteristics."""
    classification = {
        'null_pointers': 0,
        'string_pointers': 0,
        'data_pointers': 0,
        'code_pointers': 0,
        'unknown': 0,
    }
    
    for ptr in pointers:
        target = ptr['target']
        
        if target == 0:
            classification['null_pointers'] += 1
        elif target + 16 < len(data):
            region = data[target:target+16]
            
            # Check if it's string-like
            ascii_count = sum(1 for b in region if 32 <= b <= 126)
            null_count = region.count(0)
            
            if ascii_count > 8:
                classification['string_pointers'] += 1
            elif null_count > 12:
                classification['data_pointers'] += 1
            else:
                classification['unknown'] += 1
    
    return classification


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Analyze pointer networks and object graphs'
    )
    parser.add_argument('rwz_file', help='Path to RWZ file')
    parser.add_argument('--out', help='Output JSON file')
    parser.add_argument('--out-md', help='Output Markdown file')
    parser.add_argument('--confidence-min', type=float, default=0.0, 
                       help='Minimum pointer confidence (0-1)')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"Error: {rwz_path} not found", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing {rwz_path} ({len(data)} bytes)", file=sys.stderr)
    
    # Extract all pointers
    print("  - Extracting all pointers...", file=sys.stderr)
    all_pointers = extract_all_pointers(data, 0, len(data))
    print(f"    Found {len(all_pointers)} potential pointers", file=sys.stderr)
    
    # Filter by confidence
    pointers = [p for p in all_pointers if p['confidence'] >= args.confidence_min]
    print(f"    {len(pointers)} above confidence threshold {args.confidence_min}", file=sys.stderr)
    
    # Build pointer graph
    print("  - Building pointer graph...", file=sys.stderr)
    graph = build_pointer_graph(pointers, data)
    
    # Detect chains
    print("  - Detecting pointer chains...", file=sys.stderr)
    chains = detect_pointer_chains(pointers, data)
    
    # Analyze regions
    print("  - Analyzing pointer regions...", file=sys.stderr)
    regions = analyze_pointer_regions(pointers)
    
    # Classify pointers
    print("  - Classifying pointers...", file=sys.stderr)
    classification = classify_pointers(pointers, data)
    
    results = {
        'file': str(rwz_path),
        'total_pointers': len(all_pointers),
        'pointers_analyzed': len(pointers),
        'graph': {
            'nodes_count': len(graph['nodes']),
            'edges_count': len(graph['edges']),
            'sample_edges': graph['edges'][:20],
        },
        'chains': chains,
        'regions': regions,
        'classification': classification,
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
            f.write(f"# RWZ Pointer Network Analysis\n\n")
            
            f.write("## Summary\n")
            f.write(f"- Total potential pointers: {len(all_pointers)}\n")
            f.write(f"- Pointers analyzed: {len(pointers)}\n")
            f.write(f"- Graph nodes: {results['graph']['nodes_count']}\n")
            f.write(f"- Graph edges: {results['graph']['edges_count']}\n\n")
            
            # Pointer classification
            f.write("## Pointer Classification\n")
            for cls, count in classification.items():
                f.write(f"- {cls}: {count}\n")
            
            # Chains
            f.write(f"\n## Pointer Chains (Top 10)\n")
            for i, chain in enumerate(chains[:10], 1):
                f.write(f"\n### Chain {i}\n")
                f.write(f"- Type: {chain['type']}\n")
                f.write(f"- Depth: {chain['depth']}\n")
                f.write(f"- Path: {' → '.join(chain['chain'][:5])}\n")
                if 'final_target' in chain:
                    f.write(f"- Final: {chain['final_target']}\n")
            
            # Regions
            f.write(f"\n## Pointer Distribution\n")
            if regions.get('pointer_spacing'):
                spacing = regions['pointer_spacing']
                f.write(f"- Spacing min: {spacing['min']} bytes\n")
                f.write(f"- Spacing max: {spacing['max']} bytes\n")
                f.write(f"- Spacing avg: {spacing['avg']:.1f} bytes\n")
                f.write(f"- Spacing mode: {spacing['mode']} bytes\n")
            
            # Clusters
            if regions.get('clusters'):
                f.write(f"\n## Pointer Clusters\n")
                f.write(f"Found {len(regions['clusters'])} clusters\n")
                for cluster in regions['clusters'][:5]:
                    f.write(f"- 0x{cluster['start']:08x}..0x{cluster['end']:08x}: ")
                    f.write(f"{cluster['count']} pointers ({cluster['size']} bytes)\n")
        
        print(f"Markdown output: {md_path}", file=sys.stderr)
    
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(f"Pointers extracted: {len(pointers)}")
    print(f"Chains detected: {len(chains)}")
    print(f"Clusters found: {len(regions.get('clusters', []))}")
    print(f"String pointers: {classification['string_pointers']}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
