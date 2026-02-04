#!/usr/bin/env python3
"""
RWZ Phase 2 Unified Integration & Validation Pipeline
=====================================================
Author: GitHub Copilot (Session: 2026-02-03, Phase 2)
Purpose: Integrate all Phase 2 analysis results and validate findings

This tool performs:
1. Integration of all Phase 2 tool outputs
2. Cross-validation of findings
3. Rule extraction engine
4. Comparison with OCR baseline
5. Final comprehensive report generation
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict


def load_json_file(path: Path) -> Optional[Dict]:
    """Load JSON file safely."""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load {path}: {e}", file=sys.stderr)
        return None


def integrate_block_structure(block_data: Dict) -> Dict:
    """Extract key findings from block structure analysis."""
    if not block_data:
        return {}
    
    return {
        'blocks_found': block_data.get('block_count', 0),
        'blocks_analyzed': block_data.get('blocks_analyzed', 0),
        'field_boundaries': block_data.get('field_boundaries', 0),
        'repeating_patterns': block_data.get('repeating_patterns', 0),
    }


def integrate_pointer_network(pointer_data: Dict) -> Dict:
    """Extract key findings from pointer network analysis."""
    if not pointer_data:
        return {}
    
    classification = pointer_data.get('classification', {})
    
    return {
        'total_pointers': pointer_data.get('total_pointers', 0),
        'chains_detected': len(pointer_data.get('chains', [])),
        'clusters_found': len(pointer_data.get('regions', {}).get('clusters', [])),
        'string_pointers': classification.get('string_pointers', 0),
        'data_pointers': classification.get('data_pointers', 0),
    }


def integrate_size_fields(size_data: Dict) -> Dict:
    """Extract key findings from size field analysis."""
    if not size_data:
        return {}
    
    return {
        'size_fields_found': size_data.get('size_fields_analyzed', 0),
        'strings_extracted': size_data.get('strings_extracted', 0),
        'total_extractions': sum(len(s.get('strings', [])) for s in size_data.get('sample_strings', [])),
    }


def integrate_gap_analysis(gap_data: Dict) -> Dict:
    """Extract key findings from gap analysis."""
    if not gap_data:
        return {}
    
    return {
        'total_gaps': gap_data.get('total_gaps', 0),
        'gap_size_bytes': gap_data.get('total_gap_size', 0),
        'gap_percentage': gap_data.get('gap_percentage', 0),
        'pure_null_gaps': gap_data.get('classification', {}).get('pure_null', 0),
        'sparse_gaps': gap_data.get('classification', {}).get('sparse', 0),
        'structured_gaps': gap_data.get('classification', {}).get('structured', 0),
    }


def extract_rules_from_analysis(block_data: Dict, pointer_data: Dict, 
                                size_data: Dict) -> List[Dict]:
    """Attempt to extract rules from integrated analysis."""
    rules = []
    
    # Extract from size fields and strings
    if size_data and 'sample_strings' in size_data:
        for item in size_data.get('sample_strings', [])[:50]:
            for string in item.get('strings', []):
                text = string.get('text', '').strip()
                if text and len(text) > 2:
                    rules.append({
                        'source': 'size_field_extraction',
                        'value': text,
                        'encoding': string.get('encoding', 'unknown'),
                        'size_offset': item.get('size_offset_hex', ''),
                        'confidence': 0.6,
                    })
    
    # Deduplicate
    seen = set()
    unique_rules = []
    for rule in rules:
        key = (rule['source'], rule['value'])
        if key not in seen:
            seen.add(key)
            unique_rules.append(rule)
    
    return unique_rules


def validate_against_ocr(rules: List[Dict], ocr_path: Optional[Path]) -> Dict:
    """Validate extracted rules against OCR data."""
    validation = {
        'total_rules': len(rules),
        'validated': 0,
        'not_found_in_ocr': 0,
        'matches': [],
        'mismatches': [],
    }
    
    if not ocr_path or not ocr_path.exists():
        validation['status'] = 'OCR data not found'
        return validation
    
    try:
        with open(ocr_path, 'r') as f:
            ocr_data = json.load(f)
        
        ocr_texts = set()
        if isinstance(ocr_data, dict) and 'results' in ocr_data:
            for result in ocr_data.get('results', []):
                if 'text' in result:
                    ocr_texts.add(result['text'].lower())
        
        for rule in rules:
            rule_text = rule.get('value', '').lower()
            if rule_text in ocr_texts:
                validation['validated'] += 1
                validation['matches'].append(rule_text[:50])
            else:
                validation['not_found_in_ocr'] += 1
                validation['mismatches'].append(rule_text[:50])
        
        validation['status'] = 'Validation complete'
    except Exception as e:
        validation['status'] = f'Error: {e}'
    
    return validation


def generate_comprehensive_report(integration: Dict, rules: List[Dict], 
                                 validation: Dict) -> str:
    """Generate comprehensive final report."""
    report = []
    
    report.append("# RWZ Phase 2 Unified Analysis Report")
    report.append("")
    report.append("## Executive Summary")
    report.append("")
    
    # Coverage metrics
    if 'block_structure' in integration:
        bs = integration['block_structure']
        report.append(f"### Block Structure Analysis")
        report.append(f"- Blocks identified: {bs.get('blocks_found', 0)}")
        report.append(f"- Field boundaries detected: {bs.get('field_boundaries', 0)}")
        report.append(f"- Repeating patterns: {bs.get('repeating_patterns', 0)}")
        report.append("")
    
    if 'pointer_network' in integration:
        pn = integration['pointer_network']
        report.append(f"### Pointer Network Analysis")
        report.append(f"- Total pointers: {pn.get('total_pointers', 0)}")
        report.append(f"- Pointer chains: {pn.get('chains_detected', 0)}")
        report.append(f"- Clusters: {pn.get('clusters_found', 0)}")
        report.append(f"- String pointers: {pn.get('string_pointers', 0)}")
        report.append("")
    
    if 'size_fields' in integration:
        sf = integration['size_fields']
        report.append(f"### Size Field Analysis")
        report.append(f"- Size fields found: {sf.get('size_fields_found', 0)}")
        report.append(f"- Strings extracted: {sf.get('strings_extracted', 0)}")
        report.append("")
    
    if 'gap_analysis' in integration:
        ga = integration['gap_analysis']
        report.append(f"### Gap Analysis")
        report.append(f"- Total gaps: {ga.get('total_gaps', 0)}")
        report.append(f"- Gap size: {ga.get('gap_size_bytes', 0)} bytes ({ga.get('gap_percentage', 0):.1f}%)")
        report.append("")
    
    # Extracted rules
    report.append(f"## Extracted Rules ({len(rules)} total)")
    report.append("")
    for i, rule in enumerate(rules[:20], 1):
        report.append(f"{i}. {rule.get('value', '')[:80]}")
    if len(rules) > 20:
        report.append(f"... and {len(rules) - 20} more")
    report.append("")
    
    # Validation results
    report.append("## Validation Results")
    report.append(f"- Rules validated: {validation.get('validated', 0)}")
    report.append(f"- Not found in OCR: {validation.get('not_found_in_ocr', 0)}")
    if validation.get('matches'):
        report.append(f"- Sample matches: {', '.join(validation['matches'][:3])}")
    report.append("")
    
    # Next steps
    report.append("## Next Steps")
    report.append("1. Manual review of extracted rules")
    report.append("2. Refine field boundary detection")
    report.append("3. Implement custom decoder for identified structures")
    report.append("4. Validate against application behavior")
    report.append("")
    
    return "\n".join(report)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Integrate and validate Phase 2 analysis'
    )
    parser.add_argument('--workspace', type=Path, default=Path.cwd(),
                       help='Workspace root directory')
    parser.add_argument('--reports-dir', type=Path,
                       help='Reports directory (auto-detect if not specified)')
    parser.add_argument('--ocr-file', type=Path,
                       help='OCR JSON file for validation')
    parser.add_argument('--out', type=Path,
                       help='Output JSON file')
    parser.add_argument('--out-md', type=Path,
                       help='Output Markdown file')
    
    args = parser.parse_args(argv)
    
    # Auto-detect reports directory
    reports_dir = args.reports_dir or args.workspace / 'reports'
    if not reports_dir.exists():
        print(f"Error: Reports directory not found: {reports_dir}", file=sys.stderr)
        return 1
    
    print(f"Loading Phase 2 analysis results from {reports_dir}", file=sys.stderr)
    
    # Load all Phase 2 outputs
    print("  - Loading block structure analysis...", file=sys.stderr)
    block_data = load_json_file(reports_dir / 'block_structure_analysis.json')
    
    print("  - Loading pointer network analysis...", file=sys.stderr)
    pointer_data = load_json_file(reports_dir / 'pointer_network.json')
    
    print("  - Loading size field analysis...", file=sys.stderr)
    size_data = load_json_file(reports_dir / 'size_fields.json')
    
    print("  - Loading gap analysis...", file=sys.stderr)
    gap_data = load_json_file(reports_dir / 'gap_details.json')
    
    # Integrate findings
    print("  - Integrating findings...", file=sys.stderr)
    integration = {
        'block_structure': integrate_block_structure(block_data),
        'pointer_network': integrate_pointer_network(pointer_data),
        'size_fields': integrate_size_fields(size_data),
        'gap_analysis': integrate_gap_analysis(gap_data),
    }
    
    # Extract rules
    print("  - Extracting rules...", file=sys.stderr)
    rules = extract_rules_from_analysis(block_data, pointer_data, size_data)
    
    # Validate
    print("  - Validating against OCR...", file=sys.stderr)
    validation = validate_against_ocr(rules, args.ocr_file)
    
    # Generate report
    report_md = generate_comprehensive_report(integration, rules, validation)
    
    results = {
        'phase': 2,
        'stage': 'unified_integration',
        'integration_summary': integration,
        'rules_extracted': len(rules),
        'sample_rules': rules[:50],
        'validation': validation,
    }
    
    # Output JSON
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON output: {args.out}", file=sys.stderr)
    
    # Output Markdown
    if args.out_md:
        with open(args.out_md, 'w') as f:
            f.write(report_md)
        print(f"Markdown output: {args.out_md}", file=sys.stderr)
    
    # Also print to console
    print("\n=== UNIFIED INTEGRATION SUMMARY ===", file=sys.stderr)
    for section, data in integration.items():
        print(f"\n{section}:")
        for key, value in data.items():
            print(f"  {key}: {value}")
    
    print(f"\nRules extracted: {len(rules)}")
    print(f"Validation status: {validation.get('status', 'unknown')}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
