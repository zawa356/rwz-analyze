#!/usr/bin/env python3
"""
RWZ ブロック内フラグ・条件検出ツール
=====================================
作成者: GitHub Copilot (2026-02-03)
目的: 192バイトブロック内に隠れたMS Outlookルール分岐条件を検出

分析項目:
1. ブロック内の構造化フィールド分析
2. フラグビット位置の推定
3. 条件マスク（AND/OR演算）のパターン検出
4. ルール優先度フィールドの推測
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from collections import Counter


def analyze_block_flags(blocks: List[bytes], sample_size: int = 10) -> Dict:
    """ブロック内のフラグパターンを分析"""
    analysis = {
        'blocks_analyzed': min(sample_size, len(blocks)),
        'flag_candidates': [],
        'bit_patterns': {},
        'field_signatures': [],
    }
    
    for block_idx, block in enumerate(blocks[:sample_size]):
        # オフセット毎のバイト値の分布
        for offset in range(0, min(len(block), 48), 4):
            region = block[offset:offset+4]
            if len(region) == 4:
                val = struct.unpack('<I', region)[0]
                
                # 0x00000001 パターン（フラグビット）
                if val in [0x00000001, 0x00000100, 0x00010000, 0x01000000]:
                    if offset not in [c['offset'] for c in analysis['flag_candidates']]:
                        analysis['flag_candidates'].append({
                            'offset': offset,
                            'pattern': f'0x{val:08x}',
                            'interpretation': _interpret_flag_value(val),
                            'occurrences': 1,
                        })
    
    # フラグ候補の出現回数をカウント
    flag_counts = Counter()
    for block in blocks:
        for flag_cand in analysis['flag_candidates']:
            offset = flag_cand['offset']
            if offset + 4 <= len(block):
                val = struct.unpack('<I', block[offset:offset+4])[0]
                if val in [0x00000001, 0x00000100, 0x00010000, 0x01000000]:
                    flag_counts[offset] += 1
    
    # 更新
    for cand in analysis['flag_candidates']:
        cand['occurrences'] = flag_counts.get(cand['offset'], 0)
    
    return analysis


def _interpret_flag_value(val: int) -> str:
    """フラグ値の解釈"""
    if val == 0x00000001:
        return "single_bit_0"
    elif val == 0x00000100:
        return "single_bit_8"
    elif val == 0x00010000:
        return "single_bit_16"
    elif val == 0x01000000:
        return "single_bit_24"
    else:
        return f"bit_pattern_{val:08x}"


def analyze_condition_fields(blocks: List[bytes], sample_size: int = 10) -> Dict:
    """条件フィールド（DWORD）を分析"""
    analysis = {
        'blocks_analyzed': min(sample_size, len(blocks)),
        'condition_fields': [],
        'field_patterns': {},
        'priority_candidates': [],
    }
    
    condition_value_counts = Counter()
    
    for block in blocks[:sample_size]:
        # オフセット32-48は条件フィールドの可能性が高い
        for offset in range(32, min(len(block) - 3, 48), 4):
            val = struct.unpack('<I', block[offset:offset+4])[0]
            
            # 条件値として妥当な範囲
            if 0 < val < 1000:
                condition_value_counts[val] += 1
    
    # 頻出値 = 条件値の可能性
    for val, count in condition_value_counts.most_common(10):
        analysis['priority_candidates'].append({
            'value': val,
            'occurrences': count,
            'interpretation': _interpret_condition_value(val),
        })
    
    return analysis


def _interpret_condition_value(val: int) -> str:
    """条件値の解釈"""
    interpretations = []
    
    if val == 0:
        return "no_condition"
    elif val == 1:
        interpretations.append("priority_1_highest")
    elif val <= 100:
        interpretations.append(f"rule_priority_{val}")
    
    if val <= 10:
        interpretations.append("likely_flag_count")
    
    if bin(val).count('1') <= 3:
        interpretations.append("possible_bitmask")
    
    return " | ".join(interpretations) if interpretations else "unknown_condition"


def detect_rule_logic_patterns(blocks: List[bytes]) -> Dict:
    """ルール適用ロジックのパターン検出"""
    patterns = {
        'and_logic': 0,
        'or_logic': 0,
        'not_logic': 0,
        'bitwise_patterns': [],
        'sequence_patterns': [],
    }
    
    # サンプルブロックを分析
    for block in blocks[:20]:
        # 連続する同じバイト = 可能性のあるマスク
        current_byte = None
        sequence = []
        
        for byte in block:
            if byte == current_byte:
                sequence.append(byte)
            else:
                if len(sequence) >= 4 and sequence[0] != 0:
                    patterns['sequence_patterns'].append({
                        'value': sequence[0],
                        'length': len(sequence),
                        'pattern': f'0x{sequence[0]:02x}' + f" * {len(sequence)}",
                    })
                current_byte = byte
                sequence = [byte]
    
    return patterns


def extract_flag_locations(block_structure_json: Path) -> Dict:
    """既存のブロック構造分析からフラグ位置を抽出"""
    locations = {
        'known_flags': [],
        'metadata_offsets': [],
        'field_boundaries': [],
    }
    
    try:
        with open(block_structure_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # フィールド境界から推測
        if 'field_boundaries' in data:
            for boundary in data['field_boundaries'][:5]:
                offset = boundary.get('offset', 0)
                size = boundary.get('size', 1)
                locations['field_boundaries'].append({
                    'offset': offset,
                    'size': size,
                })
        
        # メタデータパターンの位置
        if 'repeating_patterns' in data:
            for pattern in data['repeating_patterns']:
                if '0001' in pattern.get('pattern', ''):
                    locations['known_flags'].append({
                        'pattern': pattern['pattern'],
                        'occurrences': pattern.get('occurrences', 0),
                    })
    except:
        pass
    
    return locations


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='ブロック内フラグ・条件検出')
    parser.add_argument('rwz_file', help='RWZファイルのパス')
    parser.add_argument('--out', help='出力JSONファイル')
    parser.add_argument('--out-md', help='出力Markdownファイル')
    parser.add_argument('--block-structure', type=Path, help='ブロック構造分析JSON')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"エラー: {rwz_path} が見つかりません", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    # 192バイトブロックを抽出
    BLOCK_SIZE = 192
    blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE) if i + BLOCK_SIZE <= len(data)]
    
    print(f"分析中: {len(blocks)}個の192バイトブロック", file=sys.stderr)
    
    # 分析実行
    print("  - ブロック内フラグ検出...", file=sys.stderr)
    flag_analysis = analyze_block_flags(blocks)
    
    print("  - 条件フィールド分析...", file=sys.stderr)
    condition_analysis = analyze_condition_fields(blocks)
    
    print("  - ルールロジックパターン検出...", file=sys.stderr)
    logic_patterns = detect_rule_logic_patterns(blocks)
    
    print("  - 既存分析結果との統合...", file=sys.stderr)
    flag_locations = extract_flag_locations(args.block_structure or 
                                           Path('reports/block_structure_analysis.json'))
    
    results = {
        'file': str(rwz_path),
        'blocks_analyzed': len(blocks),
        'flag_analysis': flag_analysis,
        'condition_analysis': condition_analysis,
        'logic_patterns': logic_patterns,
        'flag_locations': flag_locations,
        'summary': {
            'flag_candidates': len(flag_analysis['flag_candidates']),
            'condition_fields': len(condition_analysis['priority_candidates']),
            'logic_patterns_found': len(logic_patterns['sequence_patterns']),
        }
    }
    
    # JSON出力
    if args.out:
        out_path = Path(args.out)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"JSON出力: {out_path}", file=sys.stderr)
    
    # Markdown出力
    if args.out_md:
        md_path = Path(args.out_md)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# 192バイトブロック内 フラグ・条件検出報告書\n\n")
            
            f.write("## 概要\n")
            f.write(f"- 分析ブロック数: {len(blocks)}\n")
            f.write(f"- フラグ候補: {len(flag_analysis['flag_candidates'])}個\n")
            f.write(f"- 条件フィールド候補: {len(condition_analysis['priority_candidates'])}個\n")
            f.write(f"- ルールロジック: {len(logic_patterns['sequence_patterns'])}パターン\n\n")
            
            if flag_analysis['flag_candidates']:
                f.write("## 検出されたフラグ候補\n\n")
                for flag in flag_analysis['flag_candidates']:
                    f.write(f"### オフセット 0x{flag['offset']:02x}\n")
                    f.write(f"- **パターン**: {flag['pattern']}\n")
                    f.write(f"- **タイプ**: {flag['interpretation']}\n")
                    f.write(f"- **出現回数**: {flag['occurrences']}ブロック\n\n")
            
            if condition_analysis['priority_candidates']:
                f.write("## 条件フィールド候補\n\n")
                for cond in condition_analysis['priority_candidates'][:5]:
                    f.write(f"- **値**: {cond['value']}\n")
                    f.write(f"  - **出現回数**: {cond['occurrences']}\n")
                    f.write(f"  - **解釈**: {cond['interpretation']}\n\n")
            
            if logic_patterns['sequence_patterns']:
                f.write("## ルール適用ロジック候補\n\n")
                for pattern in logic_patterns['sequence_patterns'][:10]:
                    f.write(f"- パターン: {pattern['pattern']} (長さ: {pattern['length']})\n")
        
        print(f"Markdown出力: {md_path}", file=sys.stderr)
    
    print("\n=== 分析完了 ===", file=sys.stderr)
    print(f"ブロック分析: {len(blocks)}個")
    print(f"フラグ候補: {len(flag_analysis['flag_candidates'])}個")
    print(f"条件候補: {len(condition_analysis['priority_candidates'])}個")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
