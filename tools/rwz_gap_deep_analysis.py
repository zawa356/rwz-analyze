#!/usr/bin/env python3
"""
RWZ ギャップ領域深掘り分析ツール
==================================
作成者: GitHub Copilot (2026-02-03)
目的: ギャップ領域に隠れたMS Outlookルール分岐条件の検出

分析項目:
1. 30個の最大ギャップの詳細バイト分析
2. ビットパターン・フラグ候補の検出
3. ギャップ前後のコンテキスト分析
4. ルール適用条件の推測
5. ギャップとポインタ/ブロックの関連性
"""

import argparse
import json
import struct
import sys
import math
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter


def find_top_gaps(data: bytes, count: int = 30) -> List[Dict]:
    """ファイルから上位Nのギャップを抽出"""
    gaps = []
    in_gap = False
    gap_start = 0
    
    for offset in range(len(data)):
        is_null = data[offset] == 0
        
        if is_null and not in_gap:
            gap_start = offset
            in_gap = True
        elif not is_null and in_gap:
            gap_size = offset - gap_start
            if gap_size >= 4:
                gaps.append({
                    'start': gap_start,
                    'end': offset,
                    'size': gap_size,
                    'data': data[gap_start:offset],
                })
            in_gap = False
    
    if in_gap:
        gap_size = len(data) - gap_start
        if gap_size >= 4:
            gaps.append({
                'start': gap_start,
                'end': len(data),
                'size': gap_size,
                'data': data[gap_start:],
            })
    
    return sorted(gaps, key=lambda x: -x['size'])[:count]


def analyze_gap_context(data: bytes, gap: Dict) -> Dict:
    """ギャップ前後のコンテキスト分析"""
    context = {
        'gap_start': gap['start'],
        'gap_end': gap['end'],
        'gap_size': gap['size'],
        'before_context': None,
        'after_context': None,
        'nearby_pointers': [],
        'nearby_strings': [],
    }
    
    # 前のコンテキスト（16バイト）
    if gap['start'] >= 16:
        before = data[gap['start']-16:gap['start']]
        context['before_context'] = {
            'hex': before.hex(),
            'dwords': [struct.unpack('<I', before[i:i+4])[0] for i in range(0, 16, 4)],
            'printable': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in before),
        }
    
    # 後のコンテキスト（16バイト）
    if gap['end'] + 16 <= len(data):
        after = data[gap['end']:gap['end']+16]
        context['after_context'] = {
            'hex': after.hex(),
            'dwords': [struct.unpack('<I', after[i:i+4])[0] for i in range(0, min(16, len(after)), 4)],
            'printable': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in after),
        }
    
    return context


def analyze_gap_bitpatterns(gap_data: bytes) -> Dict:
    """ギャップ内のビットパターン分析"""
    analysis = {
        'total_bytes': len(gap_data),
        'byte_distribution': {},
        'bit_patterns': [],
        'repeating_sequences': [],
        'entropy': 0.0,
    }
    
    # バイト分布
    counts = Counter(gap_data)
    analysis['byte_distribution'] = {
        'null_bytes': counts.get(0, 0),
        'non_null_bytes': len(gap_data) - counts.get(0, 0),
        'unique_values': len(counts),
        'common_bytes': counts.most_common(5),
    }
    
    # ビットパターンの統計
    bit_patterns = {}
    for byte_val in counts.keys():
        bit_str = format(byte_val, '08b')
        if bit_str not in bit_patterns:
            bit_patterns[bit_str] = 0
        bit_patterns[bit_str] += counts[byte_val]
    
    analysis['bit_patterns'] = sorted(
        bit_patterns.items(),
        key=lambda x: -x[1]
    )[:10]
    
    # 繰り返しパターンの検出
    repeating = _detect_repeating_patterns(gap_data)
    analysis['repeating_sequences'] = repeating
    
    # エントロピー計算
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / len(gap_data)
            entropy -= p * math.log2(p)
    analysis['entropy'] = entropy
    
    return analysis


def _detect_repeating_patterns(data: bytes, min_length: int = 1, max_length: int = 8) -> List[Dict]:
    """繰り返しパターンの検出"""
    patterns = []
    
    for length in range(min_length, min(max_length + 1, len(data) // 2)):
        pattern_counts = defaultdict(int)
        
        for i in range(len(data) - length + 1):
            pattern = data[i:i+length]
            pattern_counts[pattern] += 1
        
        for pattern, count in pattern_counts.items():
            if count >= 3:  # 3回以上繰り返し
                patterns.append({
                    'pattern': pattern.hex(),
                    'length': length,
                    'count': count,
                    'percentage': (count * length / len(data)) * 100,
                })
    
    return sorted(patterns, key=lambda x: -x['count'])[:20]


def infer_branching_logic(gap: Dict, context: Dict, bitanalysis: Dict) -> Dict:
    """ギャップから分岐ロジックを推測"""
    inferences = {
        'potential_flags': [],
        'rule_conditions': [],
        'condition_priority': [],
        'confidence_score': 0.0,
    }
    
    # フラグ候補の検出
    byte_dist = bitanalysis['byte_distribution']
    if byte_dist['non_null_bytes'] > 0 and byte_dist['non_null_bytes'] < byte_dist['total_bytes'] * 0.1:
        # スパース（少数の非ゼロバイト）→ フラグバイト候補
        inferences['potential_flags'].append({
            'type': 'sparse_flags',
            'confidence': 0.8,
            'description': f"{byte_dist['non_null_bytes']}バイトの非ゼロデータ（全体の{(byte_dist['non_null_bytes']/byte_dist['total_bytes'])*100:.1f}%）",
        })
    
    # ビットマスク候補
    if bitanalysis['bit_patterns']:
        common_pattern = bitanalysis['bit_patterns'][0][0]
        if common_pattern.count('0') == 7 and common_pattern.count('1') == 1:
            # 単一ビットフラグ
            inferences['potential_flags'].append({
                'type': 'single_bit_flags',
                'confidence': 0.85,
                'pattern': common_pattern,
                'description': 'ビット位置毎のフラグパターン検出',
            })
    
    # ルール条件候補
    if gap['size'] >= 4:
        # 4バイト以上 → DWORD条件フィールド
        inferences['rule_conditions'].append({
            'type': 'dword_conditions',
            'offset': gap['start'],
            'size': min(gap['size'], 4),
            'confidence': 0.7,
        })
    
    if gap['size'] >= 8:
        # 8バイト以上 → ポインタペア（条件+値）
        inferences['rule_conditions'].append({
            'type': 'pointer_pair',
            'offset': gap['start'],
            'size': 8,
            'confidence': 0.65,
        })
    
    # 優先度推測
    if byte_dist['non_null_bytes'] > 0:
        inferences['condition_priority'] = [
            {'priority': 1, 'field': f'offset {gap["start"]:08x}', 'size': gap['size']},
        ]
    
    # 信頼度スコア計算
    score = 0.0
    if bitanalysis['entropy'] < 1.0:  # 低エントロピー = 構造化
        score += 0.3
    if byte_dist['non_null_bytes'] > 0 and byte_dist['non_null_bytes'] <= gap['size'] * 0.15:
        score += 0.4  # スパースデータ
    if len(bitanalysis['repeating_sequences']) > 0:
        score += 0.3  # 繰り返しパターン
    
    inferences['confidence_score'] = min(1.0, score)
    
    return inferences


def analyze_gap_block_relationships(data: bytes, gap: Dict) -> Dict:
    """ギャップとポインタ/ブロック関連性の分析"""
    relationships = {
        'nearby_blocks': [],
        'block_offsets': [],
        'pointer_references': [],
    }
    
    # 192バイトブロック境界との関連性
    BLOCK_SIZE = 192
    gap_start_block = gap['start'] // BLOCK_SIZE
    gap_end_block = gap['end'] // BLOCK_SIZE
    
    if gap_start_block == gap_end_block:
        relationships['block_offsets'].append({
            'block_number': gap_start_block,
            'offset_in_block': gap['start'] % BLOCK_SIZE,
            'size': gap['size'],
            'position': 'within_block',
        })
    else:
        relationships['block_offsets'].append({
            'start_block': gap_start_block,
            'end_block': gap_end_block,
            'position': 'cross_blocks',
        })
    
    # ギャップ前後の192バイトブロック内容チェック
    for offset in [gap['start'] - BLOCK_SIZE, gap['end'] + BLOCK_SIZE]:
        if 0 <= offset < len(data):
            block_num = offset // BLOCK_SIZE
            relationships['nearby_blocks'].append({
                'block': block_num,
                'offset': offset,
            })
    
    return relationships


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='ギャップ領域深掘り分析')
    parser.add_argument('rwz_file', help='RWZファイルのパス')
    parser.add_argument('--out', help='出力JSONファイル')
    parser.add_argument('--out-md', help='出力Markdownファイル')
    parser.add_argument('--gap-count', type=int, default=30, help='分析するギャップ数')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"エラー: {rwz_path} が見つかりません", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        data = f.read()
    
    print(f"分析中: {rwz_path} ({len(data)} バイト)", file=sys.stderr)
    
    # ギャップ抽出
    print(f"  - 上位{args.gap_count}個のギャップを抽出...", file=sys.stderr)
    top_gaps = find_top_gaps(data, args.gap_count)
    print(f"    {len(top_gaps)}個のギャップを特定", file=sys.stderr)
    
    # 詳細分析
    print("  - 各ギャップの詳細分析中...", file=sys.stderr)
    analyzed_gaps = []
    
    for gap in top_gaps:
        analysis = {
            'gap_info': {
                'start': gap['start'],
                'start_hex': f'0x{gap["start"]:08x}',
                'end': gap['end'],
                'end_hex': f'0x{gap["end"]:08x}',
                'size': gap['size'],
            },
            'context': analyze_gap_context(data, gap),
            'bitanalysis': analyze_gap_bitpatterns(gap['data']),
            'branching_inference': None,
            'block_relationships': analyze_gap_block_relationships(data, gap),
        }
        
        # 分岐ロジック推測
        inference = infer_branching_logic(
            gap,
            analysis['context'],
            analysis['bitanalysis']
        )
        analysis['branching_inference'] = inference
        
        analyzed_gaps.append(analysis)
    
    results = {
        'file': str(rwz_path),
        'total_gaps': len(top_gaps),
        'gap_analysis': analyzed_gaps,
        'summary': {
            'gaps_with_flags': sum(1 for g in analyzed_gaps if g['branching_inference']['potential_flags']),
            'gaps_with_conditions': sum(1 for g in analyzed_gaps if g['branching_inference']['rule_conditions']),
            'high_confidence': sum(1 for g in analyzed_gaps if g['branching_inference']['confidence_score'] > 0.7),
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
            f.write("# ギャップ領域深掘り分析報告書\n\n")
            f.write(f"## 概要\n")
            f.write(f"- 分析ギャップ数: {len(top_gaps)}\n")
            f.write(f"- フラグ候補検出: {results['summary']['gaps_with_flags']}個\n")
            f.write(f"- 分岐条件候補: {results['summary']['gaps_with_conditions']}個\n")
            f.write(f"- 高信頼度（>0.7）: {results['summary']['high_confidence']}個\n\n")
            
            f.write("## 詳細分析結果\n\n")
            for i, gap in enumerate(analyzed_gaps, 1):
                gap_info = gap['gap_info']
                inference = gap['branching_inference']
                
                f.write(f"### ギャップ #{i}\n")
                f.write(f"- **位置**: {gap_info['start_hex']}..{gap_info['end_hex']}\n")
                f.write(f"- **サイズ**: {gap_info['size']} バイト\n")
                f.write(f"- **信頼度スコア**: {inference['confidence_score']:.2f}\n\n")
                
                if inference['potential_flags']:
                    f.write("#### 検出されたフラグ候補\n")
                    for flag in inference['potential_flags']:
                        f.write(f"- **{flag['type']}**: {flag['description']} (信頼度: {flag['confidence']})\n")
                    f.write("\n")
                
                if inference['rule_conditions']:
                    f.write("#### ルール分岐条件候補\n")
                    for cond in inference['rule_conditions']:
                        f.write(f"- **{cond['type']}** (信頼度: {cond['confidence']})\n")
                    f.write("\n")
                
                bitanalysis = gap['bitanalysis']
                f.write(f"#### バイト統計\n")
                f.write(f"- ゼロバイト: {bitanalysis['byte_distribution']['null_bytes']}\n")
                f.write(f"- 非ゼロバイト: {bitanalysis['byte_distribution']['non_null_bytes']}\n")
                f.write(f"- ユニーク値: {bitanalysis['byte_distribution']['unique_values']}\n")
                f.write(f"- エントロピー: {bitanalysis['entropy']:.3f}\n\n")
                
                if bitanalysis['repeating_sequences']:
                    f.write(f"#### 繰り返しパターン (上位3)\n")
                    for pattern in bitanalysis['repeating_sequences'][:3]:
                        f.write(f"- `{pattern['pattern']}`: {pattern['count']}回 ({pattern['percentage']:.1f}%)\n")
                    f.write("\n")
                
                f.write("---\n\n")
        
        print(f"Markdown出力: {md_path}", file=sys.stderr)
    
    print("\n=== 分析完了 ===", file=sys.stderr)
    print(f"分析対象ギャップ: {len(top_gaps)}")
    print(f"フラグ候補検出: {results['summary']['gaps_with_flags']}個")
    print(f"分岐条件候補: {results['summary']['gaps_with_conditions']}個")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
