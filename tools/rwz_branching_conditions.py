#!/usr/bin/env python3
"""
RWZ 分岐条件抽出ツール
=======================
作成者: GitHub Copilot (2026-02-03)
目的: ギャップから検出したフラグ・条件パターンの詳細分析

分析項目:
1. ギャップ内のビットフラグパターン抽出
2. DWORD条件フィールドの検証
3. ルール適用ロジックの推測
4. 条件優先度の分析
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Set, Optional


def extract_flag_patterns(gap_data: bytes) -> List[Dict]:
    """ギャップから抽出可能なフラグパターンの列挙"""
    patterns = []
    
    # 1バイトフラグパターン
    if len(gap_data) >= 1:
        byte_values = set(gap_data[::4])  # 4バイト間隔でサンプリング
        for val in byte_values:
            if val > 0:
                patterns.append({
                    'type': '1byte_flag',
                    'value': val,
                    'hex': f'0x{val:02x}',
                    'binary': format(val, '08b'),
                    'bit_positions': [i for i in range(8) if (val >> i) & 1],
                })
    
    # 4バイト条件フィールド
    if len(gap_data) >= 4:
        for offset in range(0, min(len(gap_data) - 3, 32), 4):
            val = struct.unpack('<I', gap_data[offset:offset+4])[0]
            if val > 0 and val < 100000:  # 妥当な範囲
                patterns.append({
                    'type': '4byte_dword',
                    'offset': offset,
                    'value': val,
                    'hex': f'0x{val:08x}',
                    'interpretation': _interpret_dword(val),
                })
    
    return patterns


def _interpret_dword(value: int) -> str:
    """DWORD値の解釈"""
    interpretations = []
    
    if value == 0:
        return "null_value"
    if value == 1:
        return "enable_flag"
    if value == 0xFFFFFFFF:
        return "all_bits_set"
    
    # ビット数カウント
    bit_count = bin(value).count('1')
    interpretations.append(f"{bit_count}_bits_set")
    
    # フラグとして
    if value < 256:
        interpretations.append("possible_flag_byte")
    
    # マスク値として
    if (value & 0xFF000000) == 0:
        interpretations.append("24bit_or_less")
    
    return " | ".join(interpretations)


def correlate_with_rules(gap_analysis_path: Optional[Path], 
                        block_structure_path: Optional[Path]) -> Dict:
    """ギャップ分析結果とブロック構造の相関分析"""
    correlations = {
        'gap_block_alignment': [],
        'flag_rule_mapping': [],
        'condition_chain': [],
    }
    
    if not gap_analysis_path or not gap_analysis_path.exists():
        return correlations
    
    try:
        with open(gap_analysis_path, 'r', encoding='utf-8') as f:
            gap_data = json.load(f)
        
        # ギャップ情報の相関分析
        for gap in gap_data.get('gap_analysis', [])[:10]:
            gap_info = gap['gap_info']
            inference = gap['branching_inference']
            
            if inference['potential_flags']:
                correlations['gap_block_alignment'].append({
                    'gap_position': gap_info['start_hex'],
                    'has_flags': True,
                    'flag_count': len(inference['potential_flags']),
                })
    except:
        pass
    
    return correlations


def generate_condition_hypothesis(gaps_analysis: Dict) -> List[Dict]:
    """ギャップ分析からMS Outlookルール条件の仮説生成"""
    hypotheses = []
    
    # ギャップの統計
    total_gaps = len(gaps_analysis.get('gap_analysis', []))
    high_conf = [g for g in gaps_analysis.get('gap_analysis', [])
                 if g['branching_inference']['confidence_score'] > 0.7]
    
    if high_conf:
        hypotheses.append({
            'hypothesis': 'ギャップにフラグフィールド存在',
            'evidence': f'{len(high_conf)}/{total_gaps} ギャップが高信頼度',
            'implication': 'ルール適用の有効/無効フラグが各ブロック後に存在',
            'priority': 'HIGH',
            'testable': True,
        })
    
    # 繰り返しパターン検出
    patterns_found = [g for g in gaps_analysis.get('gap_analysis', [])
                      if g['bitanalysis']['repeating_sequences']]
    if patterns_found:
        hypotheses.append({
            'hypothesis': '繰り返しビットパターン = 条件マスク',
            'evidence': f'{len(patterns_found)}個のギャップで繰り返しパターン検出',
            'implication': 'ビット位置ごとの条件フラグ（AND/OR 演算結果）',
            'priority': 'MEDIUM',
            'testable': True,
        })
    
    # スパースデータ検出
    sparse_gaps = []
    for g in gaps_analysis.get('gap_analysis', []):
        byte_dist = g['bitanalysis']['byte_distribution']
        total = g['bitanalysis'].get('total_bytes', g['gap_info']['size'])
        if byte_dist.get('non_null_bytes', 0) < total * 0.1:
            sparse_gaps.append(g)
    
    if sparse_gaps:
        hypotheses.append({
            'hypothesis': 'スパースバイト = 条件識別子',
            'evidence': f'{len(sparse_gaps)}個のギャップがスパースデータ',
            'implication': '各ブロックのルール条件を識別するユニークID',
            'priority': 'MEDIUM',
            'testable': True,
        })
    
    return hypotheses


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='分岐条件抽出ツール')
    parser.add_argument('gap_analysis_json', help='ギャップ深掘り分析JSONファイル')
    parser.add_argument('--out', help='出力JSONファイル')
    parser.add_argument('--out-md', help='出力Markdownファイル')
    
    args = parser.parse_args(argv)
    
    gap_path = Path(args.gap_analysis_json)
    if not gap_path.exists():
        print(f"エラー: {gap_path} が見つかりません", file=sys.stderr)
        return 1
    
    # ギャップ分析結果の読み込み
    print(f"分析中: {gap_path}", file=sys.stderr)
    with open(gap_path, 'r', encoding='utf-8') as f:
        gap_analysis = json.load(f)
    
    print("  - フラグパターンを抽出...", file=sys.stderr)
    
    # 各ギャップからフラグパターン抽出
    all_patterns = []
    for gap in gap_analysis.get('gap_analysis', []):
        if gap['gap_info']['size'] > 0:
            # ギャップデータは別途読み込む必要があるため、ここでは推測のみ
            patterns = gap['branching_inference']['potential_flags']
            all_patterns.extend(patterns)
    
    print(f"  - {len(all_patterns)}個のパターン候補を検出", file=sys.stderr)
    
    # 条件仮説を生成
    print("  - MS Outlookルール条件の仮説を生成...", file=sys.stderr)
    hypotheses = generate_condition_hypothesis(gap_analysis)
    
    results = {
        'analysis_file': str(gap_path),
        'summary': gap_analysis.get('summary', {}),
        'patterns_found': len(all_patterns),
        'hypotheses': hypotheses,
        'high_priority_gaps': [
            {
                'position': g['gap_info']['start_hex'],
                'size': g['gap_info']['size'],
                'confidence': g['branching_inference']['confidence_score'],
            }
            for g in gap_analysis.get('gap_analysis', [])
            if g['branching_inference']['confidence_score'] > 0.8
        ][:10],
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
            f.write("# MS Outlookルール分岐条件 仮説報告書\n\n")
            
            f.write("## 検出概要\n")
            f.write(f"- フラグパターン: {len(all_patterns)}個\n")
            f.write(f"- 生成仮説: {len(hypotheses)}個\n")
            f.write(f"- 高信頼度ギャップ: {len(results['high_priority_gaps'])}個\n\n")
            
            f.write("## 提示された仮説\n\n")
            for i, hyp in enumerate(hypotheses, 1):
                f.write(f"### 仮説 {i}: {hyp['hypothesis']}\n")
                f.write(f"- **優先度**: {hyp['priority']}\n")
                f.write(f"- **エビデンス**: {hyp['evidence']}\n")
                f.write(f"- **インプリケーション**: {hyp['implication']}\n")
                f.write(f"- **検証可能**: {'✓' if hyp['testable'] else '✗'}\n\n")
            
            f.write("## 最有力候補ギャップ (信頼度 > 0.8)\n\n")
            for gap in results['high_priority_gaps']:
                f.write(f"- {gap['position']}: {gap['size']}バイト (信頼度: {gap['confidence']:.2f})\n")
        
        print(f"Markdown出力: {md_path}", file=sys.stderr)
    
    print("\n=== 分析完了 ===", file=sys.stderr)
    print(f"パターン候補: {len(all_patterns)}個")
    print(f"仮説生成: {len(hypotheses)}個")
    print(f"テスト対象ギャップ: {len(results['high_priority_gaps'])}個")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
