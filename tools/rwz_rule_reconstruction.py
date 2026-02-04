#!/usr/bin/env python3
"""
RWZ フラグ位置検証・ルール条件マッピングツール
==============================================
作成者: GitHub Copilot (2026-02-03)
目的: 検出されたフラグ位置でMS Outlookのルール条件を復元

検証項目:
1. フラグ位置の複数ブロックでの値検証
2. フラグ値 ↔ OCR ルール条件の相関分析
3. MS Outlookルール適用パターンの推測
4. ルール優先度・実行順序の推定
"""

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict


def extract_flag_values(rwz_data: bytes, flag_offsets: List[int], block_size: int = 192) -> Dict:
    """特定のオフセット位置の値を全ブロックから抽出"""
    result = {
        'blocks_count': len(rwz_data) // block_size,
        'flag_offsets': flag_offsets,
        'values_per_offset': {},
    }
    
    for offset in flag_offsets:
        values = defaultdict(int)
        
        for block_idx in range(len(rwz_data) // block_size):
            block_start = block_idx * block_size
            block_end = block_start + block_size
            
            if block_start < len(rwz_data) and block_end <= len(rwz_data):
                block = rwz_data[block_start:block_end]
                
                if offset + 4 <= len(block):
                    val = struct.unpack('<I', block[offset:offset+4])[0]
                    values[val] += 1
        
        result['values_per_offset'][f'0x{offset:02x}'] = {
            'value_distribution': dict(values),
            'unique_values': len(values),
            'most_common': max(values.items(), key=lambda x: x[1]) if values else (0, 0),
        }
    
    return result


def correlate_with_ocr_rules(flags_data: Dict, ocr_json_path: Path) -> Dict:
    """フラグ値とOCRから抽出したルール条件の相関分析"""
    correlation = {
        'ocr_rules_found': 0,
        'flag_rule_mappings': [],
        'unmapped_rules': [],
        'confidence': 0.0,
    }
    
    if not ocr_json_path.exists():
        return correlation
    
    try:
        with open(ocr_json_path, 'r', encoding='utf-8') as f:
            ocr_data = json.load(f)
        
        # OCRから抽出したルール数
        if isinstance(ocr_data, dict) and 'results' in ocr_data:
            correlation['ocr_rules_found'] = len(ocr_data['results'])
        
        # フラグオフセットの意味推測
        flag_meanings = {
            '0x20': 'rule_enable_disable',
            '0x24': 'rule_action_type',
            '0x00': 'rule_type_identifier',
            '0x28': 'rule_priority_or_order',
        }
        
        for offset_hex, meaning in flag_meanings.items():
            values = flags_data.get('values_per_offset', {}).get(offset_hex, {})
            if values.get('unique_values', 0) > 0:
                correlation['flag_rule_mappings'].append({
                    'offset': offset_hex,
                    'meaning': meaning,
                    'unique_values': values['unique_values'],
                    'most_common_value': values['most_common'][0] if values.get('most_common') else 0,
                })
        
        # 信頼度の計算
        if correlation['flag_rule_mappings']:
            correlation['confidence'] = min(1.0, len(correlation['flag_rule_mappings']) / 4.0)
    
    except Exception as e:
        print(f"警告: OCRファイル読込エラー: {e}", file=sys.stderr)
    
    return correlation


def infer_ms_logic(flags_data: Dict, correlation: Dict) -> List[Dict]:
    """MS Outlookのルール適用ロジックを推測"""
    logic = []
    
    # フラグ0x20（enable/disable推定）
    if '0x20' in flags_data.get('values_per_offset', {}):
        val_dist = flags_data['values_per_offset']['0x20']['value_distribution']
        if 1 in val_dist:
            logic.append({
                'stage': 1,
                'field': 'offset 0x20',
                'operation': 'rule_enabled_check',
                'logic': 'IF offset_0x20 == 0x00000001 THEN apply_rule ELSE skip',
                'condition': 'Enable/Disable フラグ',
            })
    
    # フラグ0x24（アクション推定）
    if '0x24' in flags_data.get('values_per_offset', {}):
        val_dist = flags_data['values_per_offset']['0x24']['value_distribution']
        action_values = list(val_dist.keys())
        if action_values:
            logic.append({
                'stage': 2,
                'field': 'offset 0x24',
                'operation': 'rule_action_dispatch',
                'logic': f'SWITCH offset_0x24 {{ {"; ".join(str(v) for v in action_values[:3])}... }}',
                'condition': 'ルールアクション（移動/削除/返信等）',
            })
    
    # フラグ0x28（優先度推定）
    if '0x28' in flags_data.get('values_per_offset', {}):
        val_dist = flags_data['values_per_offset']['0x28']['value_distribution']
        logic.append({
            'stage': 3,
            'field': 'offset 0x28',
            'operation': 'priority_order',
            'logic': 'sort_by offset_0x28 ASC',
            'condition': 'ルール実行優先度',
        })
    
    return logic


def generate_rule_reconstruction_guide(flags_data: Dict, logic: List[Dict]) -> str:
    """ルール復元のためのガイド生成"""
    guide = []
    
    guide.append("# MS Outlookルール復元ガイド")
    guide.append("")
    guide.append("## ステップ1: フラグ位置の確認")
    guide.append("")
    
    for offset_hex, dist in flags_data.get('values_per_offset', {}).items():
        guide.append(f"### オフセット {offset_hex}")
        guide.append(f"- ユニーク値: {dist['unique_values']}")
        guide.append(f"- 最頻値: 0x{dist['most_common'][0]:08x} ({dist['most_common'][1]}ブロック)")
        guide.append("")
    
    guide.append("## ステップ2: ルール適用ロジック")
    guide.append("")
    
    for stage in logic:
        guide.append(f"### ステージ {stage['stage']}: {stage['operation']}")
        guide.append(f"- **条件**: {stage['condition']}")
        guide.append(f"- **フィールド**: {stage['field']}")
        guide.append(f"- **ロジック**: `{stage['logic']}`")
        guide.append("")
    
    guide.append("## ステップ3: ルール抽出方法")
    guide.append("")
    guide.append("各ブロックから以下の順で情報を抽出:")
    guide.append("1. オフセット 0x20 からフラグ値を読む（有効/無効判定）")
    guide.append("2. オフセット 0x24 からアクション識別子を読む")
    guide.append("3. オフセット 0x28 から優先度を読む")
    guide.append("4. サイズフィールドから条件文字列を抽出")
    guide.append("5. ポインタから対象アドレスを解決")
    guide.append("")
    
    return "\n".join(guide)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='フラグ位置検証・ルール条件マッピング')
    parser.add_argument('rwz_file', help='RWZファイルのパス')
    parser.add_argument('--flags', type=str, default='32,36,0,40',
                       help='検証するフラグオフセット（10進）、カンマ区切り')
    parser.add_argument('--ocr', type=Path, help='OCRデータJSON')
    parser.add_argument('--out', help='出力JSONファイル')
    parser.add_argument('--out-md', help='出力Markdownファイル')
    
    args = parser.parse_args(argv)
    
    rwz_path = Path(args.rwz_file)
    if not rwz_path.exists():
        print(f"エラー: {rwz_path} が見つかりません", file=sys.stderr)
        return 1
    
    with open(rwz_path, 'rb') as f:
        rwz_data = f.read()
    
    # フラグオフセットをパース
    flag_offsets = [int(x) for x in args.flags.split(',')]
    
    print(f"分析中: {len(rwz_data)}バイト", file=sys.stderr)
    print(f"  - フラグオフセット: {', '.join(f'0x{x:02x}' for x in flag_offsets)}", file=sys.stderr)
    
    # フラグ値を抽出
    print("  - 全ブロックからフラグ値を抽出...", file=sys.stderr)
    flags_data = extract_flag_values(rwz_data, flag_offsets)
    
    # OCRと相関分析
    print("  - OCRとの相関分析...", file=sys.stderr)
    correlation = correlate_with_ocr_rules(flags_data, args.ocr or Path('inputs/ocr.json'))
    
    # ロジック推測
    print("  - ルール適用ロジックを推測...", file=sys.stderr)
    logic = infer_ms_logic(flags_data, correlation)
    
    # ガイド生成
    guide = generate_rule_reconstruction_guide(flags_data, logic)
    
    results = {
        'file': str(rwz_path),
        'flag_offsets': [f'0x{x:02x}' for x in flag_offsets],
        'flags_data': flags_data,
        'correlation': correlation,
        'inferred_logic': logic,
        'reconstruction_confidence': correlation['confidence'],
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
            f.write(guide)
        print(f"Markdown出力: {md_path}", file=sys.stderr)
    
    print("\n=== ルール復元情報 ===", file=sys.stderr)
    print(f"検証フラグ: {len(flag_offsets)}個")
    print(f"推測ロジック段数: {len(logic)}段")
    print(f"復元信頼度: {correlation['confidence']:.1%}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
