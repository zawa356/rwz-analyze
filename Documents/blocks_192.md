# 192バイトブロック構造

## 事実（観測結果）

- 192バイト固定長ブロックが **452個** 検出されている。
- ブロック内に **UTF-16LE 文字列断片**が観測される。
- ブロック内フィールド境界候補が **30箇所** 抽出されている。
- 8バイトのメタデータマーカー（`01 00 00 00 00 00 00 00`）が特定パターンとして検出されている。
- 繰り返しパターンが **20種類** 報告されている。

出典: `reports/phase2/PHASE2_FINAL_REPORT.md`, `reports/phase2/block_structure_analysis.*`, `reports/phase2/format_detection.*`

### メタデータマーカーの出現数（事実・報告値）

- マーカー `01 00 00 00 00 00 00 00` が **751回** 観測されたと報告されている。

出典: `reports/phase2/format_detection.md`, `reports/phase2/COPILOT_SESSION_REPORT.md`

## 推測（フィールド配置）

ブロックは次のような「固定オフセット + 可変参照」の構成を持つ可能性が高い。

```
0x00 ┌──────────────────────────────────────────────┐
     │  [DWORD] rule_type_identifier (?)            │  ← 推測
0x20 │  [DWORD] rule_enable_disable (?)             │  ← 推測
0x24 │  [DWORD] rule_action_type (?)                │  ← 推測
0x28 │  [DWORD] rule_priority_or_order (?)          │  ← 推測
     │  [DWORD ptr] string/structure references     │  ← 推測
     │  [DWORD size] size-field candidates          │  ← 推測
0xC0 └──────────────────────────────────────────────┘
```

※ 上記の意味付けは **フラグ検出ツールの推測結果**に基づく仮説です。

## 検証方法

- ルールの有効/無効をUIで切り替えた RWZ を比較し、
  ブロック内の差分がオフセット 0x20 に集中するかを確認。
- ルール順序の変更 → オフセット 0x28 の差分確認。
- 「アクション変更（移動/削除など）」 → オフセット 0x24 の差分確認。
- メタデータマーカーの位置とブロック境界の対応を検証。

## 参考レポート

- `reports/phase2/block_structure_analysis.json`
- `reports/phase2/block_structure_analysis.md`
- `reports/phase2/block_flags_analysis.md`
- `reports/phase2/format_detection.md`
