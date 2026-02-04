# 構造概要

## 対象ファイル

- 入力: `inputs/無題.rwz`
- サイズ: **86,842 bytes**

## 事実（観測結果）

以下は Phase2 レポートの観測結果です。

- **解析カバレッジ**: 97.6%（84,801 bytes）
- **192バイトブロック**: 452個
- **ポインタ**: 4,093 個（チェーン 100 / クラスタ 162）
- **サイズフィールド**: 692 個（文字列抽出 2,328）
- **ギャップ**: 175 個 / 2,041 bytes（全て 0x00 埋め）

出典: `reports/phase2/PHASE2_FINAL_REPORT.md`

### バイナリ統計（事実）

- **エントロピー**: 4.763（中程度）
- **null バイト**: 36,269（41.76%）
- **UTF-16 領域**: 704
- **ASCII 領域**: 362

出典: `reports/phase2/COPILOT_SESSION_REPORT.md`, `reports/phase2/binary_structure.*`

## 推測（構造モデル）

RWZ は「固定長メタデータブロック + 可変長文字列領域 + ポインタ参照」で構成される
**ハイブリッド構造**の可能性が高い。

```
┌────────────────────────────────────────────┐
│ RWZ Container                              │
├────────────────────────────────────────────┤
│ 192-byte Block Pool (metadata)             │  ← 452 blocks
│  - fixed offsets / flags / pointers        │
├────────────────────────────────────────────┤
│ String Pool (size-bounded)                 │  ← 692 size fields
│  - UTF-16 / UTF-8                           │
├────────────────────────────────────────────┤
│ Padding / Alignment (null gaps)            │  ← 175 gaps
└────────────────────────────────────────────┘
```

## 検証方法（推測を事実化するための手順）

- 192バイトブロックからポインタ値を抽出し、指す先の文字列が
  `size_fields.json` の候補に一致するかを確認する。
- 複数 RWZ ファイルで同じブロックオフセットの値が変化するか比較する。
- Outlook UI で作成したルール差分と、ブロック内の差分を対応付ける。

## 参考レポート

- `reports/phase2/PHASE2_FINAL_REPORT.md`
- `reports/phase2/COMPREHENSIVE_ANALYSIS.md`
- `reports/phase2/binary_structure.json`
- `reports/phase2/binary_structure.md`
- `reports/phase2/COPILOT_SESSION_REPORT.md`
