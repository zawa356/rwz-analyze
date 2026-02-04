# フラグとルール適用ロジック（推測含む）

## 事実（観測結果）

- 192バイトブロック内で **フラグ候補の集中オフセット**が検出されている。
- フラグ候補の位置として、**0x00 / 0x20 / 0x24 / 0x28** が挙げられている。

出典: `reports/phase2/block_flags_analysis.*`, `reports/phase2/rule_reconstruction.*`

## 推測（意味付け）

以下は **推測** に基づく解釈です。

- `0x00` : `rule_type_identifier`（ルール型）
- `0x20` : `rule_enable_disable`（有効/無効）
- `0x24` : `rule_action_type`（アクション種別）
- `0x28` : `rule_priority_or_order`（優先度）

### 推測ロジック

```
ステージ1: IF offset_0x20 == 0x00000001 THEN apply_rule ELSE skip
ステージ2: SWITCH offset_0x24 { dispatch_action }
ステージ3: sort_by offset_0x28 ASC
```

## 検証方法（推測を事実化する）

1. **ルール有効/無効テスト**
   - UI上でルールを有効/無効切替 → RWZ差分で 0x20 の値変化を確認。
2. **アクション種別テスト**
   - “移動”→“削除”などアクション変更 → 0x24 の値変化を確認。
3. **優先度テスト**
   - ルール順序を入れ替え → 0x28 の値変化を確認。

## 注意

このページの内容は **構造推測** を多く含みます。最終成果物では、
推測値を根拠付きで確定する必要があります。

## 参考レポート

- `reports/phase2/block_flags_analysis.json`
- `reports/phase2/block_flags_analysis.md`
- `reports/phase2/rule_reconstruction.json`
- `reports/phase2/rule_reconstruction_guide.md`
