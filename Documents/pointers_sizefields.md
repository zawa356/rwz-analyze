# ポインタとサイズフィールド

## 事実（観測結果）

- ポインタ総数: **4,093**
- ポインタチェーン: **100**（最大深度は「変動」と報告）
- ポインタクラスタ: **162**
- 文字列ポインタ: **513** / データポインタ: **380**
- サイズフィールド: **692**
- 文字列エンコーディング: **UTF-16 / UTF-8 が混在**

出典: `reports/phase2/PHASE2_FINAL_REPORT.md`, `reports/phase2/pointer_network.*`, `reports/phase2/size_fields.*`

### 文字列抽出数の揺れについて（事実）

レポート間で **文字列抽出数の記載が揺れています**。

- `reports/phase2/PHASE2_FINAL_REPORT.md` では「Total string extractions: 169」と記載
- `AISTATE.TXT` では「2,328 string extractions」と記載

→ **どちらが正かは未検証**です。後述の検証手順で確定します。

## 推測（構造解釈）

- RWZ は「固定長ブロックがポインタで文字列領域を参照する」モデルを採用している可能性が高い。
- サイズフィールドは「文字列長 + 直後にデータ」という **境界付け**に使われている可能性が高い。
- ポインタチェーンは「ネストされたオブジェクト（ルール → 条件 → アクション）」の表現と一致する可能性がある。

## 検証方法

1. **サイズフィールド検証**
   - `size_fields.json` の各サイズ値を基準に、直後のバイト列が UTF-16/UTF-8 文字列として妥当か確認。
2. **ポインタ参照検証**
   - ポインタ値がファイル内有効オフセットを指すかを検査。
   - 指先がサイズフィールド／文字列領域かどうかで分類。
3. **チェーン検証**
   - ルール数・条件数を UI と比較し、ポインタチェーンの分岐数と一致するかを確認。

## 参考レポート

- `reports/phase2/pointer_network.json`
- `reports/phase2/pointer_network.md`
- `reports/phase2/size_fields.json`
- `reports/phase2/size_fields.md`
