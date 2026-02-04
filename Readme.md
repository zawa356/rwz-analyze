# Outlook RWZ 解析ツール

Outlook の `.rwz` ルールエクスポートと、Outlook Web ルール画面のスクリーンショットを使って、
ルールの抽出と可視化を行うためのローカル解析ツール群です。

## ディレクトリ構成

- `run.ps1` : ルートから実行するエントリポイント
- `tools/` : 解析スクリプト
- `inputs/` : 入力データ（RWZ / OCR / スクリーンショット）
- `output/` : **最終出力（CSV/JSON/YAML）**
- `Documents/` : 構造ドキュメント（詳細）
- `reports/phase1/` : 基本解析の出力（Markdown）
- `reports/phase2/` : 深掘り解析の出力（構造推定/統合レポート）
- `carve/` : カービング/展開結果（生成物のみ）
- `scripts/` : 環境構築スクリプト
- `AISTATE.TXT` : 解析履歴・環境・出力のアーカイブ

※ `output/` / `inputs/` / `reports/phase1` / `reports/phase2` / `carve/` は中身を Git 管理しません。
（フォルダのみ残す運用）

## 環境構築（venv + requirements）

Linux/WSL:
```bash
./scripts/setup_venv.sh
```

PowerShell:
```powershell
pwsh .\scripts\setup_venv.ps1
```

## ドキュメント

詳細な構造解説は `Documents/README.md` から参照してください。

## 入力ファイルの前提

- 既定入力 `inputs/無題.rwz` はサンプル名です（Git 管理しません）。
- 実ファイルを `inputs/` に配置するか、`-Rwz` で明示指定してください。

## 使い方（基本）

PowerShell からルートで実行:

```powershell
pwsh .\run.ps1
```

圧縮スキャンまで含める（Deep モード）:

```powershell
pwsh .\run.ps1 -Deep
```

Phase2 の深掘り解析も実行:

```powershell
pwsh .\run.ps1 -Phase2
```

入力ファイルの指定:

- `inputs/` に `.rwz` が1件だけある場合は、`-Rwz` を省略できます。

```powershell
pwsh .\run.ps1 -Rwz "inputs\sample.rwz" -Screens "inputs\screenshots\my-captures"
```

## OCR の扱い

- **最終成果物は OCR なしが前提**です。
- 解析中のみ、補助データとして OCR を利用できます。
- OCR を使う場合は `-UseOcr` を明示します。

```powershell
pwsh .\run.ps1 -UseOcr
```

出力には OCR 由来の文字列を含めません。

## 主な出力

### 最終成果物（output/）

- `output/out_rules.csv` : ルール一覧（emails/keywords はセル内改行）
- `output/out_rules.json` : ルール一覧（JSON）
- `output/out_rules.yaml` : ルール一覧（YAML）
- `output/out_unified.csv` : 統合 CSV

### Phase 1（Markdownレポート）

- `reports/phase1/out_report.md` : 解析カバレッジと概要
- `reports/phase1/out_report_deep.md` : 深掘り版の概要
- `reports/phase1/out_gap_report.md` : ギャップ解析詳細

### Phase 2（深掘り解析）

- `reports/phase2/COMPREHENSIVE_ANALYSIS.md` : 統合レポート
- `reports/phase2/PHASE2_FINAL_REPORT.md` : Phase2 最終レポート
- `reports/phase2/GAP_DEEP_ANALYSIS_FINAL_REPORT.md` : ギャップ深掘り最終報告
- `reports/phase2/*_analysis.*` : 構造/ギャップ/フラグ/ポインタ分析

## 解析スクリプト一覧（tools/）

### Phase 1

- `rwz_analyze.py` : ルール抽出と要約
- `rwz_dump.py` : 文字列抽出ダンプ
- `rwz_ocr.py` : スクリーンショット OCR
- `rwz_report.py` : カバレッジ/ルール/ギャップ概要
- `rwz_gap_analyze.py` : ギャップ深掘り（エントロピー/比率/マジックバイト）
- `rwz_zlib_scan.py` : zlib 埋め込み検出
- `rwz_utf16_scan.py` : UTF‑16 文字列抽出
- `rwz_lenpref_scan.py` : 長さプレフィックス仮説スキャン
- `rwz_compress_scan.py` : 圧縮候補検出（Deep モード）
- `rwz_unified_csv.py` : 統合 CSV 生成

### Phase 2（Copilot 追加）

- `rwz_binary_structure.py`
- `rwz_format_detection.py`
- `rwz_metadata_extractor.py`
- `rwz_advanced_patterns.py`
- `rwz_hex_inspector.py`
- `rwz_block_structure_analyzer.py`
- `rwz_pointer_network.py`
- `rwz_size_fields.py`
- `rwz_gap_details.py`
- `rwz_gap_deep_analysis.py`
- `rwz_block_flags.py`
- `rwz_branching_conditions.py`
- `rwz_rule_reconstruction.py`
- `rwz_phase2_integration.py`
- `rwz_phase2_final_report.py`
- `rwz_phase2_session_summary.py`
- `rwz_comprehensive_report.py`

## 依存関係

- Python 3.12+
- tesseract 5.x（OCR 使用時）

requirements.txt に含まれるパッケージ:
- PyYAML
- lz4 / zstandard / python-snappy / lznt1

任意（深掘り解析）:
- binwalk / foremost / scalpel
- oletools / olefile

## ツール導入例

```bash
sudo apt-get update
sudo apt-get install -y binwalk foremost scalpel
python3 -m pip install --user oletools olefile
```
