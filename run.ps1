param(
  [string]$Rwz = "inputs/無題.rwz",
  [string]$Screens = "inputs/screenshots/99_Outlookフィルター/20260202",
  [switch]$Deep,
  [switch]$UseOcr,
  [switch]$Phase2
)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RwzPath = Join-Path $Root $Rwz
$ScreensPath = Join-Path $Root $Screens

$ReportsDir = Join-Path $Root "reports"
$ReportsPhase1 = Join-Path $ReportsDir "phase1"
$ReportsPhase2 = Join-Path $ReportsDir "phase2"
$OutputDir = Join-Path $Root "output"
$InputsDir = Join-Path $Root "inputs"
$CarveDir = Join-Path $Root "carve"

if (!(Test-Path $ReportsDir)) { New-Item -ItemType Directory -Path $ReportsDir | Out-Null }
if (!(Test-Path $ReportsPhase1)) { New-Item -ItemType Directory -Path $ReportsPhase1 | Out-Null }
if (!(Test-Path $ReportsPhase2)) { New-Item -ItemType Directory -Path $ReportsPhase2 | Out-Null }
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
if (!(Test-Path $InputsDir)) { New-Item -ItemType Directory -Path $InputsDir | Out-Null }
if (!(Test-Path $CarveDir)) { New-Item -ItemType Directory -Path $CarveDir | Out-Null }

$Py = "python"
$VenvPy = Join-Path $Root ".venv/bin/python"
if (Test-Path $VenvPy) { $Py = $VenvPy }

# OCR (optional; analysis-only)
$OcrJson = Join-Path $InputsDir "ocr.json"
if ($UseOcr -and (Test-Path $ScreensPath)) {
  & $Py (Join-Path $Root "tools/rwz_ocr.py") $ScreensPath --out $OcrJson
}

$MergeArgs = @()
if ($UseOcr -and (Test-Path $OcrJson)) {
  $MergeArgs = @("--merge-ocr-json", $OcrJson)
}

# Phase 1: Core rule extraction
& $Py (Join-Path $Root "tools/rwz_analyze.py") $RwzPath --format csv @MergeArgs --out (Join-Path $OutputDir "out_rules.csv")
& $Py (Join-Path $Root "tools/rwz_analyze.py") $RwzPath --format json @MergeArgs --out (Join-Path $OutputDir "out_rules.json")
& $Py (Join-Path $Root "tools/rwz_analyze.py") $RwzPath --format yaml @MergeArgs --out (Join-Path $OutputDir "out_rules.yaml")

# Phase 1: Reports
& $Py (Join-Path $Root "tools/rwz_report.py") $RwzPath --include-ascii --out (Join-Path $ReportsPhase1 "out_report.md")
& $Py (Join-Path $Root "tools/rwz_report.py") $RwzPath --min-chars 2 --include-ascii --include-utf16be --out (Join-Path $ReportsPhase1 "out_report_deep.md")
& $Py (Join-Path $Root "tools/rwz_gap_analyze.py") $RwzPath --gap-limit 200 --sample-limit 12 --preview-bytes 128 --out (Join-Path $ReportsPhase1 "out_gap_report.md")
& $Py (Join-Path $Root "tools/rwz_zlib_scan.py") $RwzPath --out (Join-Path $ReportsPhase1 "out_zlib_report.md") --dump-dir (Join-Path $CarveDir "zlib_streams")
& $Py (Join-Path $Root "tools/rwz_utf16_scan.py") $RwzPath --out (Join-Path $ReportsPhase1 "out_utf16_report.md")
& $Py (Join-Path $Root "tools/rwz_lenpref_scan.py") $RwzPath --out (Join-Path $ReportsPhase1 "out_lenpref_report.md")

if ($Deep) {
  & $Py (Join-Path $Root "tools/rwz_compress_scan.py") $RwzPath --out (Join-Path $ReportsPhase1 "out_compress_report.md") --dump-dir (Join-Path $CarveDir "compress_streams")
}

# Unified CSV
& $Py (Join-Path $Root "tools/rwz_unified_csv.py") --rules-csv (Join-Path $OutputDir "out_rules.csv") --report-md (Join-Path $ReportsPhase1 "out_report_deep.md") --gap-md (Join-Path $ReportsPhase1 "out_gap_report.md") --compress-md (Join-Path $ReportsPhase1 "out_compress_report.md") --out (Join-Path $OutputDir "out_unified.csv")

# Phase 2: Deep structure analysis (optional)
if ($Phase2) {
  & $Py (Join-Path $Root "tools/rwz_binary_structure.py") $RwzPath --out (Join-Path $ReportsPhase2 "binary_structure.json") --out-md (Join-Path $ReportsPhase2 "binary_structure.md")
  & $Py (Join-Path $Root "tools/rwz_format_detection.py") $RwzPath --out (Join-Path $ReportsPhase2 "format_detection.json") --out-md (Join-Path $ReportsPhase2 "format_detection.md")
  & $Py (Join-Path $Root "tools/rwz_metadata_extractor.py") $RwzPath --out (Join-Path $ReportsPhase2 "metadata_extractor.json") --out-md (Join-Path $ReportsPhase2 "metadata_extractor.md")
  & $Py (Join-Path $Root "tools/rwz_advanced_patterns.py") $RwzPath --out (Join-Path $ReportsPhase2 "advanced_patterns.json") --out-md (Join-Path $ReportsPhase2 "advanced_patterns.md")
  & $Py (Join-Path $Root "tools/rwz_hex_inspector.py") $RwzPath --out (Join-Path $ReportsPhase2 "hex_inspection.json") --out-md (Join-Path $ReportsPhase2 "hex_inspection.md")

  & $Py (Join-Path $Root "tools/rwz_block_structure_analyzer.py") $RwzPath --out (Join-Path $ReportsPhase2 "block_structure_analysis.json") --out-md (Join-Path $ReportsPhase2 "block_structure_analysis.md") --hex-dump (Join-Path $ReportsPhase2 "block_hex_dumps.txt")
  & $Py (Join-Path $Root "tools/rwz_pointer_network.py") $RwzPath --out (Join-Path $ReportsPhase2 "pointer_network.json") --out-md (Join-Path $ReportsPhase2 "pointer_network.md")
  & $Py (Join-Path $Root "tools/rwz_size_fields.py") $RwzPath --out (Join-Path $ReportsPhase2 "size_fields.json") --out-md (Join-Path $ReportsPhase2 "size_fields.md")
  & $Py (Join-Path $Root "tools/rwz_gap_details.py") $RwzPath --out (Join-Path $ReportsPhase2 "gap_details.json") --out-md (Join-Path $ReportsPhase2 "gap_details.md")
  & $Py (Join-Path $Root "tools/rwz_gap_deep_analysis.py") $RwzPath --out (Join-Path $ReportsPhase2 "gap_deep_analysis.json") --out-md (Join-Path $ReportsPhase2 "gap_deep_analysis.md")

  & $Py (Join-Path $Root "tools/rwz_block_flags.py") $RwzPath --out (Join-Path $ReportsPhase2 "block_flags_analysis.json") --out-md (Join-Path $ReportsPhase2 "block_flags_analysis.md") --block-structure (Join-Path $ReportsPhase2 "block_structure_analysis.json")
  & $Py (Join-Path $Root "tools/rwz_branching_conditions.py") (Join-Path $ReportsPhase2 "gap_deep_analysis.json") --out (Join-Path $ReportsPhase2 "branching_hypotheses.json") --out-md (Join-Path $ReportsPhase2 "branching_hypotheses.md")

  $RuleReconArgs = @()
  if ($UseOcr -and (Test-Path $OcrJson)) {
    $RuleReconArgs = @("--ocr", $OcrJson)
  }
  & $Py (Join-Path $Root "tools/rwz_rule_reconstruction.py") $RwzPath @RuleReconArgs --out (Join-Path $ReportsPhase2 "rule_reconstruction.json") --out-md (Join-Path $ReportsPhase2 "rule_reconstruction_guide.md")

  $Phase2IntegrationArgs = @("--reports-dir", $ReportsPhase2, "--out", (Join-Path $ReportsPhase2 "phase2_integration.json"), "--out-md", (Join-Path $ReportsPhase2 "phase2_integration.md"))
  if ($UseOcr -and (Test-Path $OcrJson)) {
    $Phase2IntegrationArgs += @("--ocr-file", $OcrJson)
  }
  & $Py (Join-Path $Root "tools/rwz_phase2_integration.py") @Phase2IntegrationArgs

  & $Py (Join-Path $Root "tools/rwz_phase2_final_report.py") --reports-dir $ReportsPhase2 --out (Join-Path $ReportsPhase2 "PHASE2_FINAL_REPORT.md")
  & $Py (Join-Path $Root "tools/rwz_phase2_session_summary.py") --reports-dir $ReportsPhase2 --out (Join-Path $ReportsPhase2 "PHASE2_SESSION_SUMMARY.json")
  & $Py (Join-Path $Root "tools/rwz_comprehensive_report.py") --reports-dir $ReportsPhase2 --out (Join-Path $ReportsPhase2 "COMPREHENSIVE_ANALYSIS.md")
}
