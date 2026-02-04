# AI Agent Instructions for rwz-analyze

This project reverse-engineers the Outlook `.rwz` mail rules export format through multi-phase binary analysis.

## Project Overview

**Goal**: Extract and visualize Outlook mail rules from `.rwz` files + OCR screenshots.

**Architecture**:
- **Phase 1 (Core)**: String extraction via UTF-16/ASCII regex + rule clustering (`rwz_analyze.py`)
- **Phase 2 (Deep)**: Binary structure reverse-engineering — 192-byte blocks, pointer networks, size fields, gap analysis
- **Outputs**: CSV/JSON/YAML rules, markdown reports, advanced analysis JSON

**Current State**: 97.6% file coverage achieved; 66 rules extracted with high confidence.

## Key Patterns & Conventions

### File Layout Pattern
RWZ files use a hybrid 3-layer architecture:
1. **Block layer**: 452 repeating 192-byte structures (rule metadata)
2. **Pointer layer**: 4,093 DWORD pointers (object graph, cross-references)
3. **String layer**: 692 size-field-bounded regions (UTF-8/UTF-16LE text)

See [tools/rwz_block_structure_analyzer.py](tools/rwz_block_structure_analyzer.py), [tools/rwz_pointer_network.py](tools/rwz_pointer_network.py), [tools/rwz_size_fields.py](tools/rwz_size_fields.py).

### String Extraction
- **UTF-16LE**: 4+ consecutive word-aligned chars `\x20-\x7e\x00`
- **ASCII**: 4+ bytes `\x20-\x7e`, skipping control chars
- **Normalization**: Case-fold emails; deduplicate via known-set tracking
- See [tools/rwz_analyze.py#extract_utf16_strings](tools/rwz_analyze.py), [tools/rwz_dump.py](tools/rwz_dump.py)

### Rule Extraction
Rules are clustered by `[Rule Name]` headers. Extraction includes:
- Title, description, enabled status
- Action/condition keywords from nearby strings
- Email recipients (normalized, deduplicated)
- Size estimates from field analysis
Example: [tools/rwz_analyze.py#summarize_rule](tools/rwz_analyze.py)

### Data Format Variants
- **OCR integration**: Optional; used for analysis only, never in final output (see `run.ps1 -UseOcr`)
- **Deep mode**: Enables compression scanning (`-Deep` flag triggers `rwz_compress_scan.py`)
- **Carving**: scalpel/foremost outputs in `carve/` (optional forensic recovery)

## Common Workflows

### Running Analysis
```powershell
pwsh .\run.ps1                                        # Default analysis
pwsh .\run.ps1 -Deep                                  # Include compression scans
pwsh .\run.ps1 -UseOcr                                # With OCR assistance
pwsh .\run.ps1 -Rwz "path/file.rwz" -Screens "path"  # Custom inputs
```

### Adding a New Analysis Tool
1. Create `tools/rwz_<phase>_<purpose>.py` with `argparse` CLI
2. Load RWZ via `Path(rwz_path).read_bytes()`
3. Output JSON to `reports/` + markdown summary
4. Integrate into orchestrator if Phase 2+: edit [tools/rwz_phase2_integration.py](tools/rwz_phase2_integration.py) / [run.ps1](run.ps1)
5. Update Phase2_EXECUTION_LOG.txt with results

### Debugging Analysis
- **String extraction issues**: Check UTF-16 regex in [rwz_dump.py#extract_utf16_strings](tools/rwz_dump.py) vs actual encoding
- **Gap mysteries**: Use [tools/rwz_gap_deep_analysis.py](tools/rwz_gap_deep_analysis.py) (byte patterns, context, nearby pointers)
- **Pointer validation**: See [tools/rwz_pointer_network.py#validate_pointers](tools/rwz_pointer_network.py)
- **Manual inspection**: `hexdump -C inputs/無題.rwz | head -100` + offset references in JSON reports

## Directory Structure

```
tools/               # Analysis scripts (24 tools; see AISTATE.TXT inventory)
├─ rwz_analyze.py           # Core rule extraction
├─ rwz_phase2_integration.py # Phase 2 validator & orchestrator
├─ rwz_block_structure_analyzer.py  # 192-byte block analysis
├─ rwz_pointer_network.py    # Pointer graph mapping
├─ rwz_size_fields.py        # Length-prefixed string extraction
├─ rwz_gap_deep_analysis.py  # Cryptic gap region analysis
└─ ...
inputs/              # RWZ files, OCR JSON, screenshots
reports/             # CSV/JSON/Markdown outputs
carve/               # Forensic carving results (optional)
```

## Critical Decision Points

### Encoding Detection
- UTF-16LE is dominant (7925 LE vs 7738 BE regions found)
- Always prioritize UTF-16LE for rule titles/conditions
- Fall back to ASCII for unterminated strings

### Confidence & Coverage
- **High confidence**: Rules from block structure + size fields (redundant extraction)
- **Medium**: OCR-assisted extraction (validation via pointer matching)
- **Low**: Raw gap analysis (requires human interpretation)
- Current: 97.6% coverage, 66 rules, all gaps confirmed null-padding

### When to Preserve vs. Discard Data
- **Preserve**: All extracted rules in outputs; all analysis JSON preserved for historical reference
- **Discard**: OCR strings are assistance-only; don't appear in final CSV/JSON unless also found in binary
- **Archive**: Store in AISTATE.TXT (append-only session log) for reproducibility

## Code Quality Notes

- **Type hints**: Used throughout Phase 2 tools (`from typing import List, Dict, ...`)
- **Error handling**: Graceful on malformed UTF-16; skip corrupt regions
- **No external data**: Analysis is file-based; inputs/ only for supplementary OCR/screenshots
- **Reproducibility**: All tools accept `--rwz` + output path; deterministic output

## Session History

- **Phase 1 (Codex)**: Core string extraction framework + basic rule clustering
- **Phase 2 (Copilot, 2026-02-03)**: Block structure, pointer networks, size fields, gap deep-dive → 97.6% coverage
- **Phase 2.5**: Branching condition hypotheses + rule reconstruction guide
- See [COPILOT_SESSION_REPORT.md](COPILOT_SESSION_REPORT.md) + [PHASE2_FINAL_REPORT.md](reports/PHASE2_FINAL_REPORT.md)

---

**Next frontiers**: Reverse-engineer rule condition/action bytecode semantics from remaining pointer chains; cross-validate with OCR screenshots for UI-to-binary mapping.
