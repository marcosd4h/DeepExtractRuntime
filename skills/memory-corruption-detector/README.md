# Memory Corruption Detector

Detect memory corruption vulnerabilities in Windows binaries: buffer overflows, integer overflow/truncation, use-after-free, double-free, and format string bugs. Includes independent assembly-level verification of each finding.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Scan for buffer overflows
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --json
```

## What It Does

Four specialized scanners detect different vulnerability classes, and a verification script confirms or rejects each finding against assembly ground truth:

| Scanner | Detects |
|---------|---------|
| `scan_buffer_overflows.py` | memcpy/strcpy with tainted or unchecked sizes (heap and stack) |
| `scan_integer_issues.py` | Integer overflow/truncation before allocation sizes |
| `scan_use_after_free.py` | Freed pointer reuse and double-free patterns |
| `scan_format_strings.py` | Non-constant format arguments from tainted sources |
| `verify_findings.py` | Independent assembly verification (CONFIRMED/LIKELY/UNCERTAIN/FALSE_POSITIVE) |

## Usage

```bash
# Run individual scanners
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --json

# Scan a single function
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --id <fid> --json

# Verify findings
python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
    --findings merged.json --db-path <db_path> --json
```

## Files

```
memory-corruption-detector/
├── SKILL.md                    # Agent skill instructions
├── README.md                   # This file
└── scripts/
    ├── _common.py              # Bootstrapping, shared patterns, scoring
    ├── scan_buffer_overflows.py    # Heap/stack overflow detection
    ├── scan_integer_issues.py      # Integer overflow/truncation detection
    ├── scan_use_after_free.py      # UAF/double-free detection
    ├── scan_format_strings.py      # Format string bug detection
    └── verify_findings.py          # Independent assembly verification
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module -- provides `api_taxonomy`, `decompiled_parser`, `guard_classifier`, `def_use_chain`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [taint-analysis](../taint-analysis/SKILL.md) -- Trace tainted data flow to dangerous sinks
- [exploitability-assessment](../exploitability-assessment/SKILL.md) -- Assess exploitability of findings
- [security-dossier](../security-dossier/SKILL.md) -- Check function reachability from exports
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct struct layouts used in overflows
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy for flagged functions
- [logic-vulnerability-detector](../logic-vulnerability-detector/SKILL.md) -- Logic bugs (auth bypass, TOCTOU)
