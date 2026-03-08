---
name: memory-corruption-detector
description: >-
  Detect memory corruption vulnerabilities in DeepExtractIDA binaries:
  buffer overflows (heap and stack), integer overflow/truncation before
  allocation, use-after-free, double-free, and format string bugs.
  Includes assembly-level verification of each finding. Use when the
  user asks to find buffer overflows, detect memory corruption, scan
  for integer overflows, check for use-after-free, find format string
  bugs, hunt for memory safety issues, or asks about memory corruption
  in an extracted module.
---

# Memory Corruption Detector

## Purpose

Detect memory corruption vulnerability classes that are the most common
and highest-severity bugs in Windows binaries. While the existing
logic-vulnerability-detector targets auth bypasses and business logic
flaws, this skill targets the classical memory safety bugs:

- **Buffer overflows**: memcpy/strcpy with tainted or unchecked sizes
- **Integer issues**: overflow/truncation before allocation sizes
- **Use-after-free / double-free**: freed pointer reuse
- **Format strings**: non-constant format argument from tainted source

Four detection scripts scan for different vulnerability classes, and an
independent verification script re-reads raw code and assembly to
confirm or reject each finding before reporting.

## Data Sources

### SQLite Databases (primary)

- `functions` table: decompiled code, assembly, xrefs, string literals
- `file_info` table: exports, security features
- See [data_format_reference.md](../../docs/data_format_reference.md)

### Finding a Module DB

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py --list
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll
```

## Utility Scripts

### scan_buffer_overflows.py -- Buffer Overflow Detection (Start Here)

Detect memcpy/memmove/strcpy-family calls where size or source comes
from tainted (parameter-derived) data without adequate bounds checking.

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path>
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --top 20 --json
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --id <fid> --json
```

Output: findings with category (heap_overflow, stack_overflow), severity, score,
evidence lines, dangerous API, size source tracking.

### scan_integer_issues.py -- Integer Overflow/Truncation Detection

Detect arithmetic on tainted values before allocation sizes and integer
truncation (e.g. DWORD to WORD cast) before size-sensitive operations.

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path>
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --id <fid> --json
```

### scan_use_after_free.py -- Use-After-Free / Double-Free Detection

Track allocation/free sequences and detect pointer reuse after
deallocation or double-free patterns.

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path>
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --json
```

### scan_format_strings.py -- Format String Detection

Flag format functions (sprintf, StringCchPrintf, etc.) where the format
string argument is a variable rather than a constant string literal.

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path>
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --json
```

### verify_findings.py -- Independent Assembly Verification

Re-read code and assembly with fresh eyes to confirm or reject each
finding. Assigns confidence: CONFIRMED, LIKELY, UNCERTAIN, FALSE_POSITIVE.

```bash
python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
    --findings findings.json --db-path <db_path> --json
```

## Workflows

### Workflow 1: "Scan a module for memory corruption"

Memory Corruption Scan Progress:
- [ ] Step 1: Resolve the module DB
- [ ] Step 2: Run all four scanners (parallel)
- [ ] Step 3: Merge and deduplicate findings
- [ ] Step 4: Verify findings against assembly
- [ ] Step 5: Present ranked results

**Step 1**: Resolve the module DB.

```bash
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py <module>
```

**Step 2**: Run all four scanners.

```bash
python .agent/skills/memory-corruption-detector/scripts/scan_buffer_overflows.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_integer_issues.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_use_after_free.py <db_path> --json
python .agent/skills/memory-corruption-detector/scripts/scan_format_strings.py <db_path> --json
```

**Step 3**: Merge findings from all scanners, deduplicate by (function, category).

**Step 4**: Write merged findings to a temp file, run verification:

```bash
python .agent/skills/memory-corruption-detector/scripts/verify_findings.py \
    --findings merged.json --db-path <db_path> --json
```

**Step 5**: Present findings sorted by verified score.

## Integration with Other Skills

| Task | Recommended Skill |
|------|------------------|
| Trace tainted data flow to dangerous sinks | taint-analysis |
| Assess exploitability of findings | exploitability-assessment |
| Check function reachability from exports | security-dossier |
| Reconstruct struct layouts used in overflows | reconstruct-types |
| Verify decompiler accuracy for flagged functions | verify-decompiled |

## Direct Helper Module Access

- `helpers.analyze_taint(code, tainted_vars)` -- Def-use chain taint propagation
- `helpers.classify_api_security(api_name)` -- API danger classification
- `helpers.find_guards_between(code, src, sink, tainted)` -- Guard extraction

## Performance

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Single scanner, single function | ~0.1s | Per-function scan |
| Single scanner, full module | ~3-8s | Scales with function count |
| All four scanners | ~10-25s | Run in parallel for best throughput |
| Verification | ~2-5s | Per finding, assembly comparison |

## Additional Resources

- [data_format_reference.md](../../docs/data_format_reference.md) -- DB schema
- Related: [logic-vulnerability-detector](../logic-vulnerability-detector/SKILL.md) for logic bugs
- Related: [taint-analysis](../taint-analysis/SKILL.md) for deeper taint tracing
