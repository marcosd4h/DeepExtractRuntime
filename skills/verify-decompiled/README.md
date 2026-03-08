# Verify Decompiled Code

Decompiler accuracy correction tool. Finds specific places where Hex-Rays got something wrong compared to the assembly, and surgically patches only those errors in the original decompiled code.

## Quick Start

```bash
# 1. Find the module DB
python .agent/skills/decompiled-code-extractor/scripts/find_module_db.py appinfo.dll

# 2. Triage -- which functions have issues?
python .agent/skills/verify-decompiled/scripts/scan_module.py extracted_dbs/appinfo_dll_e98d25a9e8.db --top 10

# 3. Verify a specific function
python .agent/skills/verify-decompiled/scripts/verify_function.py extracted_dbs/appinfo_dll_e98d25a9e8.db --id 195
```

## What It Does

Compares assembly (ground truth) against Hex-Rays decompiled output and flags specific inaccuracies. The output is the original decompiler code with minimal, targeted fixes -- not a rewrite.

|                  | verify-decompiled (this)                 | code-lifting                 |
| ---------------- | ---------------------------------------- | ---------------------------- |
| **Goal**         | Fix decompiler errors only               | Full rewrite for readability |
| **Scope**        | Surgical patches to specific lines       | Entire function rewritten    |
| **Variables**    | Keeps `a1`, `v5` as-is                   | Renames everything           |
| **Control flow** | Keeps gotos/labels as-is                 | Simplifies and restructures  |
| **When to use**  | Before reading/analyzing decompiled code | When you need clean source   |

## Scripts

### scan_module.py -- Triage (Start Here)

Scans every function in a module and ranks them by decompiler issue severity.

```bash
# Full scan
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path>

# Only CRITICAL issues
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --min-severity CRITICAL

# Top 20 most problematic functions
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --top 20

# JSON output
python .agent/skills/verify-decompiled/scripts/scan_module.py <db_path> --json
```

### verify_function.py -- Deep Verification

Extracts assembly + decompiled code with automated heuristic analysis for a single function.

```bash
# By function name
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> AiBuildMSIParams

# By function ID
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id 648

# Search for functions
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --search "Parse"

# JSON output
python .agent/skills/verify-decompiled/scripts/verify_function.py <db_path> --id 648 --json
```

## Example Output

```
################################################################################
  DECOMPILER ACCURACY SCAN: appinfo.dll
  Application Information Service
################################################################################

Scan Summary:
  Total functions in module:   1173
  Functions scanned (asm+dec): 1161
  Functions with issues:       138

Issue Distribution (18 total across 10 functions):
  By severity: 6 CRITICAL, 6 HIGH, 6 LOW
  By category:
    Branch Count Mismatch               6
    Wrong Access Size                   5
    Wrong Return Type                   5

Rank  Score       Sev   C  H  M  L      ID  Function Name
   1    110  CRITICAL   1  1  0  0     115  StateRepository::Cache::Entity::Activation_NoTh...
   2    110  CRITICAL   1  1  0  0     314  __DllMainCRTStartup
   3    101  CRITICAL   1  0  0  1     195  AppModelPolicy_GetPolicy_Internal
```

## Automated Heuristic Checks

| Check                 | Detects                                                                 | Severity      |
| --------------------- | ----------------------------------------------------------------------- | ------------- | ----------------------------- | ------------- |
| Branch count mismatch | Missing branches in decompiled code (counts `if`, `goto`, loops, `&&`/` |               | `, ternary, `case`/`default`) | CRITICAL/HIGH |
| NULL check detection  | `test reg,reg` + `jz`/`jnz` pairs without corresponding conditionals    | CRITICAL      |
| Return type mismatch  | Mangled name return type vs decompiled signature                        | LOW-HIGH      |
| Call count mismatch   | Assembly `call` instructions missing from decompiled output             | HIGH/MODERATE |
| Access size mismatch  | DWORD/QWORD/BYTE distribution differences                               | HIGH          |
| Signedness mismatch   | Unsigned asm branches (`jb`/`ja`) with signed decompiled comparisons    | HIGH          |
| Decompiler artifacts  | `do/while(0)`, `LOBYTE` wrappers                                        | LOW           |

## Severity Classification

| Severity     | Meaning                                                      | Examples                                                |
| ------------ | ------------------------------------------------------------ | ------------------------------------------------------- |
| **CRITICAL** | Missing operations that change behavior                      | Missing NULL guard, missing branch, missing error check |
| **HIGH**     | Wrong types/sizes affecting data interpretation              | DWORD shown as QWORD, signedness mismatch               |
| **MODERATE** | Wrong return/parameter types                                 | `void *` vs `struct node *`                             |
| **LOW**      | Decompiler artifacts, register-width return type differences | `do/while(0)`, `__int64` vs `int`                       |

## Files

```
verify-decompiled/
├── SKILL.md              # Agent skill instructions (read by Cursor)
├── reference.md          # Technical reference (assembly patterns, heuristic details)
├── README.md             # This file
└── scripts/
    ├── _common.py        # Assembly parser, decompiled analyzer, heuristic checks
    ├── verify_function.py # Single function verification with full code output
    └── scan_module.py    # Module-wide triage scan with ranked results
```

## Dependencies

- Python 3.10+
- `.agent/helpers/` module (workspace root) -- provides `open_individual_analysis_db`, `open_analyzed_files_db`
- SQLite analysis databases from DeepExtractIDA

## Related Skills

- [code-lifting](../code-lifting/SKILL.md) -- Lift verified code into clean, readable source
- [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) -- Navigate and understand decompiled code
- [classify-functions](../classify-functions/SKILL.md) -- Classify all functions by purpose
- [security-dossier](../security-dossier/SKILL.md) -- Security context dossier for a function
- [map-attack-surface](../map-attack-surface/SKILL.md) -- Map module-wide attack surface
