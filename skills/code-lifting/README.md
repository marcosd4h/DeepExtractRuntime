# Code Lifting

Answer: **"Rewrite this decompiled function into clean, readable C++ that is 100% functionally equivalent to the original binary."**

A workflow/recipe skill that defines the 11-step process for lifting
IDA Pro decompiled C/C++ functions into clean, readable source code.
Unlike most skills in this ecosystem, code-lifting has **no scripts of
its own** -- the code-lifter agent follows the workflow in SKILL.md,
using data extracted by dependency skills.

**This is NOT security analysis.** The sole goal is faithful, readable
reconstruction. No vulnerability annotations, security tags, or trust
boundary markers.

## Quick Start

```
1. Extract function data using decompiled-code-extractor
2. Follow the 11-step workflow in SKILL.md
3. Launch the verifier agent for independent confirmation
```

### Example: Lift a function

```
User: "Lift AiCheckSecureApplicationDirectory from appinfo.dll"

Agent workflow:
  1. find_module_db.py appinfo.dll  ->  extracted_dbs/appinfo_dll_e98d25a9e8.db
  2. extract_function_data.py <db> AiCheckSecureApplicationDirectory
  3. Follow Steps 2-10: validate against assembly, rename variables,
     replace magic numbers, reconstruct structs, simplify control flow,
     add documentation, verify
  4. Step 11: launch verifier subagent for independent confirmation
  5. Deliver lifted code with struct definitions and constants
```

## The 11-Step Workflow

| Step | Action | Key Concern |
| ---- | ------ | ----------- |
| 1 | Gather function data (decompiled + assembly + context) | Assembly is required -- it is the ground truth |
| 2 | Validate decompiled code against assembly | Catch decompiler artifacts and missing operations |
| 3 | Rename parameters (a1/a2 -> meaningful names) | Use signature > mangled name > type hints > API context |
| 4 | Rename local variables (v1/v2 -> meaningful names) | Use register comments and usage context |
| 5 | Replace magic numbers with named constants | Win32 SDK constants, HRESULTs, message IDs, flags |
| 6 | Reconstruct struct/class definitions | Collect offset patterns, cross-reference related functions |
| 7 | Convert pointer arithmetic to field access | `*((_QWORD *)a1 + 14)` -> `node->commandName` |
| 8 | Simplify control flow | Remove decompiler gotos; preserve SEH, locks, setjmp |
| 9 | Add documentation and inline comments | Infer semantic purpose; explain "why", not "what" |
| 10 | Final self-verification | Checklist: every assembly path, all memory ops, no leftover names |
| 11 | Independent verification via verifier agent | Fresh-eyes check against assembly ground truth |

## Dependency Skills

Code-lifting consumes data and tools from these skills:

| Skill | Role | When Used |
| ----- | ---- | --------- |
| [decompiled-code-extractor](../decompiled-code-extractor/SKILL.md) | Extract function data (decompiled C++, assembly, xrefs, signatures) | Step 1: data gathering |
| [reconstruct-types](../reconstruct-types/SKILL.md) | Scan memory access patterns to build struct/class definitions | Step 6: struct reconstruction |
| [verify-decompiled](../verify-decompiled/SKILL.md) | Verify decompiler accuracy before lifting; surgical fixes | Step 2: validation |
| [batch-lift](../batch-lift/SKILL.md) | Coordinate lifting of related function groups with shared context | When lifting class methods or call chains together |
| [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) | Reference for IDA conventions, file layout, and analysis patterns | General reference |

## What Makes This Skill Different

| Property | code-lifting | Most other skills (13) |
| -------- | ------------ | ---------------------- |
| **Type** | Workflow / recipe | Automation / tooling |
| **Has scripts/** | No | Yes (Python scripts) |
| **Operates via** | Agent follows SKILL.md workflow, calls other skills' scripts | Python scripts + agent |
| **Primary output** | Lifted C++ code with structs and documentation | Structured text / JSON |

Only two skills in the ecosystem are workflow/recipe skills with no
scripts: `code-lifting` and `analyze-ida-decompiled`. Both encode
knowledge and process rather than automation.

## Files

```
code-lifting/
├── SKILL.md       # 11-step lifting workflow, reference tables, common patterns
├── examples.md    # 7 before/after lifting examples with change explanations
└── README.md      # This file
```

## Related Skills

- [decompiled-code-extractor](../decompiled-code-extractor/SKILL.md) -- Extract function data from analysis databases
- [batch-lift](../batch-lift/SKILL.md) -- Lift related function groups with shared struct context
- [reconstruct-types](../reconstruct-types/SKILL.md) -- Reconstruct C/C++ struct and class definitions
- [verify-decompiled](../verify-decompiled/SKILL.md) -- Verify decompiler accuracy against assembly
- [analyze-ida-decompiled](../analyze-ida-decompiled/SKILL.md) -- Navigate and understand IDA decompiled code
