# Memory Corruption Detector -- Technical Reference

## Data Model

### MemCorruptionFinding

| Field | Type | Description |
|-------|------|-------------|
| `category` | str | Vulnerability class (see table below) |
| `function_name` | str | Function where finding was detected |
| `function_id` | int | DB function ID |
| `summary` | str | Human-readable description |
| `severity` | str | CRITICAL, HIGH, MEDIUM, or LOW |
| `score` | float | Unified score 0--1 |
| `evidence_lines` | list[str] | Source code lines supporting the finding |
| `dangerous_api` | str? | API call involved |
| `dangerous_api_category` | str? | copy, unbounded_copy, allocation, free, format, use_after_free |
| `alloc_api` | str? | Allocation API (integer overflow findings) |
| `size_source` | str? | Expression used as size argument |
| `extra` | dict | Category-specific details (tainted vars, line numbers, etc.) |

### Vulnerability Categories

| Category | Description | Impact Weight |
|----------|-------------|:------------:|
| `heap_overflow` | Tainted size/length to memcpy exceeds buffer | 1.00 |
| `stack_overflow` | Stack buffer write with unchecked tainted size | 0.95 |
| `integer_overflow` | Arithmetic overflow before allocation/size check | 0.90 |
| `format_string` | Non-constant format string from tainted source | 0.85 |
| `use_after_free` | Memory use after deallocation on same path | 0.80 |
| `double_free` | Same pointer freed twice without reallocation | 0.80 |
| `integer_truncation` | Type narrowing (DWORD->WORD) before size-sensitive op | 0.70 |
| `uninitialized_size` | Allocation with uninitialized or zero-checked size | 0.60 |

### Tracked API Sets

| Set | APIs |
|-----|------|
| Allocation | HeapAlloc, RtlAllocateHeap, malloc, calloc, realloc, VirtualAlloc, LocalAlloc, GlobalAlloc, CoTaskMemAlloc, SysAllocString |
| Free | HeapFree, RtlFreeHeap, free, VirtualFree, LocalFree, GlobalFree, CoTaskMemFree, SysFreeString |
| Bounded copy | memcpy, memmove, CopyMemory, RtlCopyMemory, RtlMoveMemory, wmemcpy, wmemmove, strncpy, wcsncpy, lstrcpyn |
| Unbounded copy | strcpy, wcscpy, lstrcpy, lstrcpyW, lstrcpyA, strcat, wcscat, lstrcat |
| Format | sprintf, swprintf, vsprintf, vswprintf, _snprintf, _snwprintf, wsprintf, wvsprintf, StringCchPrintf, StringCbPrintf, printf, fprintf, wprintf |
| Safe (excluded) | StringCchCopy/Cat/Printf variants, StringCbCopy/Cat/Printf variants |

## Output Schemas

### All Scanners (scan_buffer_overflows / scan_integer_issues / scan_use_after_free / scan_format_strings)

```json
{ "status": "ok",
  "_meta": { "db_path": "...", "skill_name": "memory-corruption-detector",
    "scanner": "buffer_overflows|integer_issues|use_after_free|format_strings",
    "top_n": N },
  "findings": [{ "category": "...", "function_name": "...", "function_id": N,
    "summary": "...", "severity": "...", "score": 0.0,
    "evidence_lines": [...], "dangerous_api": "...",
    "dangerous_api_category": "...", "size_source": "...", "extra": { ... } }],
  "summary": { "total": N, "returned": N,
    "by_category": { "heap_overflow": N, "stack_overflow": N, ... } } }
```

### verify_findings.py

```json
{ "status": "ok",
  "_meta": { ... },
  "verified_findings": [{
    "finding": { ... },
    "confidence": "CONFIRMED|LIKELY|UNCERTAIN|FALSE_POSITIVE",
    "confidence_score": 0.0-1.0,
    "reasoning": "...",
    "assembly_evidence": ["..."],
    "mitigating_factors": ["..."],
    "path_feasible": true|false|null
  }],
  "summary": { "total": N, "confirmed": N, "likely": N,
    "uncertain": N, "false_positive": N } }
```

## Scoring Model

Score is computed by `compute_finding_score()` from `finding_base`:

```
score = impact * reachability * confidence * guard_penalty * proximity
```

| Factor | Source | Range |
|--------|--------|-------|
| Impact | `IMPACT_SEVERITY[category]` | 0.6--1.0 |
| Reachability | 1.0 if exported, 0.75 if entry-reachable, 0.5 otherwise | 0.5--1.0 |
| Confidence | CONFIRMED=1.0, LIKELY=0.7, UNCERTAIN=0.3 | 0.3--1.0 |
| Guard penalty | `max(0.2, 1.0 - 0.15 * guard_count)` | 0.2--1.0 |
| Proximity | `1.0 / sqrt(max(path_hops, 1))` | 0--1.0 |

### Severity Labels

| Score Range | Severity |
|-------------|----------|
| >= 0.75 | CRITICAL |
| >= 0.55 | HIGH |
| >= 0.35 | MEDIUM |
| < 0.35 | LOW |

### Verification Confidence Levels

| Level | Score | Meaning |
|-------|-------|---------|
| CONFIRMED | 1.0 | API call and tainted data flow verified in both decompiled code and assembly |
| LIKELY | 0.7 | API call confirmed; data flow is heuristic |
| UNCERTAIN | 0.3 | Partial evidence; could not fully confirm |
| FALSE_POSITIVE | 0.0 | Finding contradicted on re-read (API absent, null guard found, safe arithmetic) |

## Error Handling

| Condition | Behavior |
|-----------|----------|
| DB path invalid | `emit_error()` with `NOT_FOUND` |
| Function not found | `emit_error()` with `NOT_FOUND` |
| No decompiled code | Returns empty findings list |
| No findings file (verify) | `emit_error()` with `NOT_FOUND` |
| Constraint solver error | Feasibility check skipped; finding proceeds |
| Cache miss | Full scan executed; result cached |
