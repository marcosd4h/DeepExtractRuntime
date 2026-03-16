# FR-006: Virtual Dispatch Resolution in Callgraph Traversal

**Status:** Proposed
**Priority:** High
**Category:** Infrastructure / Callgraph
**Author:** Runtime Assessment Review
**Date:** 2026-03-16

---

## Problem Statement

Virtual dispatch through COM vtable slots is a dead zone in call chain
analysis.  In COM-heavy Windows services, the majority of interesting
execution flows through virtual methods.  The AI scanner sees:

```
RPC stub -> dispatcher -> COM server vtable slot -> STOP
```

The handler code behind the vtable slot is invisible to the scanner.

### Current State (Not As Broken As It Looks)

The situation is more nuanced than "vtable edges are filtered out."
Two levels of callgraph traversal exist, and they handle vtables
differently:

**`CallGraph` (helpers/callgraph.py) -- vtable edges ARE followed:**

`_is_followable_xref()` has `include_vtable=True` by default.  Vtable
xrefs (`function_type=8`, `module_name="vtable"`) are included in the
graph and tracked separately in `vtable_edges`.  BFS traversal via
`reachable_from()` DOES follow these edges.

**`ChainAnalyzer` (chain_analysis.py) -- vtable edges are NOT followed:**

The `classify_xrefs()` method explicitly routes vtable refs into a
`vtable_refs` bucket and does NOT recurse into them.  The output says
`~> SomeVtableSlot` but never loads the target function's code or
follows its callees.  This is the code-with-context tracer used by
`/audit --diagram` and the AI scanner's `prepare_context.py` for
building call chains with decompiled code.

**`CrossModuleGraph` (cross_module_graph.py) -- delegates to CallGraph:**

Uses `CallGraph` internally, so vtable edges ARE included in
`reachable_from()` results.  However, the vtable target names from
the xref may be unresolved or low-quality (e.g., `sub_XXXXX` or a
vtable slot label rather than the actual method name).

### The Real Gap

The problem is not that vtable edges are filtered -- they are followed
in the structural graph.  The problem is **vtable target resolution**:

1. A vtable xref says "calls slot N of vtable at address X" but the
   `function_name` in `simple_outbound_xrefs` may be a vtable slot
   label (e.g., `??_7CMyClass@@6B@+0x10`) rather than the implementing
   method name.

2. The IDA extractor already reconstructs vtable layouts in the
   `vtable_contexts` field per function, and the detailed
   `outbound_xrefs` has `vtable_info` with vtable address, method
   offsets, and resolved method names.  But the callgraph builder
   uses only `simple_outbound_xrefs` (which has the unresolved name).

3. `ChainAnalyzer` sees the vtable ref but cannot follow it because
   the target name does not resolve to a `function_id` in the DB.

---

## Proposed Solution

### 1. Vtable Target Resolution in CallGraph Construction

When building the graph from `simple_outbound_xrefs`, if an xref has
`function_type=8` and `function_id=None` (unresolved vtable target):

1. Look up the source function's `vtable_contexts` field
2. Match the vtable xref target name against the reconstructed vtable
   layout
3. If a match is found with a concrete method name that has a
   `function_id` in the DB, use that as the resolved target
4. If no match or low confidence, annotate the edge as
   `INDIRECT_VTABLE` and optionally follow it

This uses data already in the DB -- no new IDA extraction needed.

### 2. Confidence-Annotated Vtable Edges

Add edge confidence metadata to vtable-resolved edges:

| Resolution | Confidence | Follow? |
|------------|------------|---------|
| `vtable_contexts` match with known function_id | Confirmed | Yes |
| `outbound_xrefs.vtable_info` match with resolved method | Confirmed | Yes |
| No resolution possible (no vtable_contexts data) | Unresolved | No -- report as dead end |

### 3. ChainAnalyzer Vtable Following

Update `ChainAnalyzer.classify_xrefs()` to attempt vtable resolution
before routing to the `vtable_refs` dead-end bucket:

1. For each vtable xref, attempt resolution using `vtable_contexts`
2. If resolved to a known internal function, reclassify as `internal`
   and recurse into it
3. If resolved to an external module function, reclassify as
   `resolvable` or `unresolvable` per normal cross-module logic
4. If unresolved, keep in `vtable_refs` (current behavior)

### 4. CrossModuleGraph Vtable Awareness

When `CrossModuleGraph.reachable_from()` encounters a vtable edge with
an unresolved target, attempt the same resolution using the source
function's vtable_contexts before giving up.

---

## Architecture

### Data Already Available

| DB Field | Content | Resolution Use |
|----------|---------|----------------|
| `vtable_contexts` (per function) | Reconstructed class skeletons, vtable slot names, method names | Match slot labels to method names |
| `outbound_xrefs.vtable_info` (per xref) | Vtable address, name, method offsets/names, size | Detailed slot-to-method mapping |
| `function_xrefs` (relational table) | `function_type=8` rows with `target_name` | SQL-queryable vtable edges |
| `mangled_name` (per function) | MSVC mangled names encoding class + method | Match vtable class to function class |

### New Helper Function

Add to `helpers/callgraph.py`:

```python
def resolve_vtable_target(
    xref: dict,
    vtable_contexts: list[dict],
    name_to_id: dict[str, int],
) -> tuple[str | None, int | None, float]:
    """Attempt to resolve a vtable dispatch xref to a concrete function.

    Returns (resolved_name, function_id, confidence).
    """
```

This function:
1. Extracts the vtable slot label from the xref
2. Searches `vtable_contexts` for a matching vtable entry
3. Maps the slot offset to a method name
4. Looks up the method name in `name_to_id` for the function_id
5. Returns confidence based on how direct the resolution was

---

## Integration Points

| File | Change |
|------|--------|
| `helpers/callgraph.py` | Add `resolve_vtable_target()`; use it during graph construction for `function_type=8` xrefs |
| `skills/callgraph-tracer/scripts/chain_analysis.py` | Update `classify_xrefs()` to attempt vtable resolution before dead-ending |
| `helpers/cross_module_graph.py` | Use vtable resolution in `reachable_from()` |
| `docs/cross_module_callgraph_guide.md` | Document vtable resolution behavior |
| `config/defaults.json` | Add `callgraph.follow_resolved_vtable` (bool, default true) |

### No Changes Needed To

- The IDA extractor -- vtable_contexts data is already extracted
- The DB schema -- all needed data is already in the functions table
- AI scanner prepare_context.py -- it uses CrossModuleGraph which
  will gain vtable resolution automatically
- COM interface analysis skills -- they work with the COM index, not
  the callgraph

---

## What NOT to Build

- **No heuristic vtable guessing.** Only resolve vtable targets when
  the DB contains concrete `vtable_contexts` or `vtable_info` data.
  Do not guess based on class name similarity or method name patterns.
- **No new IDA extraction pass.** Use existing `vtable_contexts` and
  `outbound_xrefs.vtable_info` data.  If the extractor did not
  reconstruct a vtable, the edge stays unresolved.
- **No forced vtable following for unknown targets.** Unresolved
  vtable edges should be reported as dead ends, not silently dropped
  or speculatively followed.

---

## Impact

### Before (COM-heavy module like appinfo.dll)

```
NetrShareGetInfo -> SsShareInfoGet -> pVtable->Method3 -> STOP
                                      (vtable_refs: 12 unresolved)
```

The AI scanner's callgraph has 20 MUST_READ functions but misses
the 15 COM handler implementations behind vtable slots.

### After

```
NetrShareGetInfo -> SsShareInfoGet -> CShare::GetInfo (resolved via vtable_contexts)
                                      -> CShare::ValidateAccess
                                      -> CShare::BuildInfoStruct
                                      (vtable_refs: 3 unresolved -- no vtable_contexts data)
```

The AI scanner sees through COM dispatch into the actual handler code.

---

## Acceptance Criteria

1. `CallGraph.from_db()` resolves vtable targets using
   `vtable_contexts` when available
2. `ChainAnalyzer` follows resolved vtable targets into their code
3. `CrossModuleGraph.reachable_from()` follows resolved vtable targets
4. Resolved edges are annotated with confidence level
5. Unresolved vtable edges remain in `vtable_refs` (no silent drops)
6. `config/defaults.json` `callgraph.follow_resolved_vtable` controls
   the behavior (default: true)
7. AI scanner `prepare_context.py` automatically benefits (uses
   CrossModuleGraph)
8. No regression in callgraph construction performance (resolution
   lookup is O(1) per vtable xref via `name_to_id`)

---

## References

- [Cross-Module Callgraph Guide](../cross_module_callgraph_guide.md) --
  current vtable handling documentation
- [Data Format Reference](../data_format_reference.md) -- vtable_contexts
  and outbound_xrefs.vtable_info schemas
- `helpers/callgraph.py` -- `_is_followable_xref()`, `vtable_edges`
- `skills/callgraph-tracer/scripts/chain_analysis.py` --
  `ChainAnalyzer.classify_xrefs()` vtable dead-end behavior
