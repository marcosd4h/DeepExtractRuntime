# Deep Research Prompt Generator -- Technical Reference

## Prompt Generation Logic

### Evidence-Based Question Generation

Research questions are derived from gathered context, not from templates. The generator inspects each data source and creates questions based on what is actually present:

| Evidence Found | Generated Questions |
|----------------|-------------------|
| Function calls `CreateProcessW` | "What processes does this function spawn? What are the command line arguments? What security context?" |
| Cross-module call to `appinfo.dll` | "How does this function interact with the AppInfo service? What elevation/consent flow is triggered?" |
| Registry path strings found | "What registry keys are read/written? What configuration data is stored? What are the default values?" |
| COM interfaces detected | "What COM interfaces are used? What servers are activated? What threading model?" |
| Dispatch table with 10+ cases | "What command/message IDs are handled? What is the dispatch variable source? Are there undocumented handlers?" |
| Global variable writes | "What global state is modified? What is the initialization order? What are race conditions?" |
| Multiple parameters forwarded to APIs | "How are parameters validated before reaching the API? What transformations occur?" |
| Dangerous APIs detected | "What security-sensitive operations are performed? What privilege level is required?" |
| State machine pattern found | "What are the states and transitions? What triggers each transition? What are terminal states?" |
| Function is an export | "Who calls this export? What is the public contract? Are there undocumented behaviors?" |

### Research Question Priority Levels

**Priority 1 -- Core Behavior** (always generated):
- What does this function do? (derived from classification + API usage)
- What are the input/output contracts? (from signatures + data flow)
- What error handling exists? (from HRESULT patterns, GetLastError calls)

**Priority 2 -- Integration & Architecture** (when cross-refs exist):
- How does this function fit into the module's architecture?
- What calls this function? (from inbound xrefs)
- What is the activation/invocation path?

**Priority 3 -- Cross-Module Chains** (when cross-module calls are resolvable):
- What happens when external function X is called?
- What is the complete cross-DLL execution path?
- What data crosses module boundaries?

**Priority 4 -- Edge Cases & Error Handling** (when complexity signals exist):
- What happens on failure paths?
- What cleanup/rollback occurs?
- Are there resource leaks?

**Priority 5 -- Domain-Specific** (based on category):
- Security: token management, privilege checks, ACL operations
- COM/RPC: interface contracts, marshaling, threading model
- File I/O: file formats, locking, encoding
- Network: protocols, endpoints, authentication
- Crypto: algorithms, key management, IV handling

### Context Gathering Depth Control

The `--depth` parameter controls how deep the call graph and data flow analysis goes:

| Depth | What's Gathered | Use Case |
|-------|----------------|----------|
| 1 | Direct callees only | Quick overview of a function |
| 2 | Callees + their callees | Standard analysis |
| 3 (default) | 3 levels deep | Thorough analysis |
| 4-5 | Deep chain | Full cross-module flow tracing |

Cross-module resolution (`--cross-module`) adds significant context but is slower -- it queries `analyzed_files.db` and opens other module DBs to resolve external function implementations.

## Prompt Template Details

### Function-Level Prompt Template

```markdown
# Deep Research: {function_name}
## Module: {file_name} (v{version}, {company})

---

## 1. Target Description

**{function_name}** is a {classification_category} function in **{module_name}**
with an interest score of {interest_score}/10.

{classification_reasoning}

**Why research this function:**
- {evidence_based_reasons}

---

## 2. Known Context from Binary Analysis

### 2.1 Function Identity

| Property | Value |
|----------|-------|
| Name | {function_name} |
| Signature | {function_signature} |
| Extended Signature | {function_signature_extended} |
| Mangled Name | {mangled_name} |
| Module | {module_name} |
| Classification | {primary_category} ({secondary_categories}) |
| Interest Score | {interest_score}/10 |
| Assembly Size | {asm_instruction_count} instructions |
| Loop Count | {loop_count} |
| Cyclomatic Complexity | {cyclomatic_complexity} |

### 2.2 API Usage Profile

**Categorized outbound calls:**

{for each category in outbound_api_categories}
#### {category_name} APIs
| API | Module | Internal/External | Notes |
|-----|--------|-------------------|-------|
| {api_name} | {module} | {internal/external} | {annotation} |
{end for}

**Dangerous APIs:** {dangerous_api_list}

### 2.3 String Intelligence

{for each string_category}
#### {category_name}
- {string_value} (referenced in: {referencing_functions})
{end for}

### 2.4 Internal Call Graph

```
{function_name}
  +-- {callee_1} [{category}] ({instruction_count} instr)
  |   +-- {sub_callee_1}
  |   +-- {sub_callee_2}
  +-- {callee_2} [{category}] ({instruction_count} instr)
  +-- [EXTERNAL] {external_callee} -> {target_module}
```

**Graph metrics:**
- Internal callees: {count}
- External calls: {count} ({resolvable_count} resolvable)
- Max call depth: {depth}
- Total reachable functions: {reachable_count}

### 2.5 Cross-Module Integration

{for each resolvable_external_call}
#### {external_function} (in {target_module})
- **Resolved in:** {target_db_path}
- **That function's classification:** {target_classification}
- **That function calls:** {target_outbound_summary}
{end for}

**Unresolvable externals** (modules not in analysis set):
- {unresolvable_list}

### 2.6 Data Flow Summary

**Parameter flow:**
{for each parameter}
- Parameter {n} ({type}): forwarded to {api_calls_receiving_it}
{end for}

**Global state accessed:**
| Global | Access | Functions Sharing |
|--------|--------|-------------------|
| {global_name} | {Read/Write} | {shared_function_list} |

### 2.7 Structural Patterns

{if dispatch_table_detected}
**Dispatch Table:** {case_count} cases dispatching on {variable}
| Case | Value | Handler |
|------|-------|---------|
| {case_id} | {hex_value} | {handler_name} |
{end if}

{if com_interfaces_detected}
**COM Interfaces:**
- Implements: {interface_list}
- WRL RuntimeClass: {wrl_info}
{end if}

{if state_machine_detected}
**State Machine:** {state_count} states, {transition_count} transitions
{end if}

---

## 3. Research Questions

### Priority 1: Core Behavior
{numbered_questions derived from classification + API usage}

### Priority 2: Integration & Architecture
{numbered_questions derived from call graph + inbound xrefs}

### Priority 3: Cross-Module Chains
{numbered_questions derived from cross-module resolution}

### Priority 4: Edge Cases & Error Handling
{numbered_questions derived from complexity + error patterns}

### Priority 5: Domain-Specific ({category_name})
{numbered_questions specific to the function's primary category}

---

## 4. Requested Output

Write a comprehensive technical document covering:

1. **Purpose and role** -- What {function_name} does and why it exists
2. **Execution flow** -- Step-by-step walkthrough of the function's behavior
3. **Parameter contract** -- What each parameter means and valid ranges
4. **Call chain documentation** -- What happens at each internal/external call
5. **Error handling** -- How failures are detected and recovered from
6. **Cross-module interactions** -- Complete flow across DLL boundaries
7. **Integration with parent system** -- How this fits into {module_name}'s architecture
{if dispatch_table} 8. **Command/message dispatch** -- Complete handler table with descriptions {end if}
{if com_interfaces} 8. **COM interface contract** -- Interface methods and their semantics {end if}

Include:
- Mermaid diagrams for call flows and state machines where applicable
- Comparison tables for different execution paths
- Cross-references to related functions in the module
```

### Module-Area Prompt Template

```markdown
# Deep Research: {area_name} in {module_name}
## Module: {file_name} (v{version}, {company})

---

## 1. Area Description

The **{area_name}** area of **{module_name}** contains {function_count} functions
classified under: {category_list}.

**Module purpose:** {module_description}
**Area focus:** {area_description derived from API/string patterns}

---

## 2. Known Context

### 2.1 Functions in This Area (by interest score)

| Rank | Function | Score | Category | Key APIs | Dangerous |
|------|----------|-------|----------|----------|-----------|
| {rank} | {name} | {score}/10 | {category} | {top_apis} | {dangerous_count} |

### 2.2 Shared API Patterns
{APIs commonly used across functions in this area}

### 2.3 Shared String Patterns
{Strings commonly referenced by functions in this area}

### 2.4 Cross-Module Dependencies
{External modules called by functions in this area}

### 2.5 Internal Call Relationships
{How functions in this area call each other}

---

## 3. Research Questions

### Architecture
{Questions about how the area is organized}

### Per-Function Deep Dives
{For each top function: specific questions}

### Integration
{How this area integrates with rest of module and external modules}

---

## 4. Requested Output

Write a comprehensive document covering:
1. Architecture overview of the {area_name} subsystem
2. Per-function analysis for the top {N} functions
3. Cross-module interaction patterns
4. Complete API usage map
5. Security/trust boundary analysis (if security area)
```

## Script Output Formats

### gather_function_context.py JSON Schema

```json
{
  "target": {
    "function_name": "string",
    "function_id": "number",
    "function_signature": "string",
    "function_signature_extended": "string",
    "mangled_name": "string",
    "db_path": "string"
  },
  "module": {
    "file_name": "string",
    "file_description": "string",
    "company_name": "string",
    "file_version": "string"
  },
  "classification": {
    "primary_category": "string",
    "secondary_categories": ["string"],
    "interest_score": "number",
    "signals": {"category": ["signal_strings"]},
    "asm_metrics": {
      "instruction_count": "number",
      "call_count": "number",
      "branch_count": "number",
      "is_leaf": "boolean"
    }
  },
  "call_graph": {
    "internal_callees": [{"name": "string", "id": "number", "category": "string"}],
    "external_callees": [{"name": "string", "module": "string", "resolvable": "boolean", "target_db": "string"}],
    "callers": [{"name": "string", "id": "number"}],
    "reachable_count": "number",
    "max_depth": "number",
    "call_tree_summary": "string"
  },
  "data_flow": {
    "parameters": [{"index": "number", "forwarded_to": ["api_names"]}],
    "globals_accessed": [{"name": "string", "access_type": "string"}],
    "returns": "string"
  },
  "strings": {
    "categorized": {"category": ["string"]},
    "total_count": "number"
  },
  "dangerous_apis": ["string"],
  "patterns": {
    "has_dispatch_table": "boolean",
    "dispatch_case_count": "number",
    "has_state_machine": "boolean",
    "has_com_interfaces": "boolean",
    "com_interfaces": ["string"]
  },
  "decompiled_code": "string (optional, with --with-code)",
  "assembly_excerpt": "string (optional, with --with-code)"
}
```

### gather_module_context.py JSON Schema

```json
{
  "module": {
    "file_name": "string",
    "file_description": "string",
    "company_name": "string",
    "file_version": "string",
    "total_functions": "number",
    "total_classes": "number"
  },
  "category_distribution": {"category": "count"},
  "import_capabilities": {"category": ["api_names"]},
  "export_summary": [{"name": "string", "category": "string"}],
  "top_functions": [{
    "function_name": "string",
    "interest_score": "number",
    "primary_category": "string",
    "dangerous_api_count": "number",
    "key_apis": ["string"]
  }],
  "cross_module_deps": {"module_name": "function_count"},
  "string_summary": {"category": "count"},
  "com_density": {
    "com_function_count": "number",
    "com_classes": ["string"]
  },
  "architecture": {
    "classes": [{"name": "string", "method_count": "number"}],
    "named_function_pct": "number",
    "avg_complexity": "number"
  }
}
```
