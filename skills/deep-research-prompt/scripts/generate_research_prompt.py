#!/usr/bin/env python3
"""Generate structured deep research prompts from gathered context.

Main orchestrator: gathers context (or reads pre-gathered JSON), then
synthesizes a structured research prompt with evidence-based questions.

Usage:
    # Function-level prompt (gathers context automatically)
    python generate_research_prompt.py <db_path> <function_name>
    python generate_research_prompt.py <db_path> <function_name> --cross-module --depth 3

    # Area-level prompt (by function categories)
    python generate_research_prompt.py <db_path> --area security

    # From pre-gathered context JSON
    python generate_research_prompt.py --from-json context.json

    # Control detail level
    python generate_research_prompt.py <db_path> <function_name> --detail full

    # Write to file
    python generate_research_prompt.py <db_path> <function_name> --output research_prompt.md
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from _common import (
    WORKSPACE_ROOT,
    emit_error,
    parse_json_safe,
    resolve_db_path,
    truncate,
)
from helpers.errors import ErrorCode, db_error_handler, safe_parse_args
from helpers.json_output import emit_json

# Import gathering scripts
from gather_function_context import gather_full_context
from gather_module_context import gather_full_module_context

from helpers import (
    get_function_id,
    load_function_index_for_db,
    open_individual_analysis_db,
    search_index,
)


# ---------------------------------------------------------------------------
# Research question generators (evidence-based)
# ---------------------------------------------------------------------------

def _generate_core_questions(context: dict) -> list[str]:
    """Generate Priority 1 questions about core behavior."""
    questions = []
    target = context["target"]
    cls = context["classification"]
    cg = context["call_graph"]
    df = context["data_flow"]

    fname = target["function_name"]
    cat = cls["primary_category"]

    # Always: what does it do
    questions.append(f"What is the complete purpose and behavior of `{fname}`?")

    # Parameter contract
    sig = target.get("function_signature_extended") or target.get("function_signature", "")
    if sig and "(" in sig:
        questions.append(f"What does each parameter in `{sig}` represent? What are valid ranges and edge cases?")

    # Return value
    questions.append(f"What does the return value indicate? What are success/failure codes?")

    # Based on API calls
    api_cats = cg.get("api_by_category", {})
    for api_cat, apis in api_cats.items():
        if api_cat == "process_thread":
            questions.append(f"What processes or threads does `{fname}` create or manage? What are the command lines and security contexts?")
        elif api_cat == "file_io":
            questions.append(f"What files does `{fname}` read, write, or create? What are the file paths and access patterns?")
        elif api_cat == "registry":
            questions.append(f"What registry keys and values does `{fname}` access? What configuration data is stored?")
        elif api_cat == "security":
            questions.append(f"What security operations does `{fname}` perform? Token manipulation, ACL checks, privilege operations?")
        elif api_cat == "crypto":
            questions.append(f"What cryptographic operations does `{fname}` perform? Algorithms, key management, data protected?")
        elif api_cat == "network":
            questions.append(f"What network operations does `{fname}` perform? Endpoints, protocols, authentication?")
        elif api_cat in ("com_ole", "rpc"):
            questions.append(f"What COM/RPC interfaces does `{fname}` use? What servers are activated? Threading model?")
        elif api_cat == "memory":
            questions.append(f"What memory operations does `{fname}` perform? Allocations, mappings, protection changes?")

    # Error handling
    questions.append(f"How does `{fname}` handle errors? What cleanup occurs on failure paths?")

    return questions


def _generate_integration_questions(context: dict) -> list[str]:
    """Generate Priority 2 questions about integration and architecture."""
    questions = []
    target = context["target"]
    cg = context["call_graph"]
    module = context.get("module", {})

    fname = target["function_name"]

    # Who calls this
    if cg.get("callers"):
        caller_names = [c["name"] for c in cg["callers"][:5]]
        questions.append(f"How is `{fname}` invoked? Its callers include: {', '.join(caller_names)}. What triggers each call path?")

    # Internal architecture
    if cg["internal_callee_count"] > 3:
        questions.append(f"`{fname}` calls {cg['internal_callee_count']} internal functions. What is the internal call hierarchy and what role does each callee serve in the execution sequence?")

    # Module role
    mod_name = module.get("file_name", "")
    if mod_name:
        questions.append(f"What role does `{fname}` serve within the architecture of `{mod_name}`? Classify as entry point, utility, or infrastructure function.")

    # Reachability
    if cg.get("reachable_count", 0) > 10:
        questions.append(f"`{fname}` can reach {cg['reachable_count']} functions within {cg['max_depth']} levels. What is the scope of its execution subtree?")

    return questions


def _generate_cross_module_questions(context: dict) -> list[str]:
    """Generate Priority 3 questions about cross-module behavior."""
    questions = []
    cross = context.get("cross_module", [])
    target = context["target"]
    fname = target["function_name"]

    if not cross:
        return questions

    resolvable = [c for c in cross if c.get("resolvable")]
    unresolvable = [c for c in cross if not c.get("resolvable")]

    if resolvable:
        for c in resolvable[:5]:
            questions.append(
                f"Trace the execution flow from `{fname}` through `{c['name']}` in `{c['module']}` "
                f"across the module boundary. Document parameter passing and return value propagation."
            )

    # Group unresolvable by module
    if unresolvable:
        unres_modules = sorted(set(c.get("module", "?") for c in unresolvable))
        for mod in unres_modules[:5]:
            funcs = [c["name"] for c in unresolvable if c.get("module") == mod][:3]
            questions.append(
                f"`{fname}` calls into `{mod}` (functions: {', '.join(funcs)}). "
                f"Document the behavior of these external calls and the data transitions across this DLL boundary."
            )

    # Overall cross-module
    if len(resolvable) > 2:
        questions.append(
            f"Document the complete cross-module execution flow from `{fname}`, "
            f"showing how data and control passes through each DLL boundary."
        )

    return questions


def _generate_edge_case_questions(context: dict) -> list[str]:
    """Generate Priority 4 questions about edge cases and error handling."""
    questions = []
    cls = context["classification"]
    df = context["data_flow"]
    dangerous = context.get("dangerous_apis", [])

    if dangerous:
        questions.append(
            f"This function uses dangerous APIs: {', '.join(dangerous[:5])}. "
            f"What are the security implications? What validation precedes each call?"
        )

    if df.get("global_write_count", 0) > 0:
        questions.append("What global state does this function modify? Are there concurrency concerns?")

    if cls.get("loop_count", 0) > 0:
        questions.append("What are the loop termination conditions? Can any loop become infinite under edge case inputs?")

    branch_count = cls.get("asm_metrics", {}).get("branch_count", 0)
    if branch_count > 10:
        questions.append(f"With {branch_count} branch points, identify the low-frequency execution paths and their trigger conditions.")

    return questions


def _generate_domain_questions(context: dict) -> list[str]:
    """Generate Priority 5 domain-specific questions based on category."""
    questions = []
    cls = context["classification"]
    cat = cls["primary_category"]
    patterns = context.get("patterns", {})
    strings = context.get("strings", {})

    domain_q = {
        "security": [
            "What tokens are created, duplicated, or validated?",
            "What privilege checks or adjustments are made?",
            "What ACL operations are performed? What permissions are set?",
            "How does impersonation/revert flow work?",
        ],
        "process_thread": [
            "What is the complete process creation flow (command line, environment, token)?",
            "How are child processes monitored or controlled?",
            "What thread synchronization is used?",
        ],
        "com_ole": [
            "What COM interfaces are implemented or consumed?",
            "What is the threading/apartment model?",
            "How are COM objects marshaled across boundaries?",
        ],
        "rpc": [
            "What RPC protocols and endpoints are used?",
            "What NDR marshaling interfaces are invoked?",
            "How is RPC authentication configured?",
        ],
        "crypto": [
            "What cryptographic algorithms are used?",
            "How are keys managed (generation, storage, rotation)?",
            "What data is encrypted/decrypted/signed?",
            "Are there any weak algorithm choices?",
        ],
        "file_io": [
            "What file formats are read or written?",
            "How is file locking handled?",
            "What encoding/character set is used?",
        ],
        "registry": [
            "What is the complete registry key/value schema?",
            "What are the default values for each registry entry?",
            "How are registry access failures handled?",
        ],
        "network": [
            "What network protocols and ports are used?",
            "How is authentication handled?",
            "What is the connection lifecycle?",
        ],
        "dispatch_routing": [
            "What is the complete dispatch table (case value -> handler)?",
            "What is the source of the dispatch variable?",
            "Are there undocumented or reserved case values?",
        ],
        "initialization": [
            "What is the initialization order and dependencies?",
            "What happens if initialization fails partway?",
            "What resources are allocated during init?",
        ],
    }

    if cat in domain_q:
        questions.extend(domain_q[cat])

    # Pattern-specific
    if patterns.get("has_dispatch_table"):
        questions.append(f"Map all {patterns.get('dispatch_case_count', 0)} dispatch cases to their handler functions and document each handler's purpose.")
    if patterns.get("has_state_machine"):
        questions.append("Reconstruct the complete state machine: all states, transitions, triggers, and terminal conditions.")
    if patterns.get("has_com_interfaces"):
        questions.append("Reconstruct the COM interface definitions with method signatures and document the QueryInterface dispatch logic.")

    # String-based
    categorized = strings.get("categorized", {})
    if "registry_key" in categorized:
        questions.append(f"Document all registry keys referenced: {', '.join(categorized['registry_key'][:3])}")
    if "guid" in categorized:
        questions.append(f"Identify all GUIDs: {', '.join(categorized['guid'][:3])}. What interfaces/classes do they identify?")
    if "named_pipe" in categorized:
        questions.append(f"Document the named pipe communication: {', '.join(categorized['named_pipe'][:3])}")
    if "rpc_endpoint" in categorized:
        questions.append(f"Document the RPC endpoint: {', '.join(categorized['rpc_endpoint'][:3])}")

    return questions


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def generate_function_prompt(context: dict, detail: str = "full") -> str:
    """Generate a complete research prompt from function context."""
    target = context["target"]
    module = context.get("module", {})
    cls = context["classification"]
    cg = context["call_graph"]
    df = context["data_flow"]
    strings = context.get("strings", {})
    dangerous = context.get("dangerous_apis", [])
    patterns = context.get("patterns", {})

    fname = target["function_name"]
    mod_name = module.get("file_name", "unknown module")
    version = module.get("file_version", "")
    company = module.get("company_name", "")

    lines = []

    # Title
    lines.append(f"# Deep Research: {fname}")
    lines.append(f"## Module: {mod_name}" + (f" (v{version}, {company})" if version else ""))
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1: Target Description
    lines.append("## 1. Target Description")
    lines.append("")
    lines.append(
        f"**{fname}** is a **{cls['primary_category']}** function in **{mod_name}** "
        f"with an interest score of **{cls['interest_score']}/10**."
    )
    if cls.get("secondary_categories"):
        lines.append(f"Secondary categories: {', '.join(cls['secondary_categories'])}.")
    lines.append("")

    # Why research this
    reasons = []
    if cls["interest_score"] >= 6:
        reasons.append(f"High interest score ({cls['interest_score']}/10)")
    if dangerous:
        reasons.append(f"Uses dangerous APIs: {', '.join(dangerous[:3])}")
    if cg.get("reachable_count", 0) > 10:
        reasons.append(f"Execution subtree: {cg['reachable_count']} reachable functions")
    if cg.get("external_callee_count", 0) > 3:
        reasons.append(f"Cross-module interaction: {cg['external_callee_count']} external calls")
    if patterns.get("has_dispatch_table"):
        reasons.append(f"Contains dispatch table ({patterns.get('dispatch_case_count', 0)} cases)")
    if patterns.get("has_com_interfaces"):
        reasons.append("Involves COM interfaces")
    if cls.get("asm_metrics", {}).get("instruction_count", 0) > 200:
        reasons.append(f"Function size: {cls['asm_metrics']['instruction_count']} assembly instructions")

    if reasons:
        lines.append("**Why research this function:**")
        for r in reasons:
            lines.append(f"- {r}")
        lines.append("")

    # Section 2: Known Context
    lines.append("---")
    lines.append("")
    lines.append("## 2. Known Context from Binary Analysis")
    lines.append("")

    # 2.1 Identity
    lines.append("### 2.1 Function Identity")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| Name | `{fname}` |")
    lines.append(f"| Signature | `{target.get('function_signature', 'N/A')}` |")
    if target.get("function_signature_extended") and target["function_signature_extended"] != target.get("function_signature"):
        lines.append(f"| Extended Signature | `{target['function_signature_extended']}` |")
    lines.append(f"| Mangled Name | `{target.get('mangled_name', 'N/A')}` |")
    lines.append(f"| Module | {mod_name} |")
    lines.append(f"| Classification | {cls['primary_category']} |")
    lines.append(f"| Interest Score | {cls['interest_score']}/10 |")
    asm = cls.get("asm_metrics", {})
    lines.append(f"| Assembly Size | {asm.get('instruction_count', 0)} instructions |")
    lines.append(f"| Loops | {cls.get('loop_count', 0)} |")
    lines.append("")

    # 2.2 API Usage
    api_cats = cg.get("api_by_category", {})
    if api_cats:
        lines.append("### 2.2 API Usage Profile")
        lines.append("")
        for cat, apis in sorted(api_cats.items(), key=lambda x: -len(x[1])):
            lines.append(f"**{cat.replace('_', ' ').title()}** ({len(apis)} calls): {', '.join(sorted(set(apis)))}")
            lines.append("")

    if dangerous:
        lines.append(f"**Dangerous APIs:** {', '.join(dangerous)}")
        lines.append("")

    # 2.3 Strings
    categorized = strings.get("categorized", {})
    if categorized:
        lines.append("### 2.3 String Intelligence")
        lines.append("")
        for cat, items in sorted(categorized.items(), key=lambda x: -len(x[1])):
            if cat == "other" and len(items) > 10:
                lines.append(f"**{cat}** ({len(items)} strings): _(see full list in gathered context)_")
            else:
                shown = items[:5]
                lines.append(f"**{cat}** ({len(items)}):")
                for s in shown:
                    lines.append(f"- `{truncate(s, 100)}`")
                if len(items) > 5:
                    lines.append(f"- _... and {len(items) - 5} more_")
            lines.append("")

    # 2.4 Call Graph
    lines.append("### 2.4 Internal Call Graph")
    lines.append("")
    lines.append(f"- Internal callees: **{cg['internal_callee_count']}**")
    lines.append(f"- External callees: **{cg['external_callee_count']}**")
    lines.append(f"- Callers: **{cg['caller_count']}**")
    lines.append(f"- Reachable functions (depth {cg['max_depth']}): **{cg.get('reachable_count', 0)}**")
    lines.append("")

    if cg["internal_callees"]:
        lines.append("**Internal callees:**")
        lines.append("")
        lines.append("| Function | Category | ID |")
        lines.append("|----------|----------|----|")
        for c in cg["internal_callees"][:20]:
            lines.append(f"| `{c['name']}` | {c['category']} | {c['id']} |")
        if len(cg["internal_callees"]) > 20:
            lines.append(f"| _... {len(cg['internal_callees']) - 20} more_ | | |")
        lines.append("")

    if cg["external_callees"]:
        lines.append("**External callees:**")
        lines.append("")
        lines.append("| Function | Module | Category |")
        lines.append("|----------|--------|----------|")
        for c in cg["external_callees"][:20]:
            lines.append(f"| `{c['name']}` | {c['module']} | {c['category']} |")
        if len(cg["external_callees"]) > 20:
            lines.append(f"| _... {len(cg['external_callees']) - 20} more_ | | |")
        lines.append("")

    # 2.5 Cross-module
    if "cross_module" in context:
        lines.append("### 2.5 Cross-Module Integration")
        lines.append("")
        summary = context.get("cross_module_summary", {})
        lines.append(f"- Total external calls: **{summary.get('total_external', 0)}**")
        lines.append(f"- Resolvable (module analyzed): **{summary.get('resolvable', 0)}**")
        lines.append(f"- Unresolvable (module not analyzed): **{summary.get('unresolvable', 0)}**")
        lines.append("")

        resolvable = [c for c in context["cross_module"] if c.get("resolvable")]
        if resolvable:
            lines.append("**Resolvable external calls (can be traced):**")
            lines.append("")
            for c in resolvable[:10]:
                lines.append(f"- `{c['name']}` in `{c['module']}` -> DB: `{c['target_db']}`")
            lines.append("")

        unresolvable = [c for c in context["cross_module"] if not c.get("resolvable")]
        if unresolvable:
            modules = sorted(set(c.get("module", "?") for c in unresolvable))
            lines.append("**Unresolvable external calls (reference documentation):**")
            lines.append("")
            for m in modules[:10]:
                funcs = [c["name"] for c in unresolvable if c.get("module") == m]
                lines.append(f"- `{m}`: {', '.join(funcs[:5])}{' ...' if len(funcs) > 5 else ''}")
            lines.append("")

    # 2.6 Data flow
    if df.get("globals_accessed"):
        lines.append("### 2.6 Data Flow Summary")
        lines.append("")
        lines.append(f"- Global reads: **{df.get('global_read_count', 0)}**")
        lines.append(f"- Global writes: **{df.get('global_write_count', 0)}**")
        lines.append("")
        if df["globals_accessed"]:
            lines.append("| Global | Access | Address |")
            lines.append("|--------|--------|---------|")
            for g in df["globals_accessed"][:15]:
                lines.append(f"| `{g['name']}` | {g['access_type']} | {g['address']} |")
            lines.append("")

    # 2.7 Patterns
    if any([patterns.get("has_dispatch_table"), patterns.get("has_state_machine"),
            patterns.get("has_com_interfaces")]):
        lines.append("### 2.7 Structural Patterns")
        lines.append("")
        if patterns.get("has_dispatch_table"):
            lines.append(f"- **Dispatch table**: {patterns.get('dispatch_case_count', 0)} cases detected")
        if patterns.get("has_state_machine"):
            lines.append("- **State machine**: dispatch-in-loop pattern detected")
        if patterns.get("has_com_interfaces"):
            ifaces = patterns.get("com_interfaces", [])
            lines.append(f"- **COM interfaces**: {len(ifaces)} detected")
            for iface in ifaces[:3]:
                lines.append(f"  - `{truncate(str(iface), 100)}`")
        lines.append("")

    # Decompiled code (if included)
    if "decompiled_code" in context and detail == "full":
        lines.append("### 2.8 Decompiled Code")
        lines.append("")
        lines.append("```cpp")
        code = context["decompiled_code"]
        code_lines = code.splitlines()
        if len(code_lines) > 150:
            lines.extend(code_lines[:150])
            lines.append(f"// ... ({len(code_lines) - 150} more lines)")
        else:
            lines.extend(code_lines)
        lines.append("```")
        lines.append("")

    # Section 3: Research Questions
    lines.append("---")
    lines.append("")
    lines.append("## 3. Research Questions")
    lines.append("")

    q1 = _generate_core_questions(context)
    q2 = _generate_integration_questions(context)
    q3 = _generate_cross_module_questions(context)
    q4 = _generate_edge_case_questions(context)
    q5 = _generate_domain_questions(context)

    if q1:
        lines.append("### Priority 1: Core Behavior")
        lines.append("")
        for i, q in enumerate(q1, 1):
            lines.append(f"{i}. {q}")
        lines.append("")

    if q2:
        lines.append("### Priority 2: Integration & Architecture")
        lines.append("")
        for i, q in enumerate(q2, 1):
            lines.append(f"{i}. {q}")
        lines.append("")

    if q3:
        lines.append("### Priority 3: Cross-Module Chains")
        lines.append("")
        for i, q in enumerate(q3, 1):
            lines.append(f"{i}. {q}")
        lines.append("")

    if q4:
        lines.append("### Priority 4: Edge Cases & Error Handling")
        lines.append("")
        for i, q in enumerate(q4, 1):
            lines.append(f"{i}. {q}")
        lines.append("")

    if q5:
        lines.append(f"### Priority 5: Domain-Specific ({cls['primary_category'].replace('_', ' ').title()})")
        lines.append("")
        for i, q in enumerate(q5, 1):
            lines.append(f"{i}. {q}")
        lines.append("")

    # Section 4: Requested Output
    lines.append("---")
    lines.append("")
    lines.append("## 4. Requested Output")
    lines.append("")
    lines.append("Produce a technical document covering:")
    lines.append("")
    lines.append(f"1. **Purpose and role** -- What `{fname}` does and why it exists in `{mod_name}`")
    lines.append(f"2. **Execution flow** -- Step-by-step walkthrough of `{fname}`'s behavior")
    lines.append(f"3. **Parameter contract** -- What each parameter means, valid ranges, edge cases")
    lines.append(f"4. **Internal call chain** -- What happens at each significant internal call")
    if cg.get("external_callee_count", 0) > 0:
        lines.append(f"5. **Cross-module interactions** -- Complete flow across DLL boundaries")
    lines.append(f"6. **Error handling** -- How failures are detected, reported, and recovered from")
    lines.append(f"7. **Integration with `{mod_name}`** -- How `{fname}` fits into the module's architecture")

    extra_num = 8
    if patterns.get("has_dispatch_table"):
        lines.append(f"{extra_num}. **Dispatch table** -- Complete case->handler mapping with handler documentation")
        extra_num += 1
    if patterns.get("has_com_interfaces"):
        lines.append(f"{extra_num}. **COM interface contract** -- Interface methods, vtable layout, QI dispatch")
        extra_num += 1
    if patterns.get("has_state_machine"):
        lines.append(f"{extra_num}. **State machine** -- All states, transitions, triggers, terminal conditions")
        extra_num += 1

    lines.append("")
    lines.append("**Include:**")
    lines.append("- Mermaid diagrams for call flows and state machines where applicable")
    lines.append("- Comparison tables for different execution paths")
    lines.append("- Cross-references to related functions in the module")
    lines.append("- Annotated code snippets for complex logic")
    lines.append("")

    # Section 5: Suggested Skill Commands
    lines.append("---")
    lines.append("")
    lines.append("## 5. Suggested Follow-Up Commands")
    lines.append("")
    lines.append("Use these commands to gather additional data during research:")
    lines.append("")

    db_path = context.get("db_path", "<db_path>")
    lines.append(f"```bash")
    lines.append(f"# Detailed function data (decompiled code + assembly)")
    lines.append(f"python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py {db_path} {fname}")
    lines.append(f"")
    lines.append(f"# Call graph with cross-module chain (follow specific callee)")
    lines.append(f"python .agent/skills/callgraph-tracer/scripts/chain_analysis.py {db_path} {fname} --depth 3 --summary")
    lines.append(f"")
    lines.append(f"# Detailed classification with all signals")
    lines.append(f"python .agent/skills/classify-functions/scripts/classify_function.py {db_path} {fname}")
    lines.append(f"")
    lines.append(f"# Forward parameter trace (param 1)")
    lines.append(f"python .agent/skills/data-flow-tracer/scripts/forward_trace.py {db_path} {fname} --param 1 --depth 2")
    lines.append(f"")
    lines.append(f"# String usage context")
    lines.append(f"python .agent/skills/data-flow-tracer/scripts/string_trace.py {db_path} --function {fname}")

    if patterns.get("has_dispatch_table"):
        lines.append(f"")
        lines.append(f"# Extract dispatch table")
        lines.append(f"python .agent/skills/state-machine-extractor/scripts/extract_dispatch_table.py {db_path} {fname}")

    if patterns.get("has_com_interfaces"):
        lines.append(f"")
        lines.append(f"# COM interface scan")
        lines.append(f"python .agent/skills/com-interface-reconstruction/scripts/scan_com_interfaces.py {db_path}")

    lines.append(f"")
    lines.append(f"# Full RE report for the module")
    lines.append(f"python .agent/skills/generate-re-report/scripts/generate_report.py {db_path}")
    lines.append(f"```")
    lines.append("")

    return "\n".join(lines)


def generate_area_prompt(context: dict, area: str) -> str:
    """Generate an area-level research prompt from module context."""
    module = context.get("module", {})
    dist = context.get("category_distribution", {})
    top_funcs = context.get("top_functions", [])
    imports = context.get("import_capabilities", {})
    cross_deps = context.get("cross_module_deps", {})
    string_summary = context.get("string_summary", {})

    mod_name = module.get("file_name", "unknown module")
    version = module.get("file_version", "")
    company = module.get("company_name", "")

    lines = []

    lines.append(f"# Deep Research: {area.replace('_', ' ').title()} in {mod_name}")
    lines.append(f"## Module: {mod_name}" + (f" (v{version}, {company})" if version else ""))
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1
    lines.append("## 1. Area Description")
    lines.append("")
    area_funcs = [f for f in top_funcs if f["primary_category"] == area]
    area_count = dist.get(area, 0)
    total = context.get("total_functions", 0)
    lines.append(
        f"The **{area.replace('_', ' ')}** area of **{mod_name}** contains "
        f"**{area_count}** functions ({area_count / total * 100:.1f}% of {total} total)."
    )
    lines.append("")
    if module.get("file_description"):
        lines.append(f"**Module purpose:** {module['file_description']}")
        lines.append("")

    # Section 2: Functions in this area
    lines.append("---")
    lines.append("")
    lines.append("## 2. Known Context")
    lines.append("")
    lines.append(f"### 2.1 Functions in This Area (by interest score)")
    lines.append("")
    if area_funcs:
        lines.append("| Rank | Function | Score | Dangerous | ASM Size |")
        lines.append("|------|----------|-------|-----------|----------|")
        for i, f in enumerate(area_funcs[:25], 1):
            lines.append(f"| {i} | `{f['function_name']}` | {f['interest_score']}/10 | {f['dangerous_api_count']} | {f['asm_instruction_count']} |")
        if len(area_funcs) > 25:
            lines.append(f"| ... | _{len(area_funcs) - 25} more functions_ | | | |")
    else:
        lines.append("_(No functions classified in this area)_")
    lines.append("")

    # Import capabilities for this area
    caps = imports.get("capabilities", {})
    if area in caps:
        lines.append(f"### 2.2 Imported {area.replace('_', ' ').title()} APIs")
        lines.append("")
        for api in sorted(caps[area]):
            lines.append(f"- `{api}`")
        lines.append("")

    # Cross-module
    if cross_deps:
        lines.append("### 2.3 Cross-Module Dependencies")
        lines.append("")
        for mod, count in sorted(cross_deps.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"- `{mod}`: {count} calls")
        lines.append("")

    # Strings
    if string_summary:
        lines.append("### 2.4 String Intelligence")
        lines.append("")
        for cat, items in sorted(string_summary.items(), key=lambda x: -len(x[1])):
            if items:
                lines.append(f"**{cat}** ({len(items)}):")
                for s in items[:3]:
                    lines.append(f"- `{truncate(s, 80)}`")
                if len(items) > 3:
                    lines.append(f"- _... and {len(items) - 3} more_")
                lines.append("")

    # Section 3: Research Questions
    lines.append("---")
    lines.append("")
    lines.append("## 3. Research Questions")
    lines.append("")

    lines.append("### Architecture")
    lines.append("")
    lines.append(f"1. How is the {area.replace('_', ' ')} subsystem organized in `{mod_name}`?")
    lines.append(f"2. What is the entry point into the {area.replace('_', ' ')} functionality?")
    lines.append(f"3. How do the {area_count} {area.replace('_', ' ')} functions relate to each other (call graph)?")
    lines.append("")

    lines.append("### Per-Function Deep Dives")
    lines.append("")
    for i, f in enumerate(area_funcs[:10], 1):
        lines.append(f"{i}. What does `{f['function_name']}` do in detail? (interest: {f['interest_score']}/10)")
    lines.append("")

    lines.append("### Integration")
    lines.append("")
    lines.append(f"1. How does the {area.replace('_', ' ')} subsystem interact with other parts of `{mod_name}`?")
    if cross_deps:
        top_dep = list(cross_deps.keys())[0]
        lines.append(f"2. What is the relationship between `{mod_name}` and `{top_dep}` for {area.replace('_', ' ')} operations?")
    lines.append("")

    # Section 4: Requested output
    lines.append("---")
    lines.append("")
    lines.append("## 4. Requested Output")
    lines.append("")
    lines.append("Produce a technical document covering:")
    lines.append("")
    lines.append(f"1. Architecture overview of the {area.replace('_', ' ')} subsystem in `{mod_name}`")
    lines.append(f"2. Per-function analysis for the top {min(len(area_funcs), 10)} functions")
    lines.append(f"3. Cross-module interaction patterns for {area.replace('_', ' ')} operations")
    lines.append(f"4. Complete API usage map for {area.replace('_', ' ')} functions")
    lines.append(f"5. Call graph showing how {area.replace('_', ' ')} functions relate to each other")
    lines.append("")

    # Section 5: Commands
    lines.append("---")
    lines.append("")
    lines.append("## 5. Suggested Follow-Up Commands")
    lines.append("")
    db_path = context.get("db_path", "<db_path>")
    lines.append("```bash")
    lines.append(f"# Classify all {area} functions")
    lines.append(f"python .agent/skills/classify-functions/scripts/classify_module.py {db_path} --category {area}")
    lines.append(f"")
    lines.append(f"# Full module report")
    lines.append(f"python .agent/skills/generate-re-report/scripts/generate_report.py {db_path}")
    if area_funcs:
        top_func = area_funcs[0]["function_name"]
        lines.append(f"")
        lines.append(f"# Deep context for top function")
        lines.append(f"python .agent/skills/deep-research-prompt/scripts/gather_function_context.py {db_path} {top_func} --cross-module --with-code")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deep research prompts from analysis DBs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("db_path", nargs="?", help="Path to the individual analysis DB")
    parser.add_argument("--function", "--name", dest="function_name", metavar="NAME",
                        help="Function name to research")
    parser.add_argument("function_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--id", "--function-id", type=int, dest="function_id", help="Function ID")
    parser.add_argument("--area", help="Generate area-level prompt for a function category (e.g., security)")
    parser.add_argument("--from-json", dest="from_json", help="Read pre-gathered context from JSON file")
    parser.add_argument("--depth", type=int, default=3, help="Call graph depth (default: 3)")
    parser.add_argument("--cross-module", action="store_true", help="Resolve external calls to analyzed modules")
    parser.add_argument("--detail", choices=["brief", "full"], default="full", help="Prompt detail level")
    parser.add_argument("--output", help="Write prompt to file instead of stdout")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = safe_parse_args(parser)
    if args.function_name_pos and not args.function_name:
        args.function_name = args.function_name_pos

    prompt = ""

    if args.from_json:
        # Read pre-gathered context
        json_path = Path(args.from_json)
        if not json_path.exists():
            emit_error(f"File not found: {args.from_json}", ErrorCode.NOT_FOUND)
        with open(json_path, "r", encoding="utf-8", errors="replace") as f:
            context = json.load(f)
        prompt = generate_function_prompt(context, detail=args.detail)

    elif args.area:
        if not args.db_path:
            emit_error("db_path is required for area-level prompts", ErrorCode.INVALID_ARGS)
        db_path = resolve_db_path(args.db_path)
        with db_error_handler(db_path, "generating research prompt"):
            with open_individual_analysis_db(db_path) as db:
                context = gather_full_module_context(db_path=db_path, db=db, filter_categories=[args.area], top_n=25)
            prompt = generate_area_prompt(context, args.area)

    elif args.function_name or args.function_id is not None:
        if not args.db_path:
            emit_error("db_path is required for function-level prompts", ErrorCode.INVALID_ARGS)
        db_path = resolve_db_path(args.db_path)
        function_index = load_function_index_for_db(db_path)

        with db_error_handler(db_path, "generating research prompt"):
            with open_individual_analysis_db(db_path) as db:
                func = None
                if args.function_id is not None:
                    func = db.get_function_by_id(args.function_id)
                    if func is None:
                        emit_error(f"No function with ID {args.function_id}.", ErrorCode.NOT_FOUND)
                else:
                    if function_index:
                        exact_entry = function_index.get(args.function_name)
                        if exact_entry:
                            function_id = get_function_id(exact_entry)
                            if function_id is not None:
                                func = db.get_function_by_id(function_id)
                    if func is None and function_index:
                        partial = search_index(function_index, args.function_name)
                        if len(partial) > 1:
                            lines = [f"Multiple matches for '{args.function_name}':"]
                            for name, entry in sorted(partial.items()):
                                fid = get_function_id(entry)
                                lines.append(f"  ID {fid if fid is not None else '?'}: {name}")
                            lines.append("Use --id <ID> to select one.")
                            emit_error("\n".join(lines), ErrorCode.AMBIGUOUS)
                        if len(partial) == 1:
                            _, entry = next(iter(partial.items()))
                            function_id = get_function_id(entry)
                            if function_id is not None:
                                func = db.get_function_by_id(function_id)
                    if func is None:
                        matches = db.get_function_by_name(args.function_name)
                        if not matches:
                            matches = db.search_functions(name_contains=args.function_name)
                        if not matches:
                            emit_error(f"No function matching '{args.function_name}'.", ErrorCode.NOT_FOUND)
                        if len(matches) > 1:
                            lines = [f"Multiple matches for '{args.function_name}':"]
                            for m in matches:
                                lines.append(f"  ID {m.function_id}: {m.function_name}")
                            lines.append("Use --id <ID> to select one.")
                            emit_error("\n".join(lines), ErrorCode.AMBIGUOUS)
                        func = matches[0]

                context = gather_full_context(
                    db_path=db_path,
                    func=func,
                    db=db,
                    depth=args.depth,
                    cross_module=args.cross_module,
                    with_code=(args.detail == "full"),
                )

            prompt = generate_function_prompt(context, detail=args.detail)

    else:
        emit_error("Provide a function name, --id, --area, or --from-json", ErrorCode.INVALID_ARGS)

    if args.json:
        emit_json({
            "status": "ok",
            "prompt": prompt,
            "function_name": getattr(args, "function_name", None),
            "depth": args.depth,
        })
    elif args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(prompt, encoding="utf-8")
        print(f"Research prompt written to: {out_path}")
    else:
        print(prompt)


if __name__ == "__main__":
    main()
