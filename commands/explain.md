# Explain Function

## Overview

Get a quick, structured explanation of what a decompiled function does -- its purpose, parameters, key API calls, data flow, and call context -- without running a full audit or trace pipeline.

The text after `/explain` specifies the **function name** and optionally the **module**:
- `/explain AiLaunchProcess` -- searches all modules
- `/explain appinfo.dll AiLaunchProcess` -- targets specific module
- `/explain appinfo.dll AiLaunchProcess --depth 2` -- include callee code 2 levels deep
- `/explain appinfo.dll --search LaunchProcess` -- pattern search

If no function is specified, ask the user.

Default callee depth is 1 (direct callees only). Override with `--depth N` (0 = no callees, 2 = callees of callees, etc.). The script performs true BFS recursive traversal through the call chain, filtering boilerplate (WIL/CRT/ETW thunks) automatically.

## IMPORTANT: Execution Model

**This is an execute-immediately command. Do NOT present anything for user confirmation.** Run and write the final explanation straight to the chat as your response. The user expects to see the completed output.

## Execution Context

> **IMPORTANT**: Any inline Python that imports `helpers.*` must run with `cd <workspace>/.agent`
> (so the `.agent/` directory is on `sys.path`), **not** from the workspace root.
> Script invocations like `python .agent/skills/.../script.py` can be run from the workspace root
> because those scripts manage their own path setup.

## Steps

### Step 0: Preflight Validation

Validate arguments using `helpers.command_validation.validate_command_args("explain", {"module": "<module>", "function": "<function>"})`.
If validation fails, report the errors and stop. On success, use `result.resolved["db_path"]` for subsequent script calls.

1. **Locate the function**
   **Quick lookup**: Use `python .agent/skills/function-index/scripts/lookup_function.py <function_name>` to locate the function across all modules instantly.
   **Cross-dimensional search**: When the search term might match a string, API call, or class name, use `python .agent/helpers/unified_search.py <db_path> --query <term>` to search all dimensions at once.
   Otherwise, use the **decompiled-code-extractor** skill (`find_module_db.py` then `list_functions.py --search`) to resolve the module DB and exact function name.

> **Tip:** All skill scripts support `--json` for machine-readable output. Use `--json` when parsing script output programmatically.

2. **Gather explanation context**
   Use the **re-analyst** agent's `explain_function.py` to extract all context in one call.

   > **CRITICAL**: For `--depth >= 1`, always use `--output-file` to write the full JSON to a file.
   > Stdout is truncated at ~20,000 chars by the Shell tool, which silently discards callee code.
   > After the script completes, read the output file with the Read tool (chunked if needed)
   > before synthesizing. **Never rely on stdout for callee code.**

   ```bash
   # Standard invocation (writes full output to file, avoids stdout truncation)
   python .agent/agents/re-analyst/scripts/explain_function.py <db_path> <function_name> \
       --depth <N> --no-assembly --output-file .agent/workspace/explain_out.json

   # Then read the output file before synthesizing:
   # Use the Read tool on .agent/workspace/explain_out.json (chunked if large)
   # The callee_details array contains all callee code at every depth level

   # By function ID (from lookup)
   python .agent/agents/re-analyst/scripts/explain_function.py <db_path> --id <function_id> \
       --output-file .agent/workspace/explain_out.json

   # Quick mode (depth 0, no callees -- stdout is fine)
   python .agent/agents/re-analyst/scripts/explain_function.py <db_path> <function_name> --depth 0

   # JSON to stdout (only for depth 0 or when output is small)
   python .agent/agents/re-analyst/scripts/explain_function.py <db_path> <function_name> --depth 0 --json
   ```

   This returns: module context, function identity, classification, decompiled code, assembly, call chain breakdown, inbound callers, categorized strings, dangerous APIs, complexity metrics, and recursive callee code (BFS traversal to `--depth` levels, boilerplate filtered).

   For additional structured queries (class listing, exports, module overview), use `re_query.py`:

   ```bash
   python .agent/agents/re-analyst/scripts/re_query.py <db_path> --function <name> --context
   ```

   **Fallback** (if re-analyst agent scripts are unavailable): Use skill scripts to gather equivalent context:
   - **decompiled-code-extractor** skill (`extract_function_data.py`) for complete function data (decompiled code, assembly, strings, xrefs, stack frame, loops):
     ```bash
     python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> <function_name> --json
     python .agent/skills/decompiled-code-extractor/scripts/extract_function_data.py <db_path> --id <function_id> --json
     ```
   - **classify-functions** skill (`classify_function.py`) for function category and purpose classification:
     ```bash
     python .agent/skills/classify-functions/scripts/classify_function.py <db_path> <function_name> --json
     ```
   These two scripts together provide the data needed to synthesize the explanation.

  **Deep mode** (when the user requests `--depth 2` or thorough analysis): Run these scripts in parallel: `classify_function.py` (classification), `chain_analysis.py --depth 2` (call context), and `forward_trace.py` (data flow per parameter). These provide equivalent multi-skill context.

3. **Pre-Synthesis Comprehension Gate**

   Before synthesizing, build block-by-block understanding of the decompiled code to prevent hallucinated or surface-level explanations.

   For each logical block in the function, document **What** it does, **Why** it appears at this position, what **Assumptions** it relies on, and what **Invariants** it establishes. Apply at least one of: **First Principles** (what is the fundamental operation?), **5 Whys** (why does this block exist?), or **5 Hows** (how does data reach this point?).

   **Rationalizations to reject:** "I get the gist" misses edge cases in type casts and error paths. "The output is self-explanatory" ignores Hex-Rays approximation artifacts — cross-reference suspicious constructs against assembly. External calls are adversarial until confirmed safe via cross-module resolution.

   **Anti-hallucination:** Never reshape evidence to fit earlier assumptions. Use "Unclear; need to inspect X" instead of "It probably...". Per function: identify at minimum 3 invariants, 5 assumptions, and 3 risk considerations.

   IDA-specific awareness: recognize `HIDWORD`/`LODWORD` as 64-bit access macros, recovered `this` parameters, and vtable dispatch patterns (`call [reg+offset]`).

4. **Synthesize explanation**
   Using the gathered context, produce a structured explanation following this format:

   - **Purpose**: 1-2 sentences on what the function does at a business level
   - **Parameters**: table mapping IDA names (a1, a2) to inferred names, types, and purpose
   - **Return Value**: what the return value means (HRESULT, BOOL, pointer, etc.)
   - **Behavior**: step-by-step description of the function's logic
   - **Key API Calls**: table of notable APIs with purpose-in-context and risk level
   - **Strings Referenced**: notable string literals with context
   - **Call Context**: who calls this function, what it calls, cross-module transitions
   - **Confidence**: HIGH/MEDIUM/LOW with justification
   - **Decompiler Notes**: any artifacts or caveats about the decompiled output

   When including observations from reading the code beyond what automated scripts report (e.g., the Behavior walkthrough or Decompiler Notes), limit to 3 significant observations, require specific code/variable references, and label as `"Manual review -- not from automated analysis"` to distinguish from reproducible script output.

   **Confidence thresholds**:

   | Level  | Criteria                                                                                           |
   |--------|----------------------------------------------------------------------------------------------------|
   | HIGH   | Named function with complete decompilation, clear control flow, and recognizable API patterns      |
   | MEDIUM | Named function but incomplete decompilation, OR `sub_XXXX` with clear API patterns and control flow |
   | LOW    | `sub_XXXX` with partial decompilation, unclear control flow, or unrecognized API patterns          |

## Output

Present the explanation in chat using the structured format above. This is a lightweight retrieval command; file output is on-request only. When saving, use `extracted_code/<module_folder>/reports/explain_<function>_<timestamp>.md` and include a provenance header (generation date, module, function name, DB path).

**Follow-up suggestions**:
- `/audit <module> <function>` -- full security audit with risk assessment
- `/audit <module> <function> --diagram` -- full security audit with call graph diagram (if export)
- `/explain <module> <callee>` -- explain a callee mentioned in the call context

## Error Handling

- **Module not found**: List available modules via `find_module_db.py --list` and ask the user to choose
- **Function not found**: Run a fuzzy search via `--search` and suggest close matches
- **DB access failure**: Report the error with the DB path and suggest running `/health`
- **Missing decompiled code**: Report that the function has no decompiled output; offer assembly-based explanation
