"""Lightweight def-use chain analysis for IDA Hex-Rays decompiled C output.

Parses decompiled code into variable definitions and uses, builds def-use
chains, and propagates taint through assignments and struct field accesses.
This provides significantly better taint precision than call-site-only
regex matching by tracking data flow through local variables.

Designed for IDA naming conventions: ``a1..aN`` for parameters,
``v1..vN`` for locals, ``*(_TYPE *)(var + offset)`` for struct accesses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# IDA variable naming patterns
# ---------------------------------------------------------------------------

_VAR_RE = re.compile(r"\b(a\d+|v\d+)\b")
_IDA_KEYWORDS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "else", "do",
    "goto", "case", "break", "continue", "default",
    "LODWORD", "HIDWORD", "LOBYTE", "HIBYTE", "LOWORD", "HIWORD",
    "BYTE1", "BYTE2", "BYTE3", "BYTE4", "COERCE_FLOAT",
    "SHIDWORD", "SLODWORD",
})

# Assignment LHS patterns:
#   v5 = expr;
#   LODWORD(v5) = expr;
#   *(_QWORD *)(v5 + 8) = expr;
#   v5->field = expr;
#   v5[index] = expr;
_SIMPLE_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:LODWORD|HIDWORD|LOBYTE|HIBYTE|LOWORD|HIWORD)"
    r"\s*\(\s*)?(\w+)\s*\)?\s*(?:[+\-*/%&|^]|<<|>>)?=[^=]",
)

_DEREF_WRITE_RE = re.compile(
    r"^\s*\*\s*\([^)]*\)\s*\(\s*(\w+)\s*[+\-]",
)

_ARROW_WRITE_RE = re.compile(
    r"^\s*(\w+)\s*->\s*\w+\s*=[^=]",
)

_ARRAY_WRITE_RE = re.compile(
    r"^\s*(\w+)\s*\[.+?\]\s*=[^=]",
)

# Function call pattern
_FUNC_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")

# Struct field read: v5 = *(TYPE *)(var + offset) or v5 = var->field
_STRUCT_READ_RE = re.compile(
    r"\*\s*\([^)]*\)\s*\(\s*(\w+)\s*[+\-]"
    r"|(\w+)\s*->\s*\w+",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VarDef:
    """A variable definition (assignment target)."""
    var: str
    line: int
    rhs_expr: str
    rhs_vars: list[str] = field(default_factory=list)


@dataclass
class VarUse:
    """A variable use site."""
    var: str
    line: int
    context: str  # call_arg, condition, return, array_index, struct_write, assignment_rhs
    target_func: Optional[str] = None
    arg_position: Optional[int] = None


@dataclass
class TaintResult:
    """Result of taint propagation through def-use chains."""
    tainted_vars: set[str] = field(default_factory=set)
    tainted_calls: list[dict] = field(default_factory=list)
    tainted_conditions: list[dict] = field(default_factory=list)
    tainted_returns: list[dict] = field(default_factory=list)
    tainted_struct_writes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tainted_vars": sorted(self.tainted_vars),
            "tainted_calls": self.tainted_calls,
            "tainted_conditions": self.tainted_conditions,
            "tainted_returns": self.tainted_returns,
            "tainted_struct_writes": self.tainted_struct_writes,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _extract_vars(expr: str) -> list[str]:
    """Extract all IDA variable references from an expression."""
    return list(dict.fromkeys(m.group(1) for m in _VAR_RE.finditer(expr)))


def _extract_call_args(line: str) -> list[tuple[str, int, str]]:
    """Extract (callee_name, arg_position, arg_expr) from function calls in a line.

    Returns a list of tuples for each call argument that contains a variable.
    """
    from .decompiled_parser import extract_function_calls, split_arguments

    results: list[tuple[str, int, str]] = []
    for m in _FUNC_CALL_RE.finditer(line):
        fname = m.group(1)
        if fname in _IDA_KEYWORDS:
            continue
        paren_start = m.end() - 1
        depth = 0
        end = paren_start
        for i in range(paren_start, len(line)):
            if line[i] == "(":
                depth += 1
            elif line[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if depth != 0:
            continue
        args_str = line[paren_start + 1:end]
        args = split_arguments(args_str)
        for pos, arg_expr in enumerate(args):
            results.append((fname, pos, arg_expr))
    return results


def parse_def_use(code: str) -> tuple[list[VarDef], list[VarUse]]:
    """Parse IDA decompiled code into variable definitions and uses.

    Returns (definitions, uses) lists.
    """
    defs: list[VarDef] = []
    uses: list[VarUse] = []

    lines = code.splitlines()
    for line_num, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # --- Definitions (assignments) ---
        assign_var = None
        rhs_expr = ""
        is_compound = False

        # Simple: v5 = expr; or LODWORD(v5) = expr; or v5 += expr;
        m = _SIMPLE_ASSIGN_RE.match(stripped)
        if m:
            assign_var = m.group(1)
            eq_idx = stripped.index("=", m.start())
            is_compound = eq_idx > 0 and stripped[eq_idx - 1] in "+-*/%&|^<>"
            rhs_expr = stripped[eq_idx + 1:].rstrip(";").strip()

        if assign_var and _VAR_RE.match(assign_var):
            rhs_vars = _extract_vars(rhs_expr)
            if is_compound and assign_var not in rhs_vars:
                rhs_vars.insert(0, assign_var)
            # Include struct field reads as sources
            for sm in _STRUCT_READ_RE.finditer(rhs_expr):
                src = sm.group(1) or sm.group(2)
                if src and src not in rhs_vars:
                    rhs_vars.append(src)
            defs.append(VarDef(
                var=assign_var, line=line_num,
                rhs_expr=rhs_expr, rhs_vars=rhs_vars,
            ))

        # --- Uses ---

        # Struct/deref writes: *(_QWORD *)(v5 + 8) = expr;
        m = _DEREF_WRITE_RE.match(stripped)
        if m:
            base_var = m.group(1)
            if _VAR_RE.match(base_var):
                uses.append(VarUse(var=base_var, line=line_num, context="struct_write"))
                rhs_after_eq = stripped.split("=", 1)
                if len(rhs_after_eq) > 1:
                    for rv in _extract_vars(rhs_after_eq[1]):
                        uses.append(VarUse(var=rv, line=line_num, context="struct_write"))

        # Arrow writes: v5->field = expr;
        m = _ARROW_WRITE_RE.match(stripped)
        if m:
            base_var = m.group(1)
            if _VAR_RE.match(base_var):
                uses.append(VarUse(var=base_var, line=line_num, context="struct_write"))

        # Array index: var[tainted_index]
        arr_matches = re.finditer(r"(\w+)\s*\[\s*([^\]]+)\]", stripped)
        for am in arr_matches:
            idx_expr = am.group(2)
            for iv in _extract_vars(idx_expr):
                uses.append(VarUse(var=iv, line=line_num, context="array_index"))

        # Conditions: if (...) / while (...)
        cond_m = re.match(r"\s*(?:if|while)\s*\(", stripped)
        if cond_m:
            for cv in _extract_vars(stripped):
                uses.append(VarUse(var=cv, line=line_num, context="condition"))

        # Return statements
        ret_m = re.match(r"\s*return\b\s*(.*?)\s*;", stripped)
        if ret_m:
            for rv in _extract_vars(ret_m.group(1)):
                uses.append(VarUse(var=rv, line=line_num, context="return"))

        # Function call arguments
        for fname, arg_pos, arg_expr in _extract_call_args(stripped):
            for cv in _extract_vars(arg_expr):
                uses.append(VarUse(
                    var=cv, line=line_num, context="call_arg",
                    target_func=fname, arg_position=arg_pos,
                ))

    return defs, uses


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def propagate_taint(
    defs: list[VarDef],
    uses: list[VarUse],
    initial_tainted: set[str],
    max_iterations: int = 50,
) -> TaintResult:
    """Propagate taint from initial variables through def-use chains.

    Uses fixed-point iteration: if a definition's RHS contains any tainted
    variable, the LHS becomes tainted. Repeats until no new variables are
    tainted or max_iterations is reached.
    """
    tainted = set(initial_tainted)
    result = TaintResult(tainted_vars=set(initial_tainted))

    # Build def lookup: var -> list of definitions
    var_defs: dict[str, list[VarDef]] = {}
    for d in defs:
        var_defs.setdefault(d.var, []).append(d)

    # Fixed-point propagation
    for _ in range(max_iterations):
        new_tainted: set[str] = set()
        for var, var_def_list in var_defs.items():
            if var in tainted:
                continue
            for vd in var_def_list:
                if any(rv in tainted for rv in vd.rhs_vars):
                    new_tainted.add(var)
                    break
        if not new_tainted:
            break
        tainted |= new_tainted

    result.tainted_vars = set(tainted)

    # Collect tainted use sites
    for use in uses:
        if use.var not in tainted:
            continue
        entry = {"var": use.var, "line": use.line}
        if use.context == "call_arg":
            entry["target_func"] = use.target_func
            entry["arg_position"] = use.arg_position
            result.tainted_calls.append(entry)
        elif use.context == "condition":
            result.tainted_conditions.append(entry)
        elif use.context == "return":
            result.tainted_returns.append(entry)
        elif use.context == "struct_write":
            result.tainted_struct_writes.append(entry)

    return result


def analyze_taint(
    code: str,
    initial_tainted: set[str],
) -> TaintResult:
    """One-shot convenience: parse code and propagate taint.

    Parameters
    ----------
    code : str
        IDA decompiled C code for a single function.
    initial_tainted : set[str]
        Set of initially tainted variable names (e.g. ``{"a1", "a2"}``).

    Returns
    -------
    TaintResult
        Full taint propagation result including all tainted variables
        and categorized use sites.
    """
    if not code or not initial_tainted:
        return TaintResult()
    defs, uses = parse_def_use(code)
    return propagate_taint(defs, uses, initial_tainted)


__all__ = [
    "TaintResult",
    "VarDef",
    "VarUse",
    "analyze_taint",
    "parse_def_use",
    "propagate_taint",
]
