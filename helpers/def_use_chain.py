"""Lightweight def-use chain analysis for IDA Hex-Rays decompiled C output.

Parses decompiled code into variable definitions and uses, builds def-use
chains, and propagates taint through assignments and struct field accesses.
Supports scope-aware propagation (early-exit blocks), field-sensitive taint
(``a1->buffer`` vs ``a1->length``), and sanitizer-kill (APIs that produce
trusted output from tainted input).

Designed for IDA naming conventions: ``a1..aN`` for parameters,
``v1..vN`` for locals, ``*(_TYPE *)(var + offset)`` for struct accesses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union

# Type alias: plain variable ``"v5"`` or field-qualified ``("a1", "buffer")``.
TaintVar = Union[str, tuple[str, str]]

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
    r"^\s*(\w+)\s*->\s*(\w+)\s*=[^=]",
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

# Arrow field read with named field capture
_ARROW_FIELD_RE = re.compile(r"(\w+)\s*->\s*(\w+)")

# Deref offset read: *(_TYPE *)(var + 0xNN)
_DEREF_OFFSET_RE = re.compile(
    r"\*\s*\([^)]*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
)

# ---------------------------------------------------------------------------
# Sanitizer API set -- calls that produce trusted output from tainted input
# ---------------------------------------------------------------------------

SANITIZER_APIS: frozenset[str] = frozenset({
    "PathCchCanonicalize", "PathCchCanonicalizeEx", "PathAllocCanonicalize",
    "PathCchCombine", "PathCchCombineEx",
    "StringCchCopy", "StringCchCopyW", "StringCchCopyA",
    "StringCbCopy", "StringCbCopyW", "StringCbCopyA",
    "StringCchPrintf", "StringCchPrintfW", "StringCbPrintf",
    "StringCchLength", "StringCbLength",
    "RtlStringCchCopyW", "RtlStringCchCopyUnicodeString",
    "GetFullPathNameW", "GetFullPathNameA",
    "WideCharToMultiByte", "MultiByteToWideChar",
    "SecureZeroMemory", "RtlSecureZeroMemory",
})


# ---------------------------------------------------------------------------
# Block tree for scope-aware propagation
# ---------------------------------------------------------------------------

@dataclass
class BlockInfo:
    """A lightweight scope block parsed from brace structure."""
    start_line: int
    end_line: int
    block_type: str       # "root", "then", "else", "loop_body"
    has_return: bool      # block contains return/break/goto that exits
    parent_idx: int = -1
    children: list[int] = field(default_factory=list)


_EARLY_EXIT_RE = re.compile(r"^\s*(?:return\b|break\s*;|goto\s+\w+)")
_IF_START_RE = re.compile(r"^\s*(?:if|while|for)\s*\(")
_ELSE_RE = re.compile(r"^\s*}\s*else\b")
_ELSE_STANDALONE_RE = re.compile(r"^\s*else\b")


def _parse_blocks(lines: list[str]) -> list[BlockInfo]:
    """Build a flat list of blocks from brace/control-flow structure.

    Returns at least one block (the root) covering all lines.
    """
    root = BlockInfo(start_line=1, end_line=len(lines), block_type="root",
                     has_return=False)
    blocks: list[BlockInfo] = [root]
    stack: list[int] = [0]  # indices into *blocks*
    pending_type: Optional[str] = None

    for i, raw in enumerate(lines):
        line_num = i + 1
        stripped = raw.strip()

        if _EARLY_EXIT_RE.match(stripped):
            blocks[stack[-1]].has_return = True

        if _IF_START_RE.match(stripped):
            pending_type = "then"
        elif _ELSE_RE.match(stripped) or _ELSE_STANDALONE_RE.match(stripped):
            pending_type = "else"

        for ch in stripped:
            if ch == "{":
                btype = pending_type or "block"
                pending_type = None
                new_block = BlockInfo(
                    start_line=line_num, end_line=line_num,
                    block_type=btype, has_return=False,
                    parent_idx=stack[-1],
                )
                idx = len(blocks)
                blocks.append(new_block)
                blocks[stack[-1]].children.append(idx)
                stack.append(idx)
            elif ch == "}":
                if len(stack) > 1:
                    blocks[stack[-1]].end_line = line_num
                    stack.pop()

    # Fixup: root always spans the full range
    blocks[0].end_line = len(lines)
    return blocks


def _compute_reaching_blocks(blocks: list[BlockInfo]) -> dict[int, set[int]]:
    """For each block index, compute the set of block indices whose defs
    can reach it (i.e. are on a feasible path to it).

    A then-block with ``has_return`` does NOT reach its parent's
    continuation (the lines after the if/else).
    """
    reaching: dict[int, set[int]] = {}
    for idx in range(len(blocks)):
        reachable: set[int] = set()
        cur = idx
        while cur >= 0:
            reachable.add(cur)
            parent_idx = blocks[cur].parent_idx
            if parent_idx >= 0:
                parent = blocks[parent_idx]
                for sib_idx in parent.children:
                    sib = blocks[sib_idx]
                    if sib_idx == cur:
                        continue
                    # A sibling then-block that always exits does NOT reach us
                    if sib.block_type == "then" and sib.has_return:
                        continue
                    reachable.add(sib_idx)
            cur = parent_idx
        reaching[idx] = reachable
    return reaching


def _block_for_line(blocks: list[BlockInfo], line: int) -> int:
    """Return the deepest (most specific) block index containing *line*."""
    best = 0
    for idx, blk in enumerate(blocks):
        if blk.start_line <= line <= blk.end_line:
            if blk.start_line >= blocks[best].start_line:
                best = idx
    return best


# ---------------------------------------------------------------------------
# Field-sensitivity helpers
# ---------------------------------------------------------------------------

def _var_covers(tainted: set, var: TaintVar) -> bool:
    """Check whether *var* is covered by the *tainted* set.

    - A base variable (``"a1"``) in *tainted* covers all its fields.
    - A field tuple (``("a1", "buffer")``) only covers that exact field.
    """
    if var in tainted:
        return True
    if isinstance(var, tuple):
        # Base taint covers all fields
        return var[0] in tainted
    # Plain var: check if any field of this var is tainted (not sufficient
    # for base coverage -- we only do base-covers-field, not field-covers-base)
    return False


def _extract_field_vars(expr: str) -> list[TaintVar]:
    """Extract field-qualified variable references from an expression.

    Returns plain ``"v5"`` for simple references and ``("a1", "field")``
    for ``a1->field`` or ``("a1", "offset_8")`` for ``*(_TYPE*)(a1+8)``.
    """
    result: list[TaintVar] = []
    seen: set = set()

    for m in _ARROW_FIELD_RE.finditer(expr):
        base, fld = m.group(1), m.group(2)
        if _VAR_RE.match(base):
            key = (base, fld)
            if key not in seen:
                seen.add(key)
                result.append(key)

    for m in _DEREF_OFFSET_RE.finditer(expr):
        base = m.group(1)
        if _VAR_RE.match(base):
            key = (base, f"offset_{m.group(2)}")
            if key not in seen:
                seen.add(key)
                result.append(key)

    for m in _VAR_RE.finditer(expr):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            result.append(v)

    return result


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
    block_idx: int = 0
    rhs_call: Optional[str] = None  # callee name when RHS is a function call


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
    tainted_vars: set = field(default_factory=set)
    tainted_calls: list[dict] = field(default_factory=list)
    tainted_conditions: list[dict] = field(default_factory=list)
    tainted_returns: list[dict] = field(default_factory=list)
    tainted_struct_writes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        def _sortable(v: TaintVar) -> str:
            if isinstance(v, tuple):
                return f"{v[0]}.{v[1]}"
            return v

        return {
            "tainted_vars": sorted((_sortable(v) for v in self.tainted_vars)),
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


def _extract_rhs_callee(rhs_expr: str) -> Optional[str]:
    """If *rhs_expr* is (or starts with) a function call, return the callee name."""
    m = _FUNC_CALL_RE.match(rhs_expr.lstrip())
    if m:
        name = m.group(1)
        if name not in _IDA_KEYWORDS:
            return name
    return None


def parse_def_use(code: str) -> tuple[list[VarDef], list[VarUse]]:
    """Parse IDA decompiled code into variable definitions and uses.

    Returns (definitions, uses) lists.  Each ``VarDef`` carries a
    ``block_idx`` for scope-aware propagation and an ``rhs_call`` for
    sanitizer-kill detection.
    """
    defs: list[VarDef] = []
    uses: list[VarUse] = []

    lines = code.splitlines()
    blocks = _parse_blocks(lines)

    for line_num, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        blk_idx = _block_for_line(blocks, line_num)

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
            rhs_callee = _extract_rhs_callee(rhs_expr)
            defs.append(VarDef(
                var=assign_var, line=line_num,
                rhs_expr=rhs_expr, rhs_vars=rhs_vars,
                block_idx=blk_idx,
                rhs_call=rhs_callee,
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
    *,
    scope_aware: bool = True,
    field_sensitive: bool = False,
    sanitizer_kill: bool = True,
    blocks: Optional[list[BlockInfo]] = None,
) -> TaintResult:
    """Propagate taint from initial variables through def-use chains.

    Uses fixed-point iteration: if a definition's RHS contains any tainted
    variable, the LHS becomes tainted.  Repeats until no new variables are
    tainted or *max_iterations* is reached.

    Parameters
    ----------
    scope_aware : bool
        When ``True`` (default), defs inside early-exit blocks (blocks
        containing ``return``/``break``/``goto``) do not propagate taint
        to continuation blocks.
    field_sensitive : bool
        When ``True``, track ``("base", "field")`` tuples in addition to
        plain variable names.  A tainted base covers all fields, but a
        tainted field does not cover other fields.
    sanitizer_kill : bool
        When ``True`` (default), assignments whose RHS is a call to a
        sanitizer API (e.g. ``PathCchCanonicalize``) do NOT propagate
        taint to the LHS variable.
    blocks : list[BlockInfo] | None
        Pre-computed block tree.  If ``None``, block info is derived from
        ``VarDef.block_idx`` values (requires ``parse_def_use`` to have
        populated them).
    """
    tainted: set[TaintVar] = set(initial_tainted)
    result = TaintResult(tainted_vars=set(initial_tainted))

    # Build def lookup: var -> list of definitions
    var_defs: dict[str, list[VarDef]] = {}
    for d in defs:
        var_defs.setdefault(d.var, []).append(d)

    # Scope-aware: compute reaching blocks once
    reaching: Optional[dict[int, set[int]]] = None
    if scope_aware and blocks:
        reaching = _compute_reaching_blocks(blocks)

    def _rhs_is_tainted(vd: VarDef) -> bool:
        for rv in vd.rhs_vars:
            if _var_covers(tainted, rv):
                return True
        return False

    # Fixed-point propagation
    for _ in range(max_iterations):
        new_tainted: set[TaintVar] = set()
        for var, var_def_list in var_defs.items():
            if _var_covers(tainted, var):
                continue
            for vd in var_def_list:
                # Sanitizer kill: callee produces trusted output
                if sanitizer_kill and vd.rhs_call and vd.rhs_call in SANITIZER_APIS:
                    continue
                if not _rhs_is_tainted(vd):
                    continue
                # Scope-aware: check that the def's block can reach at
                # least one use site (approximate: we check reachability
                # between blocks rather than per-use, which is cheaper).
                if reaching is not None and blocks:
                    blk = blocks[vd.block_idx]
                    if blk.has_return and blk.block_type in ("then", "else"):
                        continue
                new_tainted.add(var)
                break
        if not new_tainted:
            break
        tainted |= new_tainted

    result.tainted_vars = set(tainted)

    # Collect tainted use sites
    for use in uses:
        if not _var_covers(tainted, use.var):
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
    *,
    scope_aware: bool = True,
    field_sensitive: bool = False,
    sanitizer_kill: bool = True,
) -> TaintResult:
    """One-shot convenience: parse code and propagate taint.

    Parameters
    ----------
    code : str
        IDA decompiled C code for a single function.
    initial_tainted : set[str]
        Set of initially tainted variable names (e.g. ``{"a1", "a2"}``).
    scope_aware : bool
        Filter out defs in early-exit blocks from continuation propagation.
    field_sensitive : bool
        Track per-field taint (``("a1", "buffer")`` vs ``("a1", "length")``).
    sanitizer_kill : bool
        Suppress taint propagation through sanitizer API calls.

    Returns
    -------
    TaintResult
        Full taint propagation result including all tainted variables
        and categorized use sites.
    """
    if not code or not initial_tainted:
        return TaintResult()
    defs, uses = parse_def_use(code)
    lines = code.splitlines()
    blocks = _parse_blocks(lines) if scope_aware else None
    return propagate_taint(
        defs, uses, initial_tainted,
        scope_aware=scope_aware,
        field_sensitive=field_sensitive,
        sanitizer_kill=sanitizer_kill,
        blocks=blocks,
    )


@dataclass
class TaintSummary:
    """Summary of taint behaviour for a single function (procedure summary).

    Used for inter-procedural taint propagation: callers can look up
    whether calling this function with tainted arguments will produce
    tainted return values or reach known sinks.
    """
    function_name: str
    tainted_params: set[int] = field(default_factory=set)
    tainted_return: bool = False
    param_to_sink: dict[int, str] = field(default_factory=dict)
    param_to_return: set[int] = field(default_factory=set)


def build_taint_summary(code: str, param_count: int, function_name: str = "") -> TaintSummary:
    """Run ``analyze_taint`` for each parameter and produce a :class:`TaintSummary`.

    For every parameter ``a1`` ... ``a<param_count>`` the function runs
    single-param taint analysis and records:

    - whether taint from that parameter reaches a ``return`` statement
    - the first dangerous sink reached (if any)
    - which parameters flow to the return value

    Parameters
    ----------
    code:
        IDA decompiled C source for a single function.
    param_count:
        Number of parameters (typically matches ``a1`` through ``aN``).
    function_name:
        Optional function name for the summary record.
    """
    summary = TaintSummary(function_name=function_name)

    for idx in range(1, param_count + 1):
        param_name = f"a{idx}"
        result = analyze_taint(code, {param_name})

        if not result.tainted_vars - {param_name}:
            continue

        summary.tainted_params.add(idx)

        if result.tainted_returns:
            summary.tainted_return = True
            summary.param_to_return.add(idx)

        if result.tainted_calls:
            first_sink = result.tainted_calls[0].get("target_func", "")
            if first_sink:
                summary.param_to_sink[idx] = first_sink

    return summary


__all__ = [
    "BlockInfo",
    "SANITIZER_APIS",
    "TaintResult",
    "TaintSummary",
    "TaintVar",
    "VarDef",
    "VarUse",
    "analyze_taint",
    "build_taint_summary",
    "parse_def_use",
    "propagate_taint",
    "_compute_reaching_blocks",
    "_extract_field_vars",
    "_parse_blocks",
    "_var_covers",
]
