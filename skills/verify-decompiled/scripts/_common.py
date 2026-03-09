"""Shared utilities for decompiler accuracy verification.

Provides assembly instruction parsing, memory access analysis, branch
classification, decompiled code analysis, and heuristic comparison
algorithms for detecting decompiler inaccuracies.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Optional

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from skills._shared import bootstrap, make_db_resolvers
from skills._shared.skill_common import emit_error, parse_json_safe  # noqa: F401

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = bootstrap(__file__)

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    LOW = 0
    MODERATE = 1
    HIGH = 2
    CRITICAL = 3


SEVERITY_LABELS = {
    Severity.LOW: "LOW",
    Severity.MODERATE: "MODERATE",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


# ---------------------------------------------------------------------------
# Issue categories
# ---------------------------------------------------------------------------
ISSUE_CATEGORIES = [
    "wrong_access_size",
    "wrong_return_type",
    "missing_operation",
    "wrong_branch_signedness",
    "collapsed_operation",
    "decompiler_artifact",
    "wrong_offset",
    "lost_volatile",
    "call_count_mismatch",
    "branch_count_mismatch",
]


# ---------------------------------------------------------------------------
# Issue dataclass
# ---------------------------------------------------------------------------
@dataclass
class VerificationIssue:
    """A single decompiler accuracy issue found."""
    category: str
    severity: Severity
    summary: str
    details: str = ""
    decompiled_evidence: str = ""
    assembly_evidence: str = ""
    suggested_fix: str = ""
    line_hint: int = 0  # approximate decompiled line number, 0 = unknown

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": SEVERITY_LABELS[self.severity],
            "severity_rank": int(self.severity),
            "summary": self.summary,
            "details": self.details,
            "decompiled_evidence": self.decompiled_evidence,
            "assembly_evidence": self.assembly_evidence,
            "suggested_fix": self.suggested_fix,
            "line_hint": self.line_hint,
        }


@dataclass
class VerificationResult:
    """Complete verification result for a function."""
    function_id: int
    function_name: str
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    moderate_count: int = 0
    low_count: int = 0
    issues: list[VerificationIssue] = field(default_factory=list)
    asm_stats: Optional[AsmStats] = None
    decomp_stats: Optional[DecompStats] = None
    has_decompiled: bool = False
    has_assembly: bool = False

    def add_issue(self, issue: VerificationIssue) -> None:
        self.issues.append(issue)
        self.total_issues += 1
        if issue.severity == Severity.CRITICAL:
            self.critical_count += 1
        elif issue.severity == Severity.HIGH:
            self.high_count += 1
        elif issue.severity == Severity.MODERATE:
            self.moderate_count += 1
        else:
            self.low_count += 1

    @property
    def max_severity(self) -> Severity:
        if self.critical_count > 0:
            return Severity.CRITICAL
        if self.high_count > 0:
            return Severity.HIGH
        if self.moderate_count > 0:
            return Severity.MODERATE
        if self.low_count > 0:
            return Severity.LOW
        return Severity.LOW

    @property
    def severity_score(self) -> int:
        """Numeric score for sorting: higher = more severe issues."""
        return (
            self.critical_count * 100
            + self.high_count * 10
            + self.moderate_count * 3
            + self.low_count
        )

    def to_dict(self) -> dict:
        return {
            "function_id": self.function_id,
            "function_name": self.function_name,
            "total_issues": self.total_issues,
            "critical": self.critical_count,
            "high": self.high_count,
            "moderate": self.moderate_count,
            "low": self.low_count,
            "max_severity": SEVERITY_LABELS[self.max_severity],
            "severity_score": self.severity_score,
            "has_decompiled": self.has_decompiled,
            "has_assembly": self.has_assembly,
            "issues": [i.to_dict() for i in self.issues],
        }


# ---------------------------------------------------------------------------
# Assembly instruction parsing
# ---------------------------------------------------------------------------
# IDA disassembly format: ".text:ADDRESS   mnemonic   operands"
# or sometimes just "   mnemonic   operands" or "label:"
_ASM_LINE_RE = re.compile(
    r"^(?:\.[a-z]+:[0-9A-Fa-f]+\s+)?"  # optional segment:address prefix
    r"(\w+)"                              # mnemonic
    r"(?:\s+(.*))?$"                      # optional operands
)
_ASM_LABEL_RE = re.compile(r"^(?:\.[a-z]+:[0-9A-Fa-f]+\s+)?(?:loc_|LABEL_|\w+:)")
_ASM_COMMENT_RE = re.compile(r";.*$")

# Memory access width from instruction suffix / register
_REG_32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d",
            "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
_REG_64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
_REG_16 = {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"}
_REG_8 = {"al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
           "ah", "bh", "ch", "dh",
           "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}

# Branch instructions classified by signedness
_SIGNED_BRANCHES = {"jl", "jle", "jg", "jge", "jnl", "jnle", "jng", "jnge", "js", "jns", "jo", "jno"}
_UNSIGNED_BRANCHES = {"jb", "jbe", "ja", "jae", "jnb", "jnbe", "jna", "jnae", "jc", "jnc"}
_NEUTRAL_BRANCHES = {"je", "jne", "jz", "jnz", "jmp", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}
_ALL_BRANCHES = _SIGNED_BRANCHES | _UNSIGNED_BRANCHES | _NEUTRAL_BRANCHES

# Memory access pattern: [reg+offset] or [reg+reg*scale+offset]
_MEM_ACCESS_RE = re.compile(r"\[([^\]]+)\]")
_MEM_OFFSET_RE = re.compile(r"(?:\+|-)([0-9A-Fa-f]+h?)\s*\]")

# Size prefix in operands
_SIZE_PREFIX_RE = re.compile(r"\b(byte|word|dword|qword|xmmword|oword)\b", re.I)


@dataclass
class AsmInstruction:
    """A parsed assembly instruction."""
    raw: str
    mnemonic: str
    operands: str
    is_call: bool = False
    is_branch: bool = False
    is_ret: bool = False
    is_mov: bool = False
    is_test: bool = False
    is_cmp: bool = False
    is_lea: bool = False
    branch_signedness: str = ""  # "signed", "unsigned", "neutral", ""
    memory_access_size: int = 0  # bytes: 1,2,4,8 or 0 if unknown
    memory_offset: str = ""  # hex offset if detected


@dataclass
class AsmStats:
    """Aggregate assembly statistics for a function."""
    instruction_count: int = 0
    call_count: int = 0
    branch_count: int = 0
    signed_branch_count: int = 0
    unsigned_branch_count: int = 0
    neutral_branch_count: int = 0
    ret_count: int = 0
    test_count: int = 0
    cmp_count: int = 0
    lea_count: int = 0
    mov_count: int = 0
    memory_reads: int = 0
    memory_writes: int = 0
    null_check_patterns: int = 0  # test reg,reg + jz/jnz pairs
    dword_accesses: int = 0
    qword_accesses: int = 0
    byte_accesses: int = 0
    word_accesses: int = 0


def _get_access_size_from_operands(mnemonic: str, operands: str) -> int:
    """Determine memory access size from instruction operands."""
    # Explicit size prefix
    m = _SIZE_PREFIX_RE.search(operands)
    if m:
        prefix = m.group(1).lower()
        return {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16, "oword": 16}.get(prefix, 0)

    # movzx / movsx with ptr
    if mnemonic.startswith("movzx") or mnemonic.startswith("movsx"):
        if "byte" in operands.lower():
            return 1
        if "word" in operands.lower():
            return 2
        return 0

    # From destination register for mov
    parts = [p.strip() for p in operands.split(",", 1)]
    if not parts:
        return 0
    dest = parts[0].lower()
    for reg_set, size in [(_REG_64, 8), (_REG_32, 4), (_REG_16, 2), (_REG_8, 1)]:
        if dest in reg_set:
            # Only if there's a memory source
            if len(parts) > 1 and "[" in parts[1]:
                return size
            break
    # From source register for mov to memory
    if len(parts) > 1 and "[" in parts[0]:
        src = parts[1].lower().strip()
        for reg_set, size in [(_REG_64, 8), (_REG_32, 4), (_REG_16, 2), (_REG_8, 1)]:
            if src in reg_set:
                return size
    return 0


def parse_asm_instruction(raw_line: str) -> Optional[AsmInstruction]:
    """Parse a single IDA assembly line into an AsmInstruction."""
    line = raw_line.strip()
    if not line or line.startswith(";"):
        return None

    # Remove comments
    line_no_comment = _ASM_COMMENT_RE.sub("", line).strip()
    if not line_no_comment:
        return None

    # Skip labels (but not instructions at labels)
    m = _ASM_LINE_RE.search(line_no_comment)
    if not m:
        return None

    mnemonic = m.group(1).lower()
    operands = (m.group(2) or "").strip()

    # Skip IDA directives
    if mnemonic in ("align", "db", "dw", "dd", "dq", "org", "assume", "public", "extrn",
                     "proc", "endp", "end", "segment", "ends"):
        return None

    inst = AsmInstruction(raw=raw_line.strip(), mnemonic=mnemonic, operands=operands)

    # Classify instruction type
    if mnemonic == "call":
        inst.is_call = True
    elif mnemonic in _ALL_BRANCHES:
        inst.is_branch = True
        if mnemonic in _SIGNED_BRANCHES:
            inst.branch_signedness = "signed"
        elif mnemonic in _UNSIGNED_BRANCHES:
            inst.branch_signedness = "unsigned"
        else:
            inst.branch_signedness = "neutral"
    elif mnemonic in ("ret", "retn"):
        inst.is_ret = True
    elif mnemonic.startswith("mov") or mnemonic in ("movzx", "movsx"):
        inst.is_mov = True
    elif mnemonic == "test":
        inst.is_test = True
    elif mnemonic == "cmp":
        inst.is_cmp = True
    elif mnemonic == "lea":
        inst.is_lea = True

    # Memory access analysis
    if "[" in operands and mnemonic not in ("lea",):
        inst.memory_access_size = _get_access_size_from_operands(mnemonic, operands)
        offset_m = _MEM_OFFSET_RE.search(operands)
        if offset_m:
            off = offset_m.group(1)
            if off.endswith("h"):
                off = off[:-1]
            inst.memory_offset = off

    return inst


def parse_assembly(assembly_code: str) -> tuple[list[AsmInstruction], AsmStats]:
    """Parse full assembly code into instructions and stats."""
    instructions: list[AsmInstruction] = []
    stats = AsmStats()

    if not assembly_code:
        return instructions, stats

    prev_was_test = False

    for line in assembly_code.splitlines():
        inst = parse_asm_instruction(line)
        if inst is None:
            prev_was_test = False
            continue

        instructions.append(inst)
        stats.instruction_count += 1

        if inst.is_call:
            stats.call_count += 1
        if inst.is_branch:
            stats.branch_count += 1
            if inst.branch_signedness == "signed":
                stats.signed_branch_count += 1
            elif inst.branch_signedness == "unsigned":
                stats.unsigned_branch_count += 1
            else:
                stats.neutral_branch_count += 1
        if inst.is_ret:
            stats.ret_count += 1
        if inst.is_test:
            stats.test_count += 1
        if inst.is_cmp:
            stats.cmp_count += 1
        if inst.is_lea:
            stats.lea_count += 1
        if inst.is_mov:
            stats.mov_count += 1

        # Memory access size counting
        if inst.memory_access_size > 0:
            if inst.is_mov and "," in inst.operands:
                parts = inst.operands.split(",", 1)
                if "[" in parts[0]:
                    stats.memory_writes += 1
                else:
                    stats.memory_reads += 1
            else:
                stats.memory_reads += 1

            if inst.memory_access_size == 1:
                stats.byte_accesses += 1
            elif inst.memory_access_size == 2:
                stats.word_accesses += 1
            elif inst.memory_access_size == 4:
                stats.dword_accesses += 1
            elif inst.memory_access_size >= 8:
                stats.qword_accesses += 1

        # Detect test reg,reg + jz/jnz (NULL check pattern)
        if prev_was_test and inst.is_branch and inst.branch_signedness == "neutral":
            stats.null_check_patterns += 1

        prev_was_test = inst.is_test and _is_self_test(inst.operands)

    return instructions, stats


def _is_self_test(operands: str) -> bool:
    """Check if a test instruction tests a register against itself (NULL check)."""
    parts = [p.strip().lower() for p in operands.split(",")]
    if len(parts) == 2:
        return parts[0] == parts[1]
    return False


# ---------------------------------------------------------------------------
# Decompiled code analysis
# ---------------------------------------------------------------------------
_DECOMP_CAST_RE = re.compile(r"\*\(\s*\(\s*_?(QWORD|DWORD|WORD|BYTE)\s*\*\s*\)")
_DECOMP_DIRECT_CAST_RE = re.compile(r"\*\(\s*_?(QWORD|DWORD|WORD|BYTE)\s*\*\s*\)")
_DECOMP_IF_RE = re.compile(r"\bif\s*\(")
_DECOMP_GOTO_RE = re.compile(r"\bgoto\b")
_DECOMP_CALL_RE = re.compile(r"\b(\w+)\s*\(")
_DECOMP_DO_WHILE_0_RE = re.compile(r"\bdo\b.*\bwhile\s*\(\s*0\s*\)")
_DECOMP_LOBYTE_RE = re.compile(r"\bLOBYTE\s*\(")
_DECOMP_HIDWORD_RE = re.compile(r"\b(?:HIDWORD|LODWORD)\s*\(")
_DECOMP_RETURN_RE = re.compile(r"^\s*(?:return|goto\b)")
_DECOMP_WHILE_RE = re.compile(r"\bwhile\s*\(")
_DECOMP_FOR_RE = re.compile(r"\bfor\s*\(")
# Short-circuit operators && and || each represent a branch point in assembly
_DECOMP_AND_OR_RE = re.compile(r"&&|\|\|")
# Ternary operator also represents a branch
_DECOMP_TERNARY_RE = re.compile(r"\?(?!=)")
# switch/case: each case label is a branch, switch itself is a branch point
_DECOMP_CASE_RE = re.compile(r"^\s*case\s+")
_DECOMP_DEFAULT_RE = re.compile(r"^\s*default\s*:")
_DECOMP_SWITCH_RE = re.compile(r"\bswitch\s*\(")

# Signed vs unsigned comparison in decompiled code
_DECOMP_SIGNED_CMP_RE = re.compile(r"<\s*0\s*[);]|>=\s*0\s*[);]|>\s*0\s*[);]|<=\s*0\s*[);]")
_DECOMP_UNSIGNED_CAST_RE = re.compile(r"\(\s*unsigned\s+(?:int|__int64|long|short|char)\s*\)")

# Function signature return type
_DECOMP_SIG_RETURN_RE = re.compile(r"^(\w[\w\s*]+?)\s+(?:__\w+\s+)?(\w+)\s*\(")


@dataclass
class DecompStats:
    """Aggregate statistics from decompiled code."""
    line_count: int = 0
    if_count: int = 0
    goto_count: int = 0
    call_count: int = 0        # unique called function names
    total_call_sites: int = 0  # total call instances (same function counted each time)
    short_circuit_ops: int = 0 # && and || operators (each is an assembly branch)
    ternary_ops: int = 0       # ? : operators (each is an assembly branch)
    switch_count: int = 0      # switch statements
    case_count: int = 0        # case + default labels (each is a branch)
    do_while_0_count: int = 0
    lobyte_count: int = 0
    hidword_lodword_count: int = 0
    while_count: int = 0
    for_count: int = 0
    qword_casts: int = 0
    dword_casts: int = 0
    word_casts: int = 0
    byte_casts: int = 0
    return_type: str = ""
    signed_comparisons: int = 0
    unsigned_casts: int = 0
    # Called function names
    called_functions: list[str] = field(default_factory=list)


DECOMPILATION_FAILURE_PREFIXES = (
    "Decompiler returned None",
    "Decompiler not available",
    "Decompilation failed",
)


def is_decompilation_failure(code: str) -> bool:
    """Check if decompiled code is a placeholder failure message."""
    if not code:
        return True
    stripped = code.strip()
    if not stripped:
        return True
    for prefix in DECOMPILATION_FAILURE_PREFIXES:
        if stripped.startswith(prefix):
            return True
    return False


def parse_decompiled(decompiled_code: str) -> DecompStats:
    """Parse decompiled code into stats."""
    stats = DecompStats()

    if not decompiled_code or is_decompilation_failure(decompiled_code):
        return stats

    lines = decompiled_code.splitlines()
    stats.line_count = len(lines)

    # Extract return type from first non-empty line (function signature)
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("{"):
            m = _DECOMP_SIG_RETURN_RE.match(stripped)
            if m:
                stats.return_type = m.group(1).strip()
            break

    called_set: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # Count patterns
        stats.if_count += len(_DECOMP_IF_RE.findall(stripped))
        stats.goto_count += len(_DECOMP_GOTO_RE.findall(stripped))
        stats.while_count += len(_DECOMP_WHILE_RE.findall(stripped))
        stats.for_count += len(_DECOMP_FOR_RE.findall(stripped))
        stats.short_circuit_ops += len(_DECOMP_AND_OR_RE.findall(stripped))
        stats.ternary_ops += len(_DECOMP_TERNARY_RE.findall(stripped))
        stats.switch_count += len(_DECOMP_SWITCH_RE.findall(stripped))
        if _DECOMP_CASE_RE.match(stripped):
            stats.case_count += 1
        if _DECOMP_DEFAULT_RE.match(stripped):
            stats.case_count += 1

        # Count type casts
        for m in _DECOMP_CAST_RE.finditer(stripped):
            cast_type = m.group(1).upper()
            if cast_type == "QWORD":
                stats.qword_casts += 1
            elif cast_type == "DWORD":
                stats.dword_casts += 1
            elif cast_type == "WORD":
                stats.word_casts += 1
            elif cast_type == "BYTE":
                stats.byte_casts += 1
        for m in _DECOMP_DIRECT_CAST_RE.finditer(stripped):
            cast_type = m.group(1).upper()
            if cast_type == "QWORD":
                stats.qword_casts += 1
            elif cast_type == "DWORD":
                stats.dword_casts += 1
            elif cast_type == "WORD":
                stats.word_casts += 1
            elif cast_type == "BYTE":
                stats.byte_casts += 1

        # Count artifacts
        if _DECOMP_DO_WHILE_0_RE.search(stripped):
            stats.do_while_0_count += 1
        stats.lobyte_count += len(_DECOMP_LOBYTE_RE.findall(stripped))
        stats.hidword_lodword_count += len(_DECOMP_HIDWORD_RE.findall(stripped))

        # Count signed comparisons and unsigned casts
        stats.signed_comparisons += len(_DECOMP_SIGNED_CMP_RE.findall(stripped))
        stats.unsigned_casts += len(_DECOMP_UNSIGNED_CAST_RE.findall(stripped))

        # Extract function calls (heuristic: word followed by '(')
        for m in _DECOMP_CALL_RE.finditer(stripped):
            name = m.group(1)
            # Skip C keywords and IDA type casts
            if name not in ("if", "while", "for", "return", "switch", "sizeof",
                            "LOBYTE", "HIBYTE", "LOWORD", "HIWORD", "LODWORD", "HIDWORD",
                            "_QWORD", "_DWORD", "_WORD", "_BYTE", "BYTE", "unsigned",
                            "do", "int", "char", "void", "struct"):
                called_set.add(name)
                stats.total_call_sites += 1

    stats.call_count = len(called_set)
    stats.called_functions = sorted(called_set)

    return stats


# ---------------------------------------------------------------------------
# Return type decoding from mangled names
# ---------------------------------------------------------------------------
_MANGLED_RETURN_MAP = {
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "F": "short",
    "G": "unsigned short",
    "D": "char",
    "E": "unsigned char",
    "C": "signed char",
    "_N": "bool",
    "X": "void",
    "_J": "__int64",
    "_K": "unsigned __int64",
    "N": "double",
    "M": "float",
}

# Return type from extended mangled name patterns
_MANGLED_RET_SECTION_RE = re.compile(r"@@[A-Z]{3,5}([A-Z_]+)")


def decode_mangled_return_type(mangled: str) -> Optional[str]:
    """Attempt to decode the return type from a Microsoft mangled name.

    Returns a human-readable type string, or None if decoding fails.
    This is heuristic -- complex types (pointers, references, classes) may
    not decode correctly.
    """
    if not mangled or not mangled.startswith("?"):
        return None

    # Find the section after @@ that encodes calling convention + return type
    # Format: ?name@scope@@<access_conv><return_type><params>@Z
    at_idx = mangled.find("@@")
    if at_idx < 0:
        return None

    tail = mangled[at_idx + 2:]
    if len(tail) < 3:
        return None

    # Determine how many chars to skip before the return type.
    # Common prefix patterns (access specifier + calling convention):
    #   YA      = non-member __cdecl (2 chars)
    #   SA      = public static __cdecl (2 chars)
    #   QA/UA/AA/IA = member __cdecl (2 chars)
    #   UEAA/QEAA/AEAA/IEAA = member __thiscall x64 (4 chars)
    #   UEBA/QEBA  = member __thiscall x64 const (4 chars)

    # Known prefix lengths (longest first for greedy match)
    _PREFIX_SKIPS = [
        # 4-char prefixes (x64 member functions with __thiscall + near)
        ("UEAA", 4), ("QEAA", 4), ("AEAA", 4), ("IEAA", 4),
        ("UEBA", 4), ("QEBA", 4), ("AEBA", 4), ("IEBA", 4),
        ("UEHA", 4), ("QEHA", 4),
        # 3-char prefixes
        ("QAE", 3), ("UAE", 3), ("AAE", 3), ("IAE", 3),
        ("QBE", 3), ("UBE", 3),
        # 2-char prefixes (non-member / __cdecl)
        ("YA", 2), ("SA", 2), ("QA", 2), ("UA", 2), ("AA", 2), ("IA", 2),
    ]

    skip = None
    for prefix, length in _PREFIX_SKIPS:
        if tail.startswith(prefix):
            skip = length
            break

    if skip is None:
        # Fallback: skip 2 chars minimum (access + calling convention)
        skip = 2

    if len(tail) <= skip:
        return None

    ret_section = tail[skip:]

    # Check for multi-char codes first (longest match)
    for code, rtype in sorted(_MANGLED_RETURN_MAP.items(), key=lambda x: -len(x[0])):
        if ret_section.startswith(code):
            return rtype

    # PEAX = void*, PEAD = char*, PEAG = unsigned short* (wchar_t*), etc.
    if ret_section.startswith("PEA"):
        return "void *"  # generic pointer (could refine further)

    return None


# ---------------------------------------------------------------------------
# Heuristic comparison checks
# ---------------------------------------------------------------------------

def check_return_type_mismatch(
    mangled_name: Optional[str],
    decomp_return_type: str,
    decomp_sig: Optional[str],
    extended_sig: Optional[str],
) -> Optional[VerificationIssue]:
    """Check if decompiled return type mismatches mangled name encoding."""
    if not mangled_name:
        return None

    mangled_ret = decode_mangled_return_type(mangled_name)
    if not mangled_ret:
        return None

    # Normalize decompiled return type
    decomp_ret = decomp_return_type.strip()
    if not decomp_ret:
        # Try from extended signature
        if extended_sig:
            m = _DECOMP_SIG_RETURN_RE.match(extended_sig.strip())
            if m:
                decomp_ret = m.group(1).strip()
        if not decomp_ret:
            return None

    # Normalize for comparison
    norm_mangled = _normalize_type(mangled_ret)
    norm_decomp = _normalize_type(decomp_ret)

    if norm_mangled == norm_decomp:
        return None

    # Classify severity based on how significant the mismatch is
    # Common __int64 vs int/uint/long/ulong is just register-width defaulting (LOW)
    # Type-class mismatches (void vs int, bool vs int64, pointer vs int) are more serious
    int_types = {"int", "uint", "long", "ulong", "sint", "slong", "int64", "uint64", "sint64"}
    if norm_mangled in int_types and norm_decomp in int_types:
        # Both are integer types -- just a width/signedness difference
        severity = Severity.LOW
    elif (norm_mangled == "void" and norm_decomp != "void") or (norm_decomp == "void" and norm_mangled != "void"):
        # void vs non-void is a significant mismatch
        severity = Severity.HIGH
    elif "bool" in norm_mangled or "bool" in norm_decomp:
        # bool vs integer/pointer is moderately significant
        severity = Severity.MODERATE
    else:
        # Other mismatches (pointer types, class types, etc.)
        severity = Severity.MODERATE

    return VerificationIssue(
        category="wrong_return_type",
        severity=severity,
        summary=f"Return type mismatch: mangled name encodes '{mangled_ret}', decompiled shows '{decomp_ret}'",
        details=f"Mangled name: {mangled_name}",
        decompiled_evidence=f"Decompiled return type: {decomp_ret}",
        assembly_evidence=f"Mangled name decoded return type: {mangled_ret}",
        suggested_fix=f"Change return type to {mangled_ret}",
        line_hint=1,
    )


def _normalize_type(t: str) -> str:
    """Normalize a C type string for comparison."""
    t = t.lower().strip()
    t = t.replace("__", "")
    t = t.replace("unsigned ", "u")
    t = t.replace("signed ", "s")
    t = re.sub(r"\s+", "", t)
    return t


def check_call_count_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
) -> Optional[VerificationIssue]:
    """Check if assembly call count significantly differs from decompiled call sites."""
    asm_calls = asm_stats.call_count
    # Compare against TOTAL call sites (not unique function names)
    decomp_calls = decomp_stats.total_call_sites

    if asm_calls == 0 and decomp_calls == 0:
        return None

    # Allow generous tolerance -- decompiled call counting is heuristic
    diff = asm_calls - decomp_calls  # positive = assembly has MORE calls
    if diff <= 2:
        return None

    ratio = diff / max(asm_calls, 1)
    if ratio < 0.4:
        return None

    severity = Severity.HIGH if diff >= 5 else Severity.MODERATE
    return VerificationIssue(
        category="call_count_mismatch",
        severity=severity,
        summary=f"Assembly has {asm_calls} call instructions but decompiled shows ~{decomp_calls} call sites -- {diff} calls may be missing",
        details=(
            f"Assembly call instructions: {asm_calls}\n"
            f"Decompiled call sites: {decomp_calls} ({decomp_stats.call_count} unique functions)"
        ),
        suggested_fix="Check assembly for calls that the decompiler may have inlined, collapsed into expressions, or optimized away",
    )


def check_branch_count_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
) -> Optional[VerificationIssue]:
    """Check if branch count significantly differs from decompiled branch points.

    Branch points include: if, goto, while, for, &&, ||, and ternary ?.
    Each of these corresponds to at least one branch instruction in assembly.
    """
    asm_branches = asm_stats.branch_count
    # Count ALL branch points in decompiled code (not just if/goto)
    decomp_branches = (
        decomp_stats.if_count
        + decomp_stats.goto_count
        + decomp_stats.while_count
        + decomp_stats.for_count
        + decomp_stats.short_circuit_ops
        + decomp_stats.ternary_ops
        + decomp_stats.case_count
    )

    if asm_branches == 0 and decomp_branches == 0:
        return None

    diff = asm_branches - decomp_branches
    if diff <= 3:
        return None

    ratio = diff / max(asm_branches, 1)
    if ratio < 0.35:
        return None

    severity = Severity.CRITICAL if diff >= 8 else Severity.HIGH
    return VerificationIssue(
        category="branch_count_mismatch",
        severity=severity,
        summary=f"Assembly has {asm_branches} branches but decompiled shows ~{decomp_branches} branch points -- {diff} branches may be missing",
        details=(
            f"Assembly: {asm_branches} branches ({asm_stats.signed_branch_count} signed, "
            f"{asm_stats.unsigned_branch_count} unsigned, {asm_stats.neutral_branch_count} neutral)\n"
            f"Decompiled: {decomp_stats.if_count} if, {decomp_stats.goto_count} goto, "
            f"{decomp_stats.while_count + decomp_stats.for_count} loops, "
            f"{decomp_stats.short_circuit_ops} &&/||, {decomp_stats.ternary_ops} ternary, "
            f"{decomp_stats.case_count} case/default"
        ),
        suggested_fix="Compare assembly branch targets with decompiled control flow -- missing branches may indicate collapsed NULL guards or error checks",
    )


def check_null_check_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
) -> Optional[VerificationIssue]:
    """Check if assembly has more test+jz/jnz pairs than decompiled branch points suggest."""
    null_checks = asm_stats.null_check_patterns
    if null_checks == 0:
        return None

    # Each NULL check should correspond to SOME branch point in decompiled code
    # (if, &&, ||, ternary, etc.) -- not just if-statements
    total_branch_points = (
        decomp_stats.if_count
        + decomp_stats.short_circuit_ops
        + decomp_stats.ternary_ops
    )

    if null_checks <= total_branch_points:
        return None

    excess = null_checks - total_branch_points
    if excess <= 2:
        return None

    return VerificationIssue(
        category="missing_operation",
        severity=Severity.CRITICAL,
        summary=f"Assembly has {null_checks} test+branch (NULL check) patterns but decompiled has only {total_branch_points} conditional expressions -- {excess} NULL checks may be collapsed",
        details=(
            "test reg,reg followed by jz/jnz is the standard NULL-check pattern. "
            "When the decompiler collapses these, NULL guards become invisible.\n"
            f"Decompiled conditionals: {decomp_stats.if_count} if, "
            f"{decomp_stats.short_circuit_ops} &&/||, {decomp_stats.ternary_ops} ternary"
        ),
        suggested_fix="Scan assembly for test+jz/jnz patterns near call instructions -- these are likely NULL guards before function calls that the decompiler collapsed",
    )


def check_signedness_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
) -> Optional[VerificationIssue]:
    """Check if signed/unsigned branch mismatch exists."""
    # If assembly has unsigned branches but decompiled shows signed comparisons
    unsigned_asm = asm_stats.unsigned_branch_count
    signed_asm = asm_stats.signed_branch_count

    if unsigned_asm == 0 and signed_asm == 0:
        return None

    # Heuristic: if assembly is predominantly unsigned but decompiled uses few unsigned casts
    if unsigned_asm >= 3 and decomp_stats.unsigned_casts == 0:
        return VerificationIssue(
            category="wrong_branch_signedness",
            severity=Severity.HIGH,
            summary=f"Assembly uses {unsigned_asm} unsigned comparisons (jb/ja/jbe/jae) but decompiled code has no unsigned casts",
            details=(
                f"Assembly: {signed_asm} signed branches (jl/jg/etc), {unsigned_asm} unsigned branches (jb/ja/etc)\n"
                f"Decompiled: {decomp_stats.signed_comparisons} signed comparisons, {decomp_stats.unsigned_casts} unsigned casts"
            ),
            suggested_fix="Check decompiled comparisons -- the decompiler may have incorrectly used signed comparisons where unsigned (jb/ja) was used in assembly",
        )

    return None


def check_access_size_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
) -> Optional[VerificationIssue]:
    """Check if memory access sizes in assembly differ from decompiled type casts."""
    # Compare DWORD vs QWORD ratios
    asm_dword = asm_stats.dword_accesses
    asm_qword = asm_stats.qword_accesses
    decomp_dword = decomp_stats.dword_casts
    decomp_qword = decomp_stats.qword_casts

    issues_found = []

    # If assembly has many DWORD accesses but decompiled shows mostly QWORD
    if asm_dword > 3 and decomp_qword > decomp_dword and asm_qword < asm_dword:
        issues_found.append(
            f"Assembly has {asm_dword} DWORD reads but decompiled uses {decomp_qword} QWORD casts "
            f"vs {decomp_dword} DWORD casts -- some QWORD casts may actually be DWORD"
        )

    # If assembly has byte accesses but decompiled shows none
    if asm_stats.byte_accesses > 2 and decomp_stats.byte_casts == 0:
        issues_found.append(
            f"Assembly has {asm_stats.byte_accesses} byte-sized accesses but decompiled has no BYTE casts"
        )

    if not issues_found:
        return None

    return VerificationIssue(
        category="wrong_access_size",
        severity=Severity.HIGH,
        summary="Memory access size distribution mismatch between assembly and decompiled code",
        details="\n".join(issues_found) + (
            f"\n\nAssembly access sizes: BYTE={asm_stats.byte_accesses}, WORD={asm_stats.word_accesses}, "
            f"DWORD={asm_dword}, QWORD={asm_qword}\n"
            f"Decompiled type casts: _BYTE={decomp_stats.byte_casts}, _WORD={decomp_stats.word_casts}, "
            f"_DWORD={decomp_dword}, _QWORD={decomp_qword}"
        ),
        suggested_fix="Cross-reference individual memory accesses: mov eax,[...] = DWORD, mov rax,[...] = QWORD. Fix any decompiled casts that use the wrong width.",
    )


def check_decompiler_artifacts(decomp_stats: DecompStats) -> list[VerificationIssue]:
    """Detect known decompiler artifacts in decompiled code."""
    issues = []

    if decomp_stats.do_while_0_count > 0:
        issues.append(VerificationIssue(
            category="decompiler_artifact",
            severity=Severity.LOW,
            summary=f"Found {decomp_stats.do_while_0_count} do/while(0) wrapper(s) -- decompiler artifact with no assembly equivalent",
            suggested_fix="Remove do/while(0) wrappers and keep inner statements",
        ))

    if decomp_stats.lobyte_count > 3:
        issues.append(VerificationIssue(
            category="decompiler_artifact",
            severity=Severity.LOW,
            summary=f"Found {decomp_stats.lobyte_count} LOBYTE() usages -- likely decompiler artifact for bool assignments",
            suggested_fix="Replace LOBYTE(var) = expr with simple var = expr for boolean values",
        ))

    return issues


# ---------------------------------------------------------------------------
# Basic block extraction and semantic comparison
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    """A basic block extracted from assembly code."""
    index: int
    instructions: list[AsmInstruction] = field(default_factory=list)
    call_targets: list[str] = field(default_factory=list)
    memory_accesses: list[tuple[str, str, int]] = field(default_factory=list)
    branch_type: str = ""
    is_entry: bool = False
    is_exit: bool = False


def extract_basic_blocks(assembly_code: str) -> list[BasicBlock]:
    """Split assembly into basic blocks at branch/label boundaries.

    A new block starts after every branch instruction or at every label.
    Returns a list of BasicBlock with call targets and memory access
    patterns extracted for each block.
    """
    if not assembly_code:
        return []

    instructions, _ = parse_assembly(assembly_code)
    if not instructions:
        return []

    blocks: list[BasicBlock] = []
    current = BasicBlock(index=0, is_entry=True)

    for inst in instructions:
        current.instructions.append(inst)

        if inst.is_call:
            target = ""
            if inst.operands:
                target = inst.operands.strip()
                # Strip layered prefixes iteratively (e.g. cs:__imp_Foo -> Foo)
                _CALL_PREFIXES = ("__imp_", "_imp_", "j_", "cs:")
                changed = True
                while changed:
                    changed = False
                    for pfx in _CALL_PREFIXES:
                        if target.startswith(pfx):
                            target = target[len(pfx):]
                            changed = True
                            break
                # Demangle C++ mangled names: ?FuncName@@... -> FuncName
                if target.startswith("?") and "@" in target:
                    target = target[1:target.index("@")]
            if target and not target.startswith("0x") and not target.isdigit():
                current.call_targets.append(target)

        if inst.memory_access_size > 0 and inst.memory_offset:
            parts = inst.operands.split(",", 1) if inst.operands else []
            base = "?"
            if parts and "[" in (parts[0] if len(parts) > 0 else ""):
                m = _MEM_ACCESS_RE.search(parts[0])
                if m:
                    inner = m.group(1).split("+")[0].strip().lower()
                    base = inner
            elif len(parts) > 1 and "[" in parts[1]:
                m = _MEM_ACCESS_RE.search(parts[1])
                if m:
                    inner = m.group(1).split("+")[0].strip().lower()
                    base = inner
            current.memory_accesses.append(
                (base, inst.memory_offset, inst.memory_access_size)
            )

        if inst.is_branch or inst.is_ret:
            current.branch_type = inst.mnemonic
            if inst.is_ret:
                current.is_exit = True
            blocks.append(current)
            current = BasicBlock(index=len(blocks))

    if current.instructions:
        blocks.append(current)

    return blocks


@dataclass
class SemanticDiffResult:
    """Result of comparing assembly blocks against decompiled code."""
    category: str
    severity: Severity
    summary: str
    asm_block_index: int = -1
    details: str = ""


# Pre-compiled patterns for assembly call-target name normalisation.
_MSVC_MANGLED_RE = re.compile(r"^\?([^@?]+)@@")  # ?FuncName@@... -> FuncName
_MSVC_TEMPLATE_MANGLED_RE = re.compile(r"^\?\?_\w")  # ??_Gfoo@@ (dtor/scalar)
_IMP_PREFIX_RE = re.compile(r"^__imp_")
_GUARD_DISPATCH_RE = re.compile(r"^_guard_dispatch_icall")


def _normalize_asm_call_name(name: str) -> str:
    """Normalise a raw assembly call target to a demangled base name.

    Strips the ``__imp_`` import-table prefix and demangles MSVC C++ mangled
    names so that assembly call targets can be compared directly against the
    regex-extracted function names from decompiled code.

    Examples::

        "__imp_LocalFree"                              -> "LocalFree"
        "?AiBuildAxISParams@@YAKPEBG0PEAPEAU...@Z"    -> "AiBuildAxISParams"
        "__imp_?SomeMethod@@UAEXXZ"                   -> "SomeMethod"
        "_guard_dispatch_icall$thunk$..."              -> "_guard_dispatch_icall"
        "AiLaunchProcess"                              -> "AiLaunchProcess"
    """
    # Strip __imp_ prefix first (may precede a mangled name)
    n = _IMP_PREFIX_RE.sub("", name)

    # Demangle MSVC C++ names: ?Name@@... -> Name
    m = _MSVC_MANGLED_RE.match(n)
    if m:
        return m.group(1)

    # Guard dispatch thunks: normalise to the base symbol
    gd = _GUARD_DISPATCH_RE.match(n)
    if gd:
        return "_guard_dispatch_icall"

    return n


def check_semantic_block_mismatch(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
    assembly_code: str,
    decompiled_code: str,
) -> list[VerificationIssue]:
    """Compare basic block structure between assembly and decompiled code.

    Extracts basic blocks from assembly and checks for:
    1. Call targets present in assembly but missing from decompiled code
    2. Memory access patterns in assembly blocks not reflected in decompiled casts
    3. Blocks with both a NULL check and a call where the decompiled code
       may have collapsed them into a single expression
    """
    if not assembly_code or not decompiled_code:
        return []

    blocks = extract_basic_blocks(assembly_code)
    if not blocks:
        return []

    issues: list[VerificationIssue] = []

    asm_call_set: set[str] = set()
    for block in blocks:
        asm_call_set.update(_normalize_asm_call_name(t) for t in block.call_targets)

    decomp_call_set = set(decomp_stats.called_functions)

    missing_in_decomp = asm_call_set - decomp_call_set
    skip_prefixes = ("sub_", "loc_", "nullsub_", "unknown_")
    missing_in_decomp = {
        c for c in missing_in_decomp
        if not any(c.startswith(p) for p in skip_prefixes)
    }

    if len(missing_in_decomp) >= 2:
        issues.append(VerificationIssue(
            category="missing_operation",
            severity=Severity.HIGH,
            summary=(
                f"{len(missing_in_decomp)} call target(s) found in assembly "
                f"basic blocks but absent from decompiled code"
            ),
            details=f"Missing targets: {', '.join(sorted(missing_in_decomp)[:10])}",
            suggested_fix=(
                "Cross-reference these assembly call targets with the "
                "decompiled code -- they may be inlined, optimized away, "
                "or collapsed into expressions"
            ),
        ))

    guarded_call_blocks = 0
    for i, block in enumerate(blocks):
        has_test_self = any(
            inst.is_test and _is_self_test(inst.operands)
            for inst in block.instructions
        )
        has_call = bool(block.call_targets)
        has_conditional_branch = any(
            inst.is_branch and inst.branch_signedness in ("signed", "unsigned", "neutral")
            and inst.mnemonic != "jmp"
            for inst in block.instructions
        )

        if has_test_self and has_conditional_branch and i + 1 < len(blocks):
            next_block = blocks[i + 1]
            if next_block.call_targets:
                guarded_call_blocks += 1

    if guarded_call_blocks >= 2:
        total_if = decomp_stats.if_count + decomp_stats.short_circuit_ops
        if guarded_call_blocks > total_if:
            excess = guarded_call_blocks - total_if
            issues.append(VerificationIssue(
                category="missing_operation",
                severity=Severity.CRITICAL,
                summary=(
                    f"Assembly has {guarded_call_blocks} NULL-guarded call "
                    f"blocks but decompiled code has only {total_if} "
                    f"conditionals -- {excess} guards may be collapsed"
                ),
                details=(
                    "Pattern: test reg,reg + jz/jnz -> call block. "
                    "When the decompiler collapses these, the call appears "
                    "unconditional in the decompiled output."
                ),
                suggested_fix=(
                    "Scan assembly for test+branch patterns immediately "
                    "before call blocks and verify each has a corresponding "
                    "if-statement in the decompiled code"
                ),
            ))

    offset_map: dict[str, int] = defaultdict(int)
    for block in blocks:
        for base, offset, size in block.memory_accesses:
            key = f"{base}+{offset}:{size}"
            offset_map[key] += 1

    if offset_map:
        byte_access_offsets = {
            k for k, v in offset_map.items() if k.endswith(":1")
        }
        dword_access_offsets = {
            k for k, v in offset_map.items() if k.endswith(":4")
        }
        if (len(byte_access_offsets) >= 3
                and decomp_stats.byte_casts == 0
                and asm_stats.byte_accesses >= 3):
            issues.append(VerificationIssue(
                category="wrong_access_size",
                severity=Severity.MODERATE,
                summary=(
                    f"Assembly basic blocks contain {len(byte_access_offsets)} "
                    f"distinct byte-sized memory offsets but decompiled code "
                    f"has no _BYTE casts"
                ),
                details=(
                    f"Byte offsets: {', '.join(sorted(byte_access_offsets)[:8])}"
                ),
                suggested_fix=(
                    "Check if these byte accesses are represented as wider "
                    "reads in the decompiled code (e.g., DWORD read then mask)"
                ),
            ))

    issues.sort(key=lambda i: -int(i.severity))
    return issues


# ---------------------------------------------------------------------------
# Run all heuristic checks
# ---------------------------------------------------------------------------
def run_heuristic_checks(
    asm_stats: AsmStats,
    decomp_stats: DecompStats,
    mangled_name: Optional[str] = None,
    function_signature: Optional[str] = None,
    function_signature_extended: Optional[str] = None,
    assembly_code: Optional[str] = None,
    decompiled_code: Optional[str] = None,
) -> list[VerificationIssue]:
    """Run all automated heuristic checks and return found issues.

    Parameters
    ----------
    assembly_code, decompiled_code : str | None
        Raw code text.  When provided, the basic block semantic diff
        check is also run.
    """
    issues: list[VerificationIssue] = []

    # Return type
    ret_issue = check_return_type_mismatch(
        mangled_name, decomp_stats.return_type,
        function_signature, function_signature_extended,
    )
    if ret_issue:
        issues.append(ret_issue)

    # Call count
    call_issue = check_call_count_mismatch(asm_stats, decomp_stats)
    if call_issue:
        issues.append(call_issue)

    # Branch count
    branch_issue = check_branch_count_mismatch(asm_stats, decomp_stats)
    if branch_issue:
        issues.append(branch_issue)

    # NULL checks
    null_issue = check_null_check_mismatch(asm_stats, decomp_stats)
    if null_issue:
        issues.append(null_issue)

    # Signedness
    sign_issue = check_signedness_mismatch(asm_stats, decomp_stats)
    if sign_issue:
        issues.append(sign_issue)

    # Access sizes
    access_issue = check_access_size_mismatch(asm_stats, decomp_stats)
    if access_issue:
        issues.append(access_issue)

    # Artifacts
    issues.extend(check_decompiler_artifacts(decomp_stats))

    # Basic block semantic diff (requires raw code)
    if assembly_code and decompiled_code:
        block_issues = check_semantic_block_mismatch(
            asm_stats, decomp_stats, assembly_code, decompiled_code,
        )
        issues.extend(block_issues)

    # Sort by severity (highest first)
    issues.sort(key=lambda i: -int(i.severity))

    return issues


# ---------------------------------------------------------------------------
# DB helpers (bound to this skill's WORKSPACE_ROOT)
# ---------------------------------------------------------------------------
resolve_db_path, resolve_tracking_db = make_db_resolvers(WORKSPACE_ROOT)


__all__ = [
    "AsmInstruction",
    "AsmStats",
    "BasicBlock",
    "SemanticDiffResult",
    "check_access_size_mismatch",
    "check_branch_count_mismatch",
    "check_call_count_mismatch",
    "check_decompiler_artifacts",
    "check_null_check_mismatch",
    "check_return_type_mismatch",
    "check_semantic_block_mismatch",
    "check_signedness_mismatch",
    "decode_mangled_return_type",
    "DECOMPILATION_FAILURE_PREFIXES",
    "DecompStats",
    "emit_error",
    "extract_basic_blocks",
    "ISSUE_CATEGORIES",
    "is_decompilation_failure",
    "parse_asm_instruction",
    "parse_assembly",
    "parse_decompiled",
    "parse_json_safe",
    "resolve_db_path",
    "resolve_tracking_db",
    "run_heuristic_checks",
    "SCRIPT_DIR",
    "SEVERITY_LABELS",
    "Severity",
    "VerificationIssue",
    "VerificationResult",
    "WORKSPACE_ROOT",
]
