"""Shared x64 assembly regex patterns for cross-module use.

Consolidates commonly duplicated assembly analysis patterns from
``asm_metrics``, ``verifier/_comparison``, ``type-reconstructor``,
and ``verify-decompiled`` into a single importable module.

Usage::

    from helpers.asm_patterns import (
        ASM_CALL_RE, ASM_BRANCH_RE, ASM_MEM_OFFSET_RE,
        IMP_PREFIX_RE, CALL_TARGET_RE,
    )
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Instruction-level patterns (shared with asm_metrics.py)
# ---------------------------------------------------------------------------

# Matches call instructions
ASM_CALL_RE = re.compile(r"\bcall\b", re.I)

# Matches conditional/unconditional branch instructions
ASM_BRANCH_RE = re.compile(
    r"\b(?:je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|jmp|jns|js"
    r"|jo|jno|jcxz|jecxz|jrcxz|loop|loope|loopne)\b",
    re.I,
)

# Matches return instructions
ASM_RET_RE = re.compile(r"\bretn?\b", re.I)

# Matches syscall / int 2Eh
ASM_SYSCALL_RE = re.compile(r"\b(?:syscall|int\s+2[eE]h?)\b", re.I)

# ---------------------------------------------------------------------------
# Import prefix patterns
# ---------------------------------------------------------------------------

# Strips __imp_ / _imp_ / j_ prefixes from imported API names
IMP_PREFIX_RE = re.compile(r"(?:__imp_|_imp_|__imp__|j_)(.+)")

# Extracts the target of a call instruction (handles cs:__imp_Foo, [rax], etc.)
CALL_TARGET_RE = re.compile(
    r"call\s+(?:qword\s+ptr\s+)?"
    r"(?:\[.*\]|(?:cs:)?(?:__imp_|_imp_|j_)?(\w+))"
)

# ---------------------------------------------------------------------------
# Memory access patterns
# ---------------------------------------------------------------------------

# Matches [base+offset] memory references in IDA-style assembly.
# Handles simple [reg+offset], SIB [reg+reg*scale+offset], [reg+reg+offset].
ASM_MEM_OFFSET_RE = re.compile(
    r"\["
    r"(\w+)"                              # base register
    r"(?:\s*\+\s*\w+\s*\*\s*\d+)?"       # optional index*scale (e.g. +rcx*8)
    r"(?:\s*\+\s*\w+)?"                   # optional second register (e.g. +rdx)
    r"\s*[+]\s*"
    r"([0-9A-Fa-f]+h?)"                   # offset
    r"\]"
)

# ptr size qualifier (byte ptr, dword ptr, etc.)
ASM_PTR_RE = re.compile(r"(byte|word|dword|qword)\s+ptr", re.IGNORECASE)

# Load/compare destination register extraction
ASM_LOAD_RE = re.compile(r"(?:movs?[xz]?x?|lea|cmp|test)\s+(\w+)", re.IGNORECASE)

# Prologue save: mov CALLEE_SAVED, PARAM_REG
ASM_PROLOGUE_SAVE_RE = re.compile(
    r"mov\s+(\w+)\s*,\s*(rcx|ecx|rdx|edx|r8d?|r9d?)\b", re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Global variable patterns in IDA output
# ---------------------------------------------------------------------------

# dword_XXXX, qword_XXXX, word_XXXX, byte_XXXX, off_XXXX, unk_XXXX
ASM_GLOBAL_RE = re.compile(r"\b((?:dword|qword|word|byte|off|unk)_[0-9A-Fa-f]+)\b")

# ---------------------------------------------------------------------------
# IDA import-thunk prefix stripping
# ---------------------------------------------------------------------------

_IDA_IMPORT_PREFIXES = ("__imp_", "_imp_", "j_", "cs:")


def strip_import_prefix(api_name: str) -> str:
    """Remove IDA import-thunk prefixes (``__imp_``, ``_imp_``, ``j_``, ``cs:``) from *api_name*."""
    for pfx in _IDA_IMPORT_PREFIXES:
        if api_name.startswith(pfx):
            return api_name[len(pfx):]
    return api_name


# ---------------------------------------------------------------------------
# IDA decompiler parameter patterns
# ---------------------------------------------------------------------------

# Matches IDA-generated parameter names: a1, a2, a3, ...
IDA_PARAM_RE = re.compile(r"\ba(\d+)\b")
