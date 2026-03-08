"""Shared calling-convention and assembly width constants.

Central source for x64 fastcall register mapping used by multiple skills.
"""

from __future__ import annotations

# Parameter number (1-based) -> all register aliases for that parameter.
PARAM_REGISTERS: dict[int, set[str]] = {
    1: {"rcx", "ecx", "cx", "cl", "ch"},
    2: {"rdx", "edx", "dx", "dl", "dh"},
    3: {"r8", "r8d", "r8w", "r8b"},
    4: {"r9", "r9d", "r9w", "r9b"},
}

# Reverse lookup: register -> parameter number.
REGISTER_TO_PARAM: dict[str, int] = {}
for _param_num, _aliases in PARAM_REGISTERS.items():
    for _reg in _aliases:
        REGISTER_TO_PARAM[_reg] = _param_num
del _param_num, _aliases, _reg

# Backward-compatible alias commonly used by reconstruct-types.
PARAM_REGS_X64 = REGISTER_TO_PARAM

# Register width table used for memory-access size inference.
ASM_REG_SIZES: dict[str, int] = {}
for _r in (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
):
    ASM_REG_SIZES[_r] = 8
for _r in (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
):
    ASM_REG_SIZES[_r] = 4
for _r in (
    "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
):
    ASM_REG_SIZES[_r] = 2
for _r in (
    "al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl", "ah", "bh", "ch", "dh",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
):
    ASM_REG_SIZES[_r] = 1
del _r

# Instruction operand width qualifiers.
ASM_PTR_SIZES: dict[str, int] = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "xmmword": 16,
}

# Stack/frame registers excluded from struct-field inference.
STACK_REGS: frozenset[str] = frozenset({"rsp", "esp", "sp", "rbp", "ebp", "bp"})


def param_name_for(param_number: int) -> str:
    """Return IDA-style positional parameter name (a1, a2, ...)."""
    return f"a{param_number}"


__all__ = [
    "ASM_PTR_SIZES",
    "ASM_REG_SIZES",
    "PARAM_REGISTERS",
    "PARAM_REGS_X64",
    "REGISTER_TO_PARAM",
    "STACK_REGS",
    "param_name_for",
]
