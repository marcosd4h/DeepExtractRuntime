"""Shared utilities for extracting metrics from x64 assembly code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .asm_patterns import ASM_BRANCH_RE, ASM_CALL_RE, ASM_RET_RE, ASM_SYSCALL_RE


@dataclass
class AsmMetrics:
    """Structural metrics extracted from assembly code."""
    instruction_count: int = 0
    call_count: int = 0
    branch_count: int = 0
    ret_count: int = 0
    has_syscall: bool = False
    is_leaf: bool = True  # no calls
    is_tiny: bool = True  # < 10 instructions


def get_asm_metrics(assembly_code: Optional[str]) -> AsmMetrics:
    """Extract structural metrics from IDA-formatted assembly text."""
    if not assembly_code:
        return AsmMetrics()
    
    m = AsmMetrics()
    for line in assembly_code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
            
        m.instruction_count += 1
        if ASM_CALL_RE.search(stripped):
            m.call_count += 1
        if ASM_BRANCH_RE.search(stripped):
            m.branch_count += 1
        if ASM_RET_RE.search(stripped):
            m.ret_count += 1
        if ASM_SYSCALL_RE.search(stripped):
            m.has_syscall = True
            
    m.is_leaf = m.call_count == 0
    m.is_tiny = m.instruction_count < 10
    return m


def count_asm_instructions(assembly_code: Optional[str]) -> int:
    """Count non-empty, non-comment lines in assembly text."""
    if not assembly_code:
        return 0
    count = 0
    for line in assembly_code.splitlines():
        s = line.strip()
        if s and not s.startswith(";"):
            count += 1
    return count


def count_asm_calls(assembly_code: Optional[str]) -> int:
    """Count call instructions in assembly text."""
    if not assembly_code:
        return 0
    return sum(1 for line in assembly_code.splitlines() if ASM_CALL_RE.search(line))
