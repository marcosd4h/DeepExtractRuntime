import pytest
from helpers.asm_metrics import get_asm_metrics, count_asm_instructions, count_asm_calls

def test_get_asm_metrics_basic():
    asm = """
    mov eax, 1
    call some_func
    je label1
    ret
    """
    metrics = get_asm_metrics(asm)
    assert metrics.instruction_count == 4
    assert metrics.call_count == 1
    assert metrics.branch_count == 1
    assert metrics.ret_count == 1
    assert metrics.is_leaf is False
    assert metrics.is_tiny is True

def test_get_asm_metrics_empty():
    metrics = get_asm_metrics("")
    assert metrics.instruction_count == 0
    assert metrics.is_leaf is True

def test_count_asm_instructions():
    asm = """
    ; comment
    mov eax, 1
    
    add eax, 2
    """
    assert count_asm_instructions(asm) == 2

def test_count_asm_calls():
    asm = """
    call func1
    mov eax, 1
    call func2
    """
    assert count_asm_calls(asm) == 2

def test_get_asm_metrics_syscall():
    asm = """
    mov eax, 1
    syscall
    """
    metrics = get_asm_metrics(asm)
    assert metrics.has_syscall is True
