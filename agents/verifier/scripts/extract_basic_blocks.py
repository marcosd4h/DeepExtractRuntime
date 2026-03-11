#!/usr/bin/env python3
"""Extract and display basic blocks from a function's assembly code.

Splits assembly into basic blocks (leader = label or post-branch instruction)
to enable block-by-block verification where the agent can map each basic block
to a section of lifted code.

Usage:
    python extract_basic_blocks.py <db_path> <function_name>
    python extract_basic_blocks.py <db_path> --id <func_id>
    python extract_basic_blocks.py <db_path> --id <func_id> --json

Output:
    Numbered basic blocks with:
    - Entry address (or label)
    - Instructions in the block
    - Exit type (fall-through / conditional jump / unconditional jump / call / ret)
    - Successor block(s)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Import shared utilities
from _common import (
    WORKSPACE_ROOT,
    parse_asm_instruction,
    resolve_db_path,
)

sys.path.insert(0, str(WORKSPACE_ROOT / ".agent"))
from helpers import (
    load_function_index_for_db,
    open_individual_analysis_db,
    resolve_function,
)
from helpers.errors import ErrorCode, db_error_handler, emit_error, safe_parse_args
from helpers.json_output import emit_json
from helpers.script_runner import get_workspace_args


# ---------------------------------------------------------------------------
# IDA assembly line parsing for basic block extraction
# ---------------------------------------------------------------------------

# Address extraction from IDA format:  .text:00007FF7ABCD1234
_ADDR_RE = re.compile(r"^\.[a-z]+:([0-9A-Fa-f]+)")

# Label detection
_LABEL_RE = re.compile(
    r"^(?:\.[a-z]+:[0-9A-Fa-f]+\s+)?"  # optional segment:address
    r"(loc_[0-9A-Fa-f]+|LABEL_\d+|\w+_\d+)\s*:"  # label name followed by colon
)

# Also detect IDA-style labels that appear as standalone lines
_STANDALONE_LABEL_RE = re.compile(
    r"^\.[a-z]+:[0-9A-Fa-f]+\s+(loc_[0-9A-Fa-f]+|LABEL_\d+)"
)

# Unconditional jump mnemonics
_UNCONDITIONAL_JUMPS = {"jmp"}

# Conditional jump mnemonics
_CONDITIONAL_JUMPS = {
    "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
    "jb", "jbe", "ja", "jae", "jnl", "jnle", "jng", "jnge",
    "jnb", "jnbe", "jna", "jnae", "js", "jns", "jo", "jno",
    "jc", "jnc", "jcxz", "jecxz", "jrcxz",
    "loop", "loope", "loopne",
}

# Jump target extraction
_JUMP_TARGET_RE = re.compile(r"\b(loc_[0-9A-Fa-f]+|LABEL_\d+|short\s+loc_[0-9A-Fa-f]+)")


# x64/x86 general-purpose registers (for indirect jump/call detection)
_GP_REGISTERS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
})

# SEH patterns in decompiled code
_SEH_TRY_RE = re.compile(r"__try\b|_try\b|RtlpExecuteHandlerForException", re.IGNORECASE)
_SEH_EXCEPT_RE = re.compile(r"__except\b|_except\b|__finally\b|_finally\b", re.IGNORECASE)

# .pdata / exception handler references in assembly
_PDATA_REF_RE = re.compile(
    r"\bpdata\b|\.pdata\b|\bexcept_handler\b|\b__C_specific_handler\b|\bpdata_section\b",
    re.IGNORECASE,
)


def _is_indirect_jump_or_call(mnemonic: str, operands: str) -> bool:
    """Detect indirect jumps and calls (jmp rax, jmp [reg], call [reg+offset]).

    Returns True for patterns whose target cannot be resolved statically:
      jmp rax          -- register-indirect
      jmp [rax]        -- memory-indirect
      jmp [rax+rcx*8]  -- jump table dispatch
      call [rbx+10h]   -- vtable call
    """
    mn = mnemonic.lower()
    if mn not in ("jmp", "call"):
        return False

    ops = operands.strip()

    # Memory-indirect: operands contain brackets
    if "[" in ops:
        return True

    # Register-indirect: operand is a bare GP register
    if ops.lower() in _GP_REGISTERS:
        return True

    return False


@dataclass
class BasicBlock:
    """A single basic block in the control flow graph."""
    block_id: int
    entry_label: str = ""       # label name (loc_XXXX) or address
    entry_address: str = ""     # hex address if available
    instructions: list[str] = field(default_factory=list)
    instruction_count: int = 0
    exit_type: str = ""         # fall-through, conditional, unconditional, call, ret, indirect_jump
    jump_target: str = ""       # target label for jumps
    successors: list[int] = field(default_factory=list)  # successor block IDs
    has_call: bool = False
    has_memory_access: bool = False
    has_indirect_jump: bool = False

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "entry_label": self.entry_label,
            "entry_address": self.entry_address,
            "instruction_count": self.instruction_count,
            "instructions": self.instructions,
            "exit_type": self.exit_type,
            "jump_target": self.jump_target,
            "successors": self.successors,
            "has_call": self.has_call,
            "has_memory_access": self.has_memory_access,
            "has_indirect_jump": self.has_indirect_jump,
        }


def _extract_address(line: str) -> str:
    """Extract hex address from an IDA assembly line."""
    m = _ADDR_RE.match(line.strip())
    return m.group(1) if m else ""


def _extract_label(line: str) -> str:
    """Extract label name if this line defines a label."""
    stripped = line.strip()

    # Check for label: pattern
    m = _LABEL_RE.match(stripped)
    if m:
        return m.group(1)

    # Check for standalone label (IDA sometimes just shows the label name)
    m = _STANDALONE_LABEL_RE.match(stripped)
    if m:
        return m.group(1)

    return ""


def _extract_jump_target(operands: str) -> str:
    """Extract jump target label from operands."""
    m = _JUMP_TARGET_RE.search(operands)
    if m:
        target = m.group(1)
        # Strip "short " prefix
        if target.startswith("short "):
            target = target[6:]
        return target
    return ""


def extract_basic_blocks(assembly_code: str) -> list[BasicBlock]:
    """Split assembly code into basic blocks.

    Leaders (start of a basic block) are:
    1. The first instruction
    2. Any instruction that is the target of a branch (i.e., has a label)
    3. Any instruction immediately after a branch or ret instruction
    """
    if not assembly_code or not assembly_code.strip():
        return []

    lines = assembly_code.splitlines()

    # First pass: identify leaders (indices that start basic blocks)
    leaders: set[int] = {0}  # First instruction is always a leader
    label_to_line: dict[str, int] = {}

    # Pre-scan for labels and post-branch positions
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        # Check if this line has a label
        label = _extract_label(stripped)
        if label:
            leaders.add(i)
            label_to_line[label] = i

        # Check if this is a branch/ret/indirect jump (next real instruction is a leader)
        inst = parse_asm_instruction(stripped)
        if inst and (inst.is_branch or inst.is_ret):
            # Find next non-empty, non-comment line
            for j in range(i + 1, len(lines)):
                next_stripped = lines[j].strip()
                if next_stripped and not next_stripped.startswith(";"):
                    leaders.add(j)
                    break
        elif inst and _is_indirect_jump_or_call(inst.mnemonic, inst.operands):
            for j in range(i + 1, len(lines)):
                next_stripped = lines[j].strip()
                if next_stripped and not next_stripped.startswith(";"):
                    leaders.add(j)
                    break

    # Sort leaders
    sorted_leaders = sorted(leaders)

    # Second pass: build basic blocks
    blocks: list[BasicBlock] = []
    leader_to_block: dict[int, int] = {}  # line index -> block ID

    for block_idx, leader_line in enumerate(sorted_leaders):
        block = BasicBlock(block_id=block_idx)

        # Determine end of this block (start of next leader or end of file)
        if block_idx + 1 < len(sorted_leaders):
            end_line = sorted_leaders[block_idx + 1]
        else:
            end_line = len(lines)

        # Entry info
        block.entry_address = _extract_address(lines[leader_line])
        block.entry_label = _extract_label(lines[leader_line])
        leader_to_block[leader_line] = block_idx

        # Collect instructions in this block
        last_inst = None
        for i in range(leader_line, end_line):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith(";"):
                continue

            inst = parse_asm_instruction(stripped)
            if inst:
                block.instructions.append(stripped)
                block.instruction_count += 1
                last_inst = inst

                if inst.is_call:
                    block.has_call = True
                if "[" in inst.operands and inst.mnemonic != "lea":
                    block.has_memory_access = True

        # Determine exit type
        if last_inst is None:
            block.exit_type = "empty"
        elif last_inst.is_ret:
            block.exit_type = "ret"
        elif _is_indirect_jump_or_call(last_inst.mnemonic, last_inst.operands):
            block.exit_type = "indirect_jump"
            block.has_indirect_jump = True
        elif last_inst.mnemonic in _UNCONDITIONAL_JUMPS:
            block.exit_type = "unconditional_jump"
            block.jump_target = _extract_jump_target(last_inst.operands)
        elif last_inst.mnemonic in _CONDITIONAL_JUMPS:
            block.exit_type = "conditional_jump"
            block.jump_target = _extract_jump_target(last_inst.operands)
        else:
            block.exit_type = "fall-through"

        blocks.append(block)

    # Third pass: resolve successors
    label_to_block_id: dict[str, int] = {}
    for block in blocks:
        if block.entry_label:
            label_to_block_id[block.entry_label] = block.block_id

    for block in blocks:
        if block.exit_type == "fall-through":
            # Successor is the next block
            if block.block_id + 1 < len(blocks):
                block.successors.append(block.block_id + 1)
        elif block.exit_type == "conditional_jump":
            # Two successors: jump target and fall-through
            if block.jump_target and block.jump_target in label_to_block_id:
                block.successors.append(label_to_block_id[block.jump_target])
            if block.block_id + 1 < len(blocks):
                block.successors.append(block.block_id + 1)
        elif block.exit_type == "unconditional_jump":
            # One successor: jump target
            if block.jump_target and block.jump_target in label_to_block_id:
                block.successors.append(label_to_block_id[block.jump_target])
        # ret, empty, and indirect_jump have no known successors

    return blocks


def detect_seh_patterns(assembly_code: str, decompiled_code: str | None = None) -> dict:
    """Detect SEH (Structured Exception Handling) patterns in a function.

    Returns a dict with:
      has_seh: bool
      indicators: list of strings describing what was found
    """
    indicators: list[str] = []

    if assembly_code:
        for line in assembly_code.splitlines():
            stripped = line.strip()
            if _PDATA_REF_RE.search(stripped):
                indicators.append(f"Exception handler reference: {stripped[:80]}")

    if decompiled_code:
        for m in _SEH_TRY_RE.finditer(decompiled_code):
            indicators.append(f"SEH __try pattern at offset {m.start()}")
        for m in _SEH_EXCEPT_RE.finditer(decompiled_code):
            indicators.append(f"SEH __except/__finally pattern at offset {m.start()}")

    return {
        "has_seh": bool(indicators),
        "indicators": indicators,
    }


def compute_limitations(
    blocks: list[BasicBlock],
    seh_info: dict,
) -> list[str]:
    """Compute analysis limitations for the extracted basic blocks.

    Returns a list of limitation strings describing patterns that
    couldn't be fully analyzed.
    """
    limitations: list[str] = []

    indirect_count = sum(1 for b in blocks if b.has_indirect_jump)
    if indirect_count:
        limitations.append(
            f"indirect_jump: {indirect_count} block(s) end with indirect "
            f"jumps (jmp reg / jmp [mem]) whose targets cannot be resolved "
            f"statically"
        )

    if seh_info.get("has_seh"):
        limitations.append(
            "unresolved_exception_flow: function uses SEH exception handling "
            "which creates hidden control flow not visible in the basic block graph"
        )

    unresolved_jumps = sum(
        1 for b in blocks
        if b.exit_type == "unconditional_jump" and b.jump_target and not b.successors
    )
    if unresolved_jumps:
        limitations.append(
            f"unresolved_targets: {unresolved_jumps} unconditional jump(s) "
            f"target labels not found in the function body"
        )

    return limitations


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _print_blocks_human(
    blocks: list[BasicBlock],
    func_name: str,
    db_path: str,
    limitations: list[str] | None = None,
) -> None:
    """Print basic blocks in human-readable format."""
    print(f"{'#' * 80}")
    print(f"  BASIC BLOCK ANALYSIS")
    print(f"  Function: {func_name}")
    print(f"  DB: {db_path}")
    print(f"  Total blocks: {len(blocks)}")
    print(f"{'#' * 80}")
    print()

    # Summary
    exit_types = {}
    total_insts = 0
    call_blocks = 0
    mem_blocks = 0
    indirect_blocks = 0
    for b in blocks:
        exit_types[b.exit_type] = exit_types.get(b.exit_type, 0) + 1
        total_insts += b.instruction_count
        if b.has_call:
            call_blocks += 1
        if b.has_memory_access:
            mem_blocks += 1
        if b.has_indirect_jump:
            indirect_blocks += 1

    print(f"Summary:")
    print(f"  Total instructions: {total_insts}")
    print(f"  Blocks with calls:  {call_blocks}")
    print(f"  Blocks with memory: {mem_blocks}")
    if indirect_blocks:
        print(f"  Blocks with indirect jumps: {indirect_blocks}")
    print(f"  Exit types: {json.dumps(exit_types)}")

    if limitations:
        print(f"\n  Limitations ({len(limitations)}):")
        for lim in limitations:
            print(f"    - {lim}")
    print()

    # Block details
    for block in blocks:
        label_str = f" ({block.entry_label})" if block.entry_label else ""
        addr_str = f"@{block.entry_address}" if block.entry_address else ""

        print(f"{'=' * 70}")
        print(f"  Block #{block.block_id}{label_str} {addr_str}")
        print(f"  Instructions: {block.instruction_count} | "
              f"Exit: {block.exit_type} | "
              f"Successors: {block.successors}")
        if block.jump_target:
            print(f"  Jump target: {block.jump_target}")
        print(f"{'=' * 70}")

        for inst_line in block.instructions:
            print(f"  {inst_line}")
        print()


def _print_blocks_json(
    blocks: list[BasicBlock],
    func_name: str,
    func_id: int,
    limitations: list[str] | None = None,
) -> None:
    """Print basic blocks as JSON."""
    output = {
        "function_name": func_name,
        "function_id": func_id,
        "total_blocks": len(blocks),
        "total_instructions": sum(b.instruction_count for b in blocks),
        "blocks": [b.to_dict() for b in blocks],
        "limitations": limitations or [],
    }
    emit_json(output)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def extract_and_display(
    db_path: str,
    function_name: str | None = None,
    function_id: int | None = None,
    output_json: bool = False,
) -> None:
    """Extract basic blocks for a function and display them."""
    function_index = load_function_index_for_db(db_path)
    with open_individual_analysis_db(db_path) as db:
        func, err = resolve_function(
            db, name=function_name, function_id=function_id,
            function_index=function_index,
        )
        if err:
            if "Multiple matches" in err:
                emit_error(err, ErrorCode.AMBIGUOUS)
            emit_error(f"[{Path(db_path).stem}] {err}", ErrorCode.NOT_FOUND)

        assert func is not None

        if not func.assembly_code or not func.assembly_code.strip():
            emit_error(f"No assembly code available for {func.function_name}.", ErrorCode.NO_DATA)

        blocks = extract_basic_blocks(func.assembly_code)
        seh_info = detect_seh_patterns(func.assembly_code, func.decompiled_code)
        limitations = compute_limitations(blocks, seh_info)

        if output_json:
            _print_blocks_json(
                blocks, func.function_name or "(unnamed)", func.function_id,
                limitations=limitations,
            )
        else:
            _print_blocks_human(
                blocks, func.function_name or "(unnamed)", db_path,
                limitations=limitations,
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract basic blocks from a function's assembly code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("db_path", help="Path to the individual analysis DB")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("function_name", nargs="?", help="Function name to analyze")
    group.add_argument("--id", type=int, dest="function_id", help="Function ID to analyze")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = safe_parse_args(parser)

    # Force JSON output when workspace mode is active so bootstrap captures
    # structured data instead of human-readable text.
    force_json = args.json or bool(get_workspace_args(args)["workspace_dir"])

    db_path = resolve_db_path(args.db_path)

    if args.function_id is None and args.function_name is None:
        emit_error("Provide a function name or --id", ErrorCode.INVALID_ARGS)

    with db_error_handler(db_path, "extracting basic blocks"):
        extract_and_display(
            db_path=db_path,
            function_name=args.function_name,
            function_id=args.function_id,
            output_json=force_json,
        )


if __name__ == "__main__":
    main()
