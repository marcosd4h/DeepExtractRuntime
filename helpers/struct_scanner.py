"""Shared struct/class access scanners for decompiled and assembly code."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Optional

from .calling_conventions import (
    ASM_PTR_SIZES,
    ASM_REG_SIZES,
    PARAM_REGS_X64,
    STACK_REGS,
)


def _parse_int_literal(text: str) -> int:
    value = text.strip()
    return int(value, 16) if value.startswith(("0x", "0X")) else int(value)


def _type_size(name: str, type_sizes: dict[str, int], default_size: int = 8) -> int:
    return int(type_sizes.get(name.strip(), default_size))


def _type_choice_regex(type_sizes: dict[str, int]) -> str:
    names = sorted(type_sizes.keys(), key=len, reverse=True)
    if not names:
        return r"\w+"
    return "|".join(re.escape(name) for name in names)


def scan_batch_struct_accesses(
    decompiled_code: str,
    type_sizes: dict[str, int],
) -> list[dict[str, Any]]:
    """Batch-lift style scanning output: base/offset/size/type_name/pattern."""
    if not decompiled_code:
        return []

    type_choice = _type_choice_regex(type_sizes)
    pat_indexed = re.compile(
        r"\*\(\s*\(\s*(" + type_choice + r")\s*\*\s*\)\s*(\w+)\s*\+\s*(\d+)\s*\)"
    )
    pat_direct = re.compile(
        r"\*\(\s*(" + type_choice + r")\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[\da-fA-F]+|\d+)\s*\)"
    )
    pat_zero = re.compile(
        r"\*\(\s*(" + type_choice + r")\s*\*\s*\)\s*(\w+)\s*[;,\)\s]"
    )

    accesses: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()

    for match in pat_indexed.finditer(decompiled_code):
        type_name, base, index_str = match.group(1), match.group(2), match.group(3)
        size = _type_size(type_name, type_sizes)
        offset = int(index_str) * size
        key = (base, offset, size)
        if key in seen:
            continue
        seen.add(key)
        accesses.append(
            {
                "base": base,
                "offset": offset,
                "size": size,
                "type_name": type_name,
                "pattern": "indexed",
            }
        )

    for match in pat_direct.finditer(decompiled_code):
        type_name, base, offset_str = match.group(1), match.group(2), match.group(3)
        size = _type_size(type_name, type_sizes)
        offset = int(offset_str, 0)
        key = (base, offset, size)
        if key in seen:
            continue
        seen.add(key)
        accesses.append(
            {
                "base": base,
                "offset": offset,
                "size": size,
                "type_name": type_name,
                "pattern": "direct",
            }
        )

    for match in pat_zero.finditer(decompiled_code):
        type_name, base = match.group(1), match.group(2)
        size = _type_size(type_name, type_sizes)
        key = (base, 0, size)
        if key in seen:
            continue
        seen.add(key)
        accesses.append(
            {
                "base": base,
                "offset": 0,
                "size": size,
                "type_name": type_name,
                "pattern": "zero_offset",
            }
        )

    accesses.sort(key=lambda item: (item["base"], item["offset"]))
    return accesses


def scan_decompiled_struct_accesses(
    code: str,
    type_sizes: dict[str, int],
    *,
    default_size: int = 8,
) -> list[dict]:
    """Extract struct-field accesses from decompiled C++ code.

    Output schema:
      ``base``, ``type``, ``byte_offset``, ``size``, ``pattern``, ``line_num``
    """
    if not code:
        return []

    type_choice = _type_choice_regex(type_sizes)
    var_name = r"[a-zA-Z_]\w*"
    num = r"(?:0[xX][0-9a-fA-F]+|\d+)"

    re_elem = re.compile(
        r"\*\s*\(\s*\(\s*(" + type_choice + r")\s*\*\s*\)\s*(" + var_name + r")\s*\+\s*(" + num + r")\s*\)"
    )
    re_byte = re.compile(
        r"\*\s*\(\s*(" + type_choice + r")\s*\*\s*\)\s*\(\s*(?:\(\s*char\s*\*\s*\)\s*)?"
        + "(" + var_name + r")\s*\+\s*(" + num + r")\s*\)"
    )
    re_zero = re.compile(
        r"\*\s*\(\s*(" + type_choice + r")\s*\*\s*\)\s*(" + var_name + r")(?!\s*[+\-({\[\w])"
    )

    accesses: list[dict] = []
    for line_num, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        for match in re_elem.finditer(stripped):
            type_name = match.group(1).strip()
            base = match.group(2)
            elem_offset = _parse_int_literal(match.group(3))
            size = _type_size(type_name, type_sizes, default_size)
            accesses.append(
                {
                    "base": base,
                    "type": type_name,
                    "byte_offset": elem_offset * size,
                    "size": size,
                    "pattern": "typed_ptr_arith",
                    "line_num": line_num,
                }
            )

        for match in re_byte.finditer(stripped):
            type_name = match.group(1).strip()
            base = match.group(2)
            byte_offset = _parse_int_literal(match.group(3))
            size = _type_size(type_name, type_sizes, default_size)
            accesses.append(
                {
                    "base": base,
                    "type": type_name,
                    "byte_offset": byte_offset,
                    "size": size,
                    "pattern": "byte_offset",
                    "line_num": line_num,
                }
            )

        already = {a["base"] for a in accesses if a["line_num"] == line_num}
        for match in re_zero.finditer(stripped):
            type_name = match.group(1).strip()
            base = match.group(2)
            if base in already:
                continue
            size = _type_size(type_name, type_sizes, default_size)
            accesses.append(
                {
                    "base": base,
                    "type": type_name,
                    "byte_offset": 0,
                    "size": size,
                    "pattern": "zero_offset",
                    "line_num": line_num,
                }
            )

    return accesses


# [reg+offseth] -- struct field access in IDA assembly (h suffix = hex)
_RE_ASM_MEM = re.compile(r"\[\s*([a-zA-Z]\w*)\s*\+\s*([0-9A-Fa-f]+)h?\s*\]")
# [reg] -- zero-offset dereference
_RE_ASM_MEM_ZERO = re.compile(r"\[\s*([a-zA-Z]\w*)\s*\]")
# ptr size qualifier: byte/word/dword/qword ptr
_RE_ASM_PTR = re.compile(r"(byte|word|dword|qword|xmmword)\s+ptr", re.IGNORECASE)
# Destination register in load-type instructions
_RE_ASM_LOAD = re.compile(r"(?:movs?[xz]?x?|lea|cmp|test)\s+(\w+)", re.IGNORECASE)
# Prologue pattern: mov CALLEE_SAVED, PARAM_REG (parameter register save)
_RE_PROLOGUE_SAVE = re.compile(
    r"mov\s+(\w+)\s*,\s*(rcx|ecx|rdx|edx|r8d?|r9d?)\b", re.IGNORECASE
)


def _detect_param_reg_aliases(
    asm_lines: list[str],
    param_regs: dict[str, int],
    stack_regs: frozenset[str],
    max_prologue: int = 30,
) -> dict[str, int]:
    aliases: dict[str, int] = {}
    for line in asm_lines[:max_prologue]:
        match = _RE_PROLOGUE_SAVE.search(line.lower())
        if not match:
            continue
        dest = match.group(1)
        src = match.group(2)
        param_num = param_regs.get(src, 0)
        if param_num and dest not in param_regs and dest not in stack_regs:
            aliases[dest] = param_num
    return aliases


def scan_assembly_struct_accesses(
    code: str,
    *,
    param_regs: dict[str, int] | None = None,
    asm_ptr_sizes: dict[str, int] | None = None,
    asm_reg_sizes: dict[str, int] | None = None,
    stack_regs: frozenset[str] | None = None,
) -> list[dict]:
    """Extract struct-field memory accesses from assembly.

    Output schema:
      ``base``, ``byte_offset``, ``size``, ``param_num``, ``source``, ``line_num``
    """
    if not code:
        return []

    param_regs = param_regs or PARAM_REGS_X64
    asm_ptr_sizes = asm_ptr_sizes or ASM_PTR_SIZES
    asm_reg_sizes = asm_reg_sizes or ASM_REG_SIZES
    stack_regs = stack_regs or STACK_REGS

    lines = code.splitlines()
    param_map: dict[str, int] = dict(param_regs)
    param_map.update(_detect_param_reg_aliases(lines, param_regs, stack_regs))

    accesses: list[dict] = []
    for line_num, line in enumerate(lines, 1):
        low = line.lower().strip()
        if not low:
            continue

        mem = _RE_ASM_MEM.search(low)
        if mem:
            base_reg = mem.group(1)
            if base_reg in stack_regs:
                continue
            bracket_start = low.index("[")
            bracket_end = low.index("]", bracket_start)
            if "*" in low[bracket_start:bracket_end]:
                continue
            byte_offset = int(mem.group(2).rstrip("hH"), 16)
        else:
            zero = _RE_ASM_MEM_ZERO.search(low)
            if not zero:
                continue
            base_reg = zero.group(1)
            if base_reg in stack_regs:
                continue
            byte_offset = 0

        size = 0
        ptr_match = _RE_ASM_PTR.search(low)
        if ptr_match:
            size = asm_ptr_sizes.get(ptr_match.group(1).lower(), 0)
        if not size:
            load_match = _RE_ASM_LOAD.search(low)
            if load_match:
                size = asm_reg_sizes.get(load_match.group(1).lower(), 0)
        if not size:
            size = 8

        accesses.append(
            {
                "base": base_reg,
                "byte_offset": byte_offset,
                "size": size,
                "param_num": param_map.get(base_reg, 0),
                "source": "assembly",
                "line_num": line_num,
            }
        )

    return accesses


def parse_signature_params(signature: str) -> dict[str, str]:
    """Extract ``param_name -> type_string`` from a function signature."""
    if not signature:
        return {}

    depth = 0
    start = end = -1
    for index, char in enumerate(signature):
        if char == "(":
            if depth == 0:
                start = index
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                end = index
                break

    if start < 0 or end < 0:
        return {}

    params_str = signature[start + 1 : end].strip()
    if not params_str or params_str in {"void", "..."}:
        return {}

    params: dict[str, str] = {}
    depth = 0
    current: list[str] = []
    param_pos = 1
    for char in params_str:
        if char == "," and depth == 0:
            _extract_one_param("".join(current).strip(), params, position=param_pos)
            param_pos += 1
            current = []
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        current.append(char)

    _extract_one_param("".join(current).strip(), params, position=param_pos)
    return params


def _extract_one_param(text: str, out: dict[str, str], position: int = 0) -> None:
    text = text.replace("/*BYREF*/", "").strip()
    if not text:
        return
    tokens = text.split()
    if not tokens:
        return

    name = tokens[-1].lstrip("*&")
    if not name or not (name[0].isalpha() or name[0] == "_"):
        if position > 0:
            synthetic = f"a{position}"
            type_str = text.rstrip("* &").strip()
            if type_str:
                out[synthetic] = type_str
        return

    type_str = text[: text.rfind(name)].strip()
    if not type_str:
        type_str = " ".join(tokens[:-1]) if len(tokens) > 1 else "unknown"
    out[name] = type_str


def merge_struct_fields(
    all_accesses: dict[str, list[dict[str, Any]]],
    size_to_c_type: dict[int, str],
) -> list[dict[str, Any]]:
    """Merge struct accesses from multiple functions by byte offset.

    Accepts output from both ``scan_batch_struct_accesses``
    (keys: ``offset``, ``type_name``) and ``scan_decompiled_struct_accesses``
    (keys: ``byte_offset``, ``type``).
    """
    merged: dict[int, dict[str, Any]] = {}
    for access in [a for accesses in all_accesses.values() for a in accesses]:
        offset = int(access.get("offset", access.get("byte_offset", 0)))
        type_name = access.get("type_name", access.get("type", "unknown"))
        size = int(access.get("size", 0))
        if offset not in merged or size > int(merged[offset]["size"]):
            merged[offset] = {
                "offset": offset,
                "size": size,
                "type_name": type_name,
                "c_type": size_to_c_type.get(size, f"uint8_t[{size}]"),
            }
    return sorted(merged.values(), key=lambda field: field["offset"])


__all__ = [
    "merge_struct_fields",
    "parse_signature_params",
    "scan_assembly_struct_accesses",
    "scan_batch_struct_accesses",
    "scan_decompiled_struct_accesses",
]
