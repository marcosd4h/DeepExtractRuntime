# Decompiler Verification Technical Reference

Detailed reference for assembly-vs-decompiled comparison methodology, common Hex-Rays inaccuracy patterns, and the automated heuristic algorithms.

---

## Issue Category Details

### 1. Wrong Data Types / Access Sizes

The most common and most dangerous decompiler error. Hex-Rays often gets the access width wrong.

**How to detect:** Compare assembly memory access instruction to decompiled type cast.

| Assembly | Actual Width | Decompiled (if wrong) |
|----------|-------------|----------------------|
| `mov eax, [rcx+70h]` | DWORD (4 bytes) | `*((_QWORD *)a1 + N)` |
| `mov rax, [rcx+70h]` | QWORD (8 bytes) | `*((_DWORD *)a1 + N)` |
| `movzx eax, byte ptr [rcx+5]` | BYTE (1 byte) | `*((_DWORD *)a1 + N)` |
| `movzx eax, word ptr [rcx+A]` | WORD (2 bytes) | `*((_DWORD *)a1 + N)` |

**Fix pattern:**
```
Before: v5 = *((_QWORD *)a1 + 14);          // implies 8-byte read
After:  v5 = *(_DWORD *)((char *)a1 + 0x70); // actual: 4-byte DWORD at byte offset
```

### 2. Wrong Return Type

Hex-Rays frequently guesses `__int64` when the function returns a 32-bit value via `eax`.

**How to detect:** Decode the mangled name to find the encoded return type. Compare with the decompiled function signature.

| Mangled Code | Actual Return Type |
|-------------|-------------------|
| `H` | `int` |
| `I` | `unsigned int` |
| `J` | `long` |
| `K` | `unsigned long` |
| `_N` | `bool` |
| `X` | `void` |
| `_J` | `__int64` |
| `_K` | `unsigned __int64` |

Also check how `rax`/`eax` is used at `ret`: if only `eax` is set, the return is 32-bit.

### 3. Missing Operations

Assembly instructions with no corresponding decompiled code.

**Detection strategy:**
- Count branches in assembly vs if/goto in decompiled. A significant deficit in decompiled indicates missing branches.
- Look for `test reg, reg` + `jz/jnz` pairs (NULL checks) that have no corresponding `if` in decompiled code.
- Look for `cmp` + conditional branch sequences between two operations in assembly that appear adjacent in decompiled code.

### 4. Wrong Branch Signedness

Assembly uses `jb`/`ja` (unsigned) but decompiled shows `< 0` or signed comparison.

| Assembly Branch | Signedness | C++ Comparison |
|----------------|-----------|---------------|
| `jl` / `jle` / `jg` / `jge` | Signed | `< > <= >=` (signed int) |
| `jb` / `jbe` / `ja` / `jae` | Unsigned | `< > <= >=` (unsigned int) |
| `je` / `jne` / `jz` / `jnz` | Neutral | `== !=` or NULL check |
| `js` | Signed | `< 0` (sign flag) |

**Fix pattern:**
```
Before: if ( v7 < 0 )                            // signed
After:  if ( (unsigned int)v7 < (unsigned int)v8 ) // matches jb in assembly
```

### 5. Collapsed Multi-Step Operations

Decompiler merges multiple distinct assembly operations into one C++ expression, hiding intermediate state.

**Detection strategy (agent-driven):** Walk the assembly linearly. When you see:
1. A memory load (`mov reg, [mem]`)
2. A test or comparison (`test reg, reg` or `cmp reg, 0`)
3. A conditional branch (`jz`/`jnz` to skip the next block)
4. A function call or operation

And the decompiled code shows only step 1+4 merged into a single expression, the test+branch (steps 2-3) was collapsed.

**Fix pattern:**
```
Before: v10 = SomeFunc(*((_QWORD *)a1 + 3));
After:  v9 = *((_QWORD *)a1 + 3);
        if ( v9 )
            v10 = SomeFunc(v9);
```

### 6. Decompiler Artifacts

Things in the decompiled code with no assembly equivalent.

| Artifact | Description | Fix |
|----------|-------------|-----|
| `do { ... } while(0)` | Block wrapper, no loop in assembly | Remove wrapper, keep inner statements |
| `LOBYTE(v1) = expr` | Byte assignment for bool | `v1 = expr` |
| `(unsigned __int8)func()` | Redundant cast chain for bool return | `func()` |
| `(unsigned int)result` | Redundant cast on HRESULT return | `result` |

### 7. Wrong Offset in Pointer Arithmetic

Hex-Rays sometimes gets the scaled offset wrong.

**The scaling rule:**
```
*((_QWORD *)ptr + N)  -> byte offset = N * 8
*((_DWORD *)ptr + N)  -> byte offset = N * 4
*((_WORD  *)ptr + N)  -> byte offset = N * 2
*((_BYTE  *)ptr + N)  -> byte offset = N * 1
*(_TYPE *)((char *)ptr + N) -> byte offset = N (direct)
```

**Verification:** The assembly `[reg+offset]` always uses the **byte** offset. If the decompiled scaled offset doesn't match the assembly byte offset, the decompiler got it wrong.

Example:
```
Assembly:    mov eax, [rcx+1CBh]         // byte offset 0x1CB
Decompiled:  *((_DWORD *)a1 + 459)       // scaled: 459 * 4 = 0x72C (WRONG)
Fix:         *(_DWORD *)((char *)a1 + 0x1CB)  // direct byte offset
```

### 8. Lost Volatile / Side-Effect Operations

Decompiler may optimize away reads/writes it considers redundant but which are actually volatile.

**Detection:** Consecutive identical memory reads in assembly (same `[reg+offset]`). In decompiled code, only one read appears.

---

## Automated Heuristic Details

### Assembly Parsing

The `_common.py` module parses IDA's disassembly format:

```
.text:00000001800ABCDE   mov     eax, [rcx+70h]    ; comment
```

It extracts: mnemonic, operands, memory access sizes (from register widths and explicit size prefixes), branch signedness, and patterns like test+jz/jnz (NULL checks).

### Memory Access Size Detection

| Source | Width |
|--------|-------|
| `byte ptr` in operands | 1 |
| `word ptr` in operands | 2 |
| `dword ptr` in operands | 4 |
| `qword ptr` in operands | 8 |
| Destination register is `eax`/`ecx`/etc. + memory source | 4 |
| Destination register is `rax`/`rcx`/etc. + memory source | 8 |
| Destination register is `al`/`cl`/etc. + memory source | 1 |
| Destination register is `ax`/`cx`/etc. + memory source | 2 |
| `movzx`/`movsx` with `byte ptr` | 1 |
| `movzx`/`movsx` with `word ptr` | 2 |

### NULL Check Pattern Detection

Counts `test reg, reg` followed by `jz`/`jnz` (a neutral branch). These are the standard NULL-check idiom in x64 code. When the count of these patterns exceeds the number of `if`-statements in the decompiled code, some NULL checks are likely collapsed.

### Branch Signedness Analysis

Counts signed branches (`jl`/`jg`/`jle`/`jge`/`js`/etc.) separately from unsigned branches (`jb`/`ja`/`jbe`/`jae`/etc.). If assembly uses predominantly unsigned comparisons but decompiled code has no `(unsigned int)` casts, there may be a signedness mismatch.

---

## Mangled Name Return Type Decoding

Microsoft C++ mangled names encode the return type after the `@@` section and calling convention specifiers. The `_common.py` module attempts to decode the return type from common patterns:

| Mangled Fragment | Decoded Type |
|-----------------|--------------|
| `...@@UEAAHXZ` | `int` (H after calling conv) |
| `...@@QEAAXXZ` | `void` (X) |
| `...@@AEAA_NXZ` | `bool` (_N) |
| `...@@UEAA_JXZ` | `__int64` (_J) |
| `...@@UEAAIXZ` | `unsigned int` (I) |
| `...@@UEAAKXZ` | `unsigned long` (K) |

This is heuristic -- complex types (pointers, references, classes) may not decode correctly.

---

## Script Output Reference

### verify_function.py Output Sections

1. **FUNCTION SIGNATURE** -- base and extended signatures, mangled name
2. **ASSEMBLY STATISTICS** -- instruction/call/branch/NULL-check counts, memory access size distribution
3. **DECOMPILED CODE STATISTICS** -- line/if/goto counts, type cast distribution, artifact counts
4. **AUTOMATED HEURISTIC FINDINGS** -- issues found with severity, evidence, and fix suggestions
5. **AGENT VERIFICATION INSTRUCTIONS** -- guidance for manual deep comparison
6. **DECOMPILED CODE** -- full decompiled output to verify and correct
7. **ASSEMBLY CODE** -- full assembly (ground truth)

### scan_module.py Output Sections

1. **Scan Summary** -- function counts, scan coverage
2. **Issue Distribution** -- by severity and category
3. **Ranked Function List** -- all functions with issues, sorted by severity score
4. **Top Function Details** -- detailed findings for the top-5 most problematic functions
5. **Next Steps** -- command to verify individual functions

### Severity Scoring Formula

```
severity_score = critical_count * 100 + high_count * 10 + moderate_count * 3 + low_count * 1
```

Functions are ranked by this score in descending order.
