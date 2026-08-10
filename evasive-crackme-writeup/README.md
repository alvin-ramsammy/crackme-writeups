# Evasive — crackme writeup

Static-analysis writeup for **Evasive**, a Windows x64 crackme from [crackmes.one](https://crackmes.one).
The binary is an LZMA self-extractor whose real flag is computed on the stack and then
deliberately discarded, so it is never printed, written, or compared. Solving it requires
static analysis or a well-placed breakpoint — running the program only produces a decoy.

| | |
|---|---|
| Platform | Windows x64 (PE32+, console) |
| Tools used | Ghidra, Detect It Easy, Resource Hacker, 7-Zip, x64dbg, CyberChef |
| Techniques | Resource-embedded packer, LZMA-alone container, runtime API resolution, XOR-encoded string, dead-code flag, overlapping stack stores |
| Solve time | ~20 min once the packer is identified |

The challenge binary is **not redistributed here** — download it from crackmes.one and verify
against [`HASHES.md`](HASHES.md). See [Reproducing](#reproducing) to regenerate every artifact.

---

## TL;DR

1. `Evasive.exe` is a 46 KB stub. Six imports, two of which are `LoadLibraryA` +
   `GetProcAddress`; a 35 KB `.rsrc` section at entropy 7.99. It's packed.
2. The `RCDATA` resource named `FPACK` is a plain **LZMA-alone** container
   (`5D 00 00 10 00` + 8-byte size). No custom crypto. Decompress it → a 127 KB
   MinGW-built PE32+ with its COFF symbol table intact.
3. `main` in the unpacked binary does two unrelated things:
   - builds a 38-element `int` array, XORs every element with `0x60`, then **never uses the result**;
   - writes a *different* hardcoded 28-byte string to `flag.txt`.
4. The `flag.txt` string is a decoy: `F12ag_i5_somehow_1_hidden_XD`.
5. XOR-decoding the discarded array yields the real flag.

<details>
<summary><strong>Flag (spoiler)</strong></summary>

```
IEEE{S031me_T1mes_We_h1s_t0_Su111ffer}
```

</details>

---

## Stage 1 — Triage: recognising the packer

Before opening a disassembler, three cheap checks classify the file.

**Import table.** The entire import directory is six functions from one DLL:

```
KERNEL32.dll: HeapFree, GetProcessHeap, GetModuleHandleA, GetProcAddress, LoadLibraryA, HeapAlloc
```

A program that actually does work needs more than this. The presence of
`LoadLibraryA` + `GetProcAddress` means the real API set is resolved at runtime, so the
import table is intentionally uninformative. This is the single strongest packer tell.

**Section entropy.** Detect It Easy, or any entropy tool:

| Section | VSize | Entropy |
|---|---|---|
| `.text` | 0x1d41 | 6.16 |
| `.rdata` | 0x3be | 4.25 |
| `.data` | 0x20 | 0.00 |
| `.pdata` | 0x210 | 2.31 |
| **`.rsrc`** | **0x89d8** | **7.99** |
| `.reloc` | 0x14 | 0.22 |

Normal code and text sit at 4–6. Anything ≥ 7.5 is compressed or encrypted. A 35 KB
high-entropy resource in a 46 KB file means the resource *is* the program.

**Strings in the stub.** The strings the loader resolves dynamically are still visible
in `.rdata` and spell out the algorithm:

```
FindResourceW  LoadResource  LockResource  SizeofResource
VirtualAlloc   VirtualProtect  RtlAddFunctionTable
```

That is the canonical unpacking sequence: locate resource → allocate memory → decompress →
mark it executable → register exception tables so the unpacked code's SEH works → jump.
`RtlAddFunctionTable` in particular is specific to x64 unpackers, since x64 SEH is
table-driven rather than stack-based.

**Conclusion:** don't reverse the stub. Extract the payload and reverse *that*.

## Stage 2 — Unpacking

The resource is `RCDATA` / `FPACK`, 33,948 bytes. Its first bytes:

```
5D 00 00 10 00 | 01 F2 01 00 00 00 00 00 | 00 26 96 8E 70 ...
```

This is the [LZMA-alone](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm)
container format — a 13-byte header with no magic number, which is why it isn't
auto-detected by `file`:

| Offset | Size | Value | Meaning |
|---|---|---|---|
| 0 | 1 | `0x5D` | properties byte: `lc=3, lp=0, pb=2` (the LZMA defaults) |
| 1 | 4 | `0x00100000` | dictionary size, 1 MiB, little-endian |
| 5 | 8 | `0x1F201` = 127489 | uncompressed size, little-endian |
| 13 | … | | LZMA stream |

Recognising `5D 00 00 10 00` is worth committing to memory; it's the default output of
`xz --format=lzma`, 7-Zip's `.lzma`, and every LZMA SDK example.

**GUI route:** Resource Hacker → `RCDATA` → `FPACK` → *Save resource to a \*.bin file* →
rename to `payload.lzma` → 7-Zip → *Extract Here*.

**Script route:** [`solve/unpack.py`](solve/unpack.py).

Either way the output is a 127,489-byte PE32+ with **19 sections**, including `/4`, `/19`,
`/31`… — the MinGW convention for long section names, here DWARF debug sections. The COFF
symbol table survived, so `main` is named for us. The author packed the binary but never
stripped it; the packer was doing all the work.

Imports of the unpacked binary, which now describe actual behaviour:

```
KERNEL32.dll: CreateFileA, WriteFile, Sleep, VirtualProtect, VirtualQuery, ...
msvcrt.dll:   fprintf, fflush, strlen, strncmp, malloc, free, ...
```

> `strncmp` is imported but never reached from `main` — it's pulled in by the MinGW CRT.
> Chasing it is a dead end. Likewise `VirtualQuery`/`VirtualProtect` here belong to
> `_pei386_runtime_relocator`, not to any anti-debug check. Despite the name, the unpacked
> binary contains **no** anti-debugging: the "evasion" is entirely the packer plus the
> dead-code trick in Stage 4.

## Stage 3 — `main`, and the decoy

`main` is at `0x140001490`. Ghidra names it automatically from the symbol table.

The last thing `main` does is build a string and write it to a file:

```c
CreateFileA("flag.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
WriteFile(hFile, buf, 0x1c, NULL, NULL);
```

The string is assembled from four 64-bit immediates via three stores into one stack buffer —
and the stores **overlap**:

```asm
movabs rax, 0x35695F6761323146      ; "F12ag_i5"
movabs rdx, 0x776F68656D6F735F      ; "_somehow"
mov    QWORD PTR [rbp-0x40], rax    ; buffer offset 0
mov    QWORD PTR [rbp-0x38], rdx    ; buffer offset 8
movabs rax, 0x69685F315F776F68      ; "how_1_hi"
movabs rdx, 0x0044585F6E656464      ; "dden_XD\0"
mov    QWORD PTR [rbp-0x33], rax    ; buffer offset 13  <-- overlaps
mov    QWORD PTR [rbp-0x2B], rdx    ; buffer offset 21  <-- overlaps
```

Because the third store lands at offset 13, it truncates `"F12ag_i5_somehow"` after
13 bytes. Reassembling by hand:

| Offsets | Contents |
|---|---|
| 0–12 | `F12ag_i5_some` |
| 13–20 | `how_1_hi` |
| 21–27 | `dden_XD` |

giving exactly the `0x1c` = 28 bytes passed to `WriteFile`:

```
F12ag_i5_somehow_1_hidden_XD
```

Read as leetspeak: *"flag is somehow hidden XD."* This is the author taunting anyone who
solved the challenge by double-clicking it. **It is not the flag.**

This overlap is also why `strings` on the unpacked binary shows disjoint fragments
(`F12ag_i5`, `how_1_hi`, `dden_X`) that can't simply be concatenated — the immediates are
code operands, not a data-section string, and the layout only exists at runtime.

## Stage 4 — The real flag

Earlier in `main`, before any of the above, 39 dword immediates are written to consecutive
stack slots from `[rbp-0x20]` to `[rbp+0x78]`, followed by a loop:

```asm
mov    DWORD PTR [rbp+0x7c], 0x0        ; i = 0
jmp    check
loop:  mov  eax, [rbp+0x7c]
       mov  edx, [rbp+rax*4-0x20]       ; arr[i]
       xor  edx, [rbp+0x78]             ; ^= key
       mov  [rbp+rax*4-0x20], edx       ; arr[i] = ...
       add  DWORD PTR [rbp+0x7c], 0x1
check: cmp  DWORD PTR [rbp+0x7c], 0x25  ; i <= 37
       jle  loop
```

The source was almost certainly:

```c
int arr[38] = { 0x29, 0x25, ... };
int key = 0x60;
int i;
for (i = 0; i <= 37; i++) arr[i] ^= key;
```

GCC laid the three locals out contiguously, which is why the "key" is simply the dword
immediately past the array — `[rbp+0x78]` is `arr[38]`. Recognising that
*array-then-scalar* stack layout is the trick to reading this quickly.

Encoded bytes:

```
29 25 25 25 1b 33 50 53 51 0d 05 3f 34 51 0d 05 13 3f 37
05 3f 08 51 13 3f 14 50 3f 33 15 51 51 51 06 06 05 12 1d
```

XOR each with `0x60`:

```
IEEE{S031me_T1mes_We_h1s_t0_Su111ffer}
```

38 characters, matching the 38 loop iterations, opening `IEEE{` and closing `}`. The
triple `0x25` at the start decoding to `EEE` is a useful sanity check — three identical
encoded bytes must be three identical plaintext characters, which constrains the prefix
before you even know the key.

**And then nothing reads it.** The array is XORed in place and the function moves straight
on to the decoy. The decoded flag exists only in stack memory, for a few microseconds,
and is destroyed when `main` returns. That's the challenge.

### Recovering it in a debugger instead

If you'd rather not do the arithmetic, the flag can be read directly out of memory. In
x64dbg on the **unpacked** binary:

1. Breakpoint at `0x1400015E0` — the `movabs rax, 0x35695F6761323146` immediately after
   `jle` falls through, i.e. the first instruction after the loop terminates.
2. Run. The loop has now completed and the buffer is fully decoded.
3. In the dump pane, follow `rbp-0x20`.

The catch: the array is `int[38]`, not `char[38]`, so each character occupies 4 bytes and
appears in the dump as ASCII interleaved with three null bytes (`49 00 00 00 45 00 00 00 …`).
Read every fourth byte, or set the dump to *Integer → 32-bit signed* and read the column.
This is a good habit to notice early — a "string" that looks null-padded in a dump is
usually a wide type or an int array, not a corrupted buffer.

## Reproducing

```bash
pip install pefile
python3 solve/unpack.py path/to/Evasive.exe
```

Output:

```
[+] FPACK: 33948 bytes, props=5d00001000, unpacked size=127489
[+] wrote Evasive_unpacked.exe (127489 bytes)
[+] key = 0x60
[!] REAL FLAG : IEEE{S031me_T1mes_We_h1s_t0_Su111ffer}
[-] decoy written to flag.txt: F12ag_i5_somehow_1_hidden_XD
```

The script re-derives the flag by parsing the disassembly of `main` rather than hardcoding
the byte array, so it verifies the analysis rather than restating its conclusion.

For the Ghidra route, [`ghidra/decode_flag.py`](ghidra/decode_flag.py) does the same thing
inside Ghidra's script manager against the unpacked binary.

## Ghidra workflow notes

Reusable technique, not specific to this binary:

- **Import the unpacked payload, not the stub.** Reversing a packer's `GetProcAddress`
  resolution is a detour unless the packer itself is the puzzle.
- **Retype stack arrays immediately.** By default Ghidra renders 39 consecutive dword
  stores as 39 unrelated locals, which is unreadable. Right-click the first →
  *Retype Variable* → `int[38]` collapses them into an array and turns the loop into an
  obvious `arr[i] ^= key`.
- **`movabs` immediates are strings.** An 8-byte immediate whose bytes are all in
  `0x20–0x7E` is an inline string constant. Byte-swap it (x86 is little-endian) to read it.
  Ghidra will not do this for you because the bytes live in the instruction stream, not in
  a data section, so `Defined Strings` never shows them.
- **Check whether a computed value is ever used.** Ghidra's decompiler happily shows dead
  code without flagging it. Here, the entire flag computation has no consumer. Use
  *Highlight Def-Use* on the array variable, or simply notice no read follows the loop.
- **Trust the symbol table when it's there.** 19 sections with `/NN` names indicates MinGW
  with DWARF debug info retained — check for symbols before assuming a stripped binary.

## Lessons

- **Dynamic-only analysis fails here by design.** Running the program yields a taunt. The
  author's whole thesis is that "run it and see what it prints" is not reverse engineering.
- **Static-only analysis is slower than necessary.** Hand-decoding is fine for 38 bytes;
  for 3,800 you'd want the breakpoint. Neither approach dominates — the skill is picking.
- **Recognise container formats by header, not by extension.** `5D 00 00 10 00` saved the
  entire challenge. Header triage is a large fraction of practical unpacking.
- **The obvious comparison function is bait.** `strncmp` sits in the import table looking
  like the win condition and is never called on user input.

## References

- [LZMA-alone / `.lzma` file format](https://sourceforge.net/projects/sevenzip/files/LZMA%20SDK/) — header layout in `lzma.txt`
- [FLARE-VM](https://github.com/mandiant/flare-vm) — the Windows RE toolset used here
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) — entropy and packer triage
- [x64dbg](https://x64dbg.com/)

## License

Writeup text and scripts: MIT (see [LICENSE](LICENSE)). The challenge binary is the
property of its original author on crackmes.one and is not included in this repository.
