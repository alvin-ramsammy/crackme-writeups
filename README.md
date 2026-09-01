# crackme-writeups

Reverse engineering writeups I produce while learning the craft. Each one documents a
crackme or CTF binary from first look to solved, including my wrong turns.

I'm a cybersecurity undergraduate (B.S. Cybersecurity, class of 2027) working toward
vulnerability research and reverse engineering. I have a systems background, having studied x86 assembly,
C, embedded work and I'm building applied RE on top of it. This repository is the
practice log for that.

## Where I currently am

**Comfortable with:** reading x86-64 assembly; navigating Ghidra and interpreting decompiler
output; recognising common packers and container formats from headers and entropy;
identifying and reversing simple encodings (XOR, arithmetic, substitution); using x64dbg to
breakpoint and inspect memory; PE structure: sections, imports, resources.

**Actively learning:** obfuscation and anti-analysis (control-flow flattening, VM-based
protections, anti-debug); manual unpacking of custom packers rather than known formats;
Ghidra scripting beyond simple listing walks; heap and allocator internals; .NET and
scripting-language targets.



## Writeups

| Challenge | Source | Platform | Key techniques | Writeup |
|---|---|---|---|---|
| **Evasive** | crackmes.one | Windows x64 (PE32+) | LZMA-alone resource packer, runtime API resolution, XOR-encoded string, dead-code flag, overlapping stack stores | [→](evasive/) |

More on the way -> see [Roadmap](#roadmap).

## How these are organised

Every challenge gets its own directory:

```
<challenge-name>/
├── README.md      # the writeup
├── HASHES.md      # sample hashes, so readers can verify they have the same binary
├── solve/         # scripts that reproduce the solution end to end
└── ghidra/        # any Ghidra scripts written for the challenge
```



## Environment



| | |
|---|---|
| Windows targets | Windows VM running [FLARE-VM](https://github.com/mandiant/flare-vm), networking off, snapshot before each sample |
| Linux targets | Linux VM, Ghidra + `gdb`/`pwndbg` |
| Static analysis | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) |
| Dynamic analysis | [x64dbg](https://x64dbg.com/), `gdb` |
| Triage | [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), PE-bear, Resource Hacker, HxD |
| Scripting | Python (`pefile`, `capstone`), Ghidra's script manager |


