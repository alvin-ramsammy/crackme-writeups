# main.out — "Hello in my first programm" (crackmes.one)

| | |
|---|---|
| **Date** | 2026-05-30 |
| **Platform** | Linux x86-64 ELF (PIE, dynamically linked, **not stripped**) |
| **Tools** | `file`, IDA (disassembly + patching) |
| **SHA-256** | `ba7c61f81dbeb140cbcbfddbcf0eee2f0ab56118242c868ad8ee559333c116ff` |
| **Difficulty** | Very easy |
| **Objective** | Find a check whose condition can never be met, and force it to pass |
| **Solution** | Patch `jz` → `jnz` at `0x117C` (1 byte: `74` → `75`) |

## TL;DR

`main` moves the constant `0Ah` (10) into a local variable, then immediately checks whether that variable equals `0Ah`. The check always passes, and passing it sends execution to the `Error!` path. The `Success!` block sits directly after the jump and is never reached. Flipping `jz` to `jnz` inverts the branch, so execution falls through into `Success!`.

## 1. Recon

I start by running `file` on the binary to get basic information:

```
$ file main.out
main.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

**Not stripped** means the function names are preserved, so `main` will show up by name in the disassembler.

Next, I make the binary executable and run it to see how it behaves:

```
$ chmod +x main.out
$ ./main.out
Hello in my first programm for crackme.one
Error!
```

It prints `Error!` immediately and never asks for input. So the check has to be on something hardcoded inside the binary.

## 2. Finding the check (IDA)

Opening the binary in IDA and going to `main`:

```asm
; int __fastcall main(int argc, const char **argv, const char **envp)
var_8 = dword ptr -8
var_4 = dword ptr -4

endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     [rbp+var_4], 0
lea     rdi, format          ; "Hello in my first programm for crackme."...
mov     al, 0
call    _printf
mov     [rbp+var_8], 0Ah     ; var_8 = 10          <-- hardcoded
cmp     [rbp+var_8], 0Ah     ; var_8 == 10 ?
jz      short loc_118E       ; always taken
```

This is the check. The program writes `0Ah` into `var_8` and then compares `var_8` to `0Ah` on the very next instruction. The values are always equal, so the zero flag (ZF) is always set and `jz` always jumps to `loc_118E`.

### The two paths

**Fall-through (only reached if the jump is not taken):** the success block, located right after the `jz`.

```asm
lea     rdi, aSuccess        ; "Success!\n"
mov     al, 0
call    _printf
jmp     short loc_11A4       ; -> return
```

**Jump target `loc_118E`:** the error path.

```asm
loc_118E:
cmp     [rbp+var_8], 0Ah     ; same comparison again
jnz     short loc_11A2       ; not taken, because var_8 is still 10
lea     rdi, aError          ; "Error!"
mov     al, 0
call    _printf
loc_11A2:
jmp     short loc_11A4       ; -> return
```

`loc_118E` repeats the same comparison. Since `var_8` is still 10, its `jnz` is **not** taken. Execution falls through to the `Error!` call, then continues through `loc_11A2` to the function's epilogue at `loc_11A4`.

### Reconstructed logic

```c
int x = 10;
if (x != 10)
    printf("Success!\n");   // unreachable
else if (x == 10)
    printf("Error!");
return 0;
```

```
            printf(hello)
                 │
              x = 10
                 │
          ┌── x == 10 ? ──┐
       no │               │ yes   (always: jz taken)
          ▼               ▼
   printf("Success!")   loc_118E: x == 10 ? ──► printf("Error!")
          │                                         │
          └───────────────► return ◄────────────────┘
```

The success branch is dead code, so no input could ever reach it. The only way in is to patch the binary.

## 3. Patching in IDA

The easiest fix is to invert the branch: change `jz` (jump if zero) to `jnz` (jump if not zero). The comparison still sets ZF, but the jump now fires only when the values *differ*. That never happens, so execution falls through into the `Success!` block.

1. Click the line `jz short loc_118E`.
2. **Edit → Patch program → Assemble**.
3. Change the instruction to `jnz short loc_118E` and click **OK**.
4. **Edit → Patch program → Apply patches to input file**.
5. Tick **Create backup** (recommended) and click **OK**.

At the byte level, the change is one opcode byte:

```
0x117C:  74 10   jz  loc_118E
   ->    75 10   jnz loc_118E
```

## 4. Result

```
$ ./main.out
Hello in my first programm for crackme.one
Success!
```

After the patch, the area around the check looks like this:

```asm
cmp     [rbp+var_8], 0Ah
jnz     short loc_118E       ; never taken now
lea     rdi, aSuccess        ; "Success!\n"
mov     al, 0
call    _printf
jmp     short loc_11A4
```

`var_8` is still 10, so `jnz` doesn't jump. The program runs straight into the `Success!` print and then jumps to the return.

## 5. Takeaways

- **A check against a value the program just set is a constant.** `mov [x], 0Ah` followed by `cmp [x], 0Ah` is decided at compile time, so the branch it controls is dead code.
- **Inverting a conditional jump is the quickest patch.** `jz` ↔ `jnz` (`74` ↔ `75`) flips the outcome with a 1-byte change and doesn't disturb anything else in the function.
- **Labels aren't functions.** `loc_118E` and `loc_11A2` are jump targets inside `main`, not separate functions. Reading the code as one function makes the control flow easier to follow.
- **Keep the backup.** Applying patches in IDA overwrites the input file, and the original is handy for diffing or for trying other patches.
