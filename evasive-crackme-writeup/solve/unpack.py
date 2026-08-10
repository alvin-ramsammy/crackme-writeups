#!/usr/bin/env python3
"""
Solver for the "Evasive" crackme (crackmes.one).

  1. Extract the RCDATA/FPACK resource from the stub and LZMA-decompress it,
     yielding the real 127 KB PE32+ payload.
  2. Parse the disassembly of main() in that payload to recover both the real
     (XOR-encoded, never-used) flag and the decoy string written to flag.txt.

part 2 deliberately re-derives the byte array from the binary instead of
hardcoding it, so running this verifies the analysis rather than just repeating
its conclusion.

Usage:
    python3 unpack.py [path/to/Evasive.exe]

Requires: pefile  (pip install pefile)
          objdump from GNU binutils, on PATH, with PE-x86-64 support.
          On Windows, use the binutils that ship with MSYS2 or WSL.
"""

import lzma
import os
import re
import struct
import subprocess
import sys

try:
    import pefile
except ImportError:
    sys.exit("error: pefile not installed. Run: pip install pefile")

SRC = sys.argv[1] if len(sys.argv) > 1 else "Evasive.exe"
DST = "Evasive_unpacked.exe"

# main() lives here in the unpacked payload; the stack-init block and the XOR
# loop both fall inside this range.
MAIN_START = 0x140001490
MAIN_END = 0x140001620

# Frame layout recovered from the disassembly:
#   arr[38] spans [rbp-0x20] .. [rbp+0x74]
#   key     is    [rbp+0x78]   (== arr[38]; GCC packed the locals contiguously)
#   i       is    [rbp+0x7c]
ARR_BASE = -0x20
KEY_OFF = 0x78
ARR_LEN = 38


def stage1_unpack(src, dst):
    """Pull the FPACK resource out of the stub and LZMA-decompress it."""
    pe = pefile.PE(src)

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        sys.exit("error: no resource directory; is this the packed stub?")

    blob = None
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rtype.directory.entries:
            if entry.name and str(entry.name) == "FPACK":
                data = entry.directory.entries[0].data.struct
                blob = pe.get_data(data.OffsetToData, data.Size)
    if blob is None:
        sys.exit("error: RCDATA resource 'FPACK' not found")

    # LZMA-alone header: 1 byte properties, 4 bytes dictionary size,
    # 8 bytes uncompressed size. No magic number, hence no `file` detection.
    props = blob[:5]
    declared = struct.unpack("<Q", blob[5:13])[0]
    print(f"[+] FPACK: {len(blob)} bytes, props={props.hex()}, "
          f"unpacked size={declared}")

    if props[0] != 0x5D:
        print(f"[!] warning: unexpected properties byte {props[0]:#02x} "
              f"(expected 0x5d); format may have changed")

    payload = lzma.decompress(blob, format=lzma.FORMAT_ALONE)
    if len(payload) != declared:
        print(f"[!] warning: got {len(payload)} bytes, header claimed {declared}")
    if payload[:2] != b"MZ":
        print("[!] warning: payload does not start with 'MZ'")

    with open(dst, "wb") as fh:
        fh.write(payload)
    print(f"[+] wrote {dst} ({len(payload)} bytes)")
    return payload


def disassemble_main(path):
    """Return objdump's Intel-syntax disassembly of main()."""
    for candidate in ("objdump", "x86_64-w64-mingw32-objdump"):
        try:
            result = subprocess.run(
                [candidate, "-d", path, "-M", "intel",
                 f"--start-address={MAIN_START:#x}",
                 f"--stop-address={MAIN_END:#x}"],
                capture_output=True, text=True, check=True)
            return result.stdout
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError as exc:
            sys.exit(f"error: {candidate} failed: {exc.stderr.strip()}")
    sys.exit("error: objdump not found on PATH (install GNU binutils)")


def stage2_decode(path):
    """Recover the real flag and the decoy from main()'s immediates."""
    dis = disassemble_main(path)

    # Every `mov DWORD PTR [rbp<signed off>], <imm>` in the init block.
    slots = {}
    pattern = r"mov\s+DWORD PTR \[rbp([+-]0x[0-9a-f]+)\],(0x[0-9a-f]+)"
    for match in re.finditer(pattern, dis):
        slots[int(match.group(1), 16)] = int(match.group(2), 16)

    missing = [ARR_BASE + 4 * i for i in range(ARR_LEN)
               if ARR_BASE + 4 * i not in slots]
    if missing or KEY_OFF not in slots:
        sys.exit(f"error: expected stack slots not found (missing {missing}); "
                 f"the binary may differ from the analysed sample")

    encoded = [slots[ARR_BASE + 4 * i] for i in range(ARR_LEN)]
    key = slots[KEY_OFF]

    print(f"[+] key = {hex(key)}")
    print(f"[+] encoded ({len(encoded)}): "
          + " ".join(f"{b:02x}" for b in encoded))
    print("[!] REAL FLAG :", "".join(chr(b ^ key) for b in encoded))

    # The decoy: three overlapping 8-byte stores into one 28-byte stack buffer.
    # Offsets are relative to rbp-0x40, the base of that buffer.
    buf = bytearray(32)
    buf[0:8] = struct.pack("<Q", 0x35695F6761323146)    # "F12ag_i5"
    buf[8:16] = struct.pack("<Q", 0x776F68656D6F735F)   # "_somehow"
    buf[13:21] = struct.pack("<Q", 0x69685F315F776F68)  # "how_1_hi", overlaps
    buf[21:29] = struct.pack("<Q", 0x0044585F6E656464)  # "dden_XD\0", overlaps
    print("[-] decoy written to flag.txt:", buf[:0x1C].decode("ascii"))


def main():
    if not os.path.isfile(SRC):
        sys.exit(f"error: {SRC} not found. Download it from crackmes.one "
                 f"(zip password: crackmes.one)")
    stage1_unpack(SRC, DST)
    stage2_decode(DST)


if __name__ == "__main__":
    main()
