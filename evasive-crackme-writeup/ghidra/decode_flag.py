# Recovers the hidden flag from the "Evasive" crackme inside Ghidra.
#
# Run against the UNPACKED payload (Evasive_unpacked.exe), not the stub.
#
# Usage: Window -> Script Manager -> Create New Script (Python) -> paste ->
#        select main() in the listing (or just run; it looks main up by name).
#
# It walks main(), collects every `MOV [RBP+x], imm32`, and XORs the 38-element
# array against the key that GCC placed in the slot immediately after it.
#
# @category CrackMe.Evasive
# @keybinding
# @menupath
# @toolbar

ARR_LEN = 38
KEY_INDEX = 38  # key sits at arr[38]; locals were laid out contiguously


def collect_immediates(func):
    """Every MOV of an immediate into an RBP-relative dword, in program order."""
    values = []
    body = func.getBody()
    inst = getFirstInstruction(func)
    while inst is not None and body.contains(inst.getAddress()):
        if inst.getMnemonicString() == "MOV":
            scalar = inst.getScalar(1)
            dest = inst.getDefaultOperandRepresentation(0).upper()
            if scalar is not None and "RBP" in dest:
                values.append(scalar.getUnsignedValue())
        inst = inst.getNext()
    return values


def run():
    funcs = getGlobalFunctions("main")
    if not funcs:
        print("main() not found. Is this the unpacked payload, and did "
              "auto-analysis finish?")
        return
    func = funcs[0]
    print("main() at %s" % func.getEntryPoint())

    values = collect_immediates(func)
    if len(values) < KEY_INDEX + 1:
        print("Only found %d RBP immediates; expected at least %d. "
              "Wrong binary?" % (len(values), KEY_INDEX + 1))
        return

    key = values[KEY_INDEX]
    encoded = values[:ARR_LEN]

    # Trailing values (the loop counter's `i = 0`) are ignored by the slice.
    print("key   = 0x%02x" % key)
    print("bytes = %s" % " ".join("%02x" % v for v in encoded))
    print("FLAG  = %s" % "".join(chr(v ^ key) for v in encoded))


run()
