#!/usr/bin/env python3
"""Scan __text of the 目標 App Mach-O for ADRP+LDR references to given data VAs.

Usage:
    python3 scan_refs.py <binary> <va> [<va> ...]
"""
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

sys.path.insert(0, ".")
from smartdis import MachO  # noqa: E402


def scan(m, targets):
    text = [s for s in m.sect_list if s[1] == "__text"][0]
    seg, sn, addr, size, soff, r1 = text
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    adrp = {}
    hits = {t: [] for t in targets}
    code = m.b[soff:soff + size]
    for ins in md.disasm(code, addr):
        ops = ins.op_str
        if ins.mnemonic == "adrp":
            reg = ops.split(",")[0].strip()
            try:
                adrp[reg] = int(ops.split("#")[1], 16)
            except Exception:
                adrp.pop(reg, None)
            continue
        if ins.mnemonic in ("ldr", "ldrb", "ldrh", "str", "add") and "[" in ops:
            head = ops.split(",")[0].strip()
            body = ops[ops.index("["):]
            base = body[1:].split(",")[0].strip().rstrip("]")
            if base in adrp and "#" in body:
                try:
                    delta = int(body.split("#")[-1].rstrip("]").strip(), 16)
                except Exception:
                    continue
                tgt = adrp[base] + delta
                if tgt in hits:
                    hits[tgt].append((ins.address, ins.mnemonic))
        # keep adrp values for a few instructions only
    return hits


if __name__ == "__main__":
    mo = MachO(sys.argv[1])
    targets = [int(a, 16) for a in sys.argv[2:]]
    hits = scan(mo, targets)
    for t in targets:
        print("=== target 0x%x : %d refs" % (t, len(hits[t])))
        for a, mn in hits[t][:40]:
            print("    0x%x  (%s)" % (a, mn))
