#!/usr/bin/env python3
"""Fast xref scanner for the 目標 App Mach-O (arm64).

python3 xref.py <binary> <target-VA> [target-VA ...]

Single program-order pass: tracks adrp <rd>, page in a register map, then
matches ADRP+ADD (string/ptr literals) and ADRP+LDR (selrefs/globals),
plus B/BL sites.  Also reports the enclosing function start (nearest
prologue) so results can be disassembled directly.
"""
import struct
import sys

sys.path.insert(0, ".")
from objcdump import MachO  # noqa: E402


def main():
    m = MachO(sys.argv[1])
    targets = set(int(x, 0) for x in sys.argv[2:])

    base = size = soff = None
    for seg, sn, addr, sz, s, r1 in m.sect_list:
        if sn == "__text":
            base, size, soff = addr, sz, s
    print("__text %s size=0x%x" % (hex(base), size))

    data = m.b[soff:soff + size]
    n = size // 4
    words = struct.unpack_from("<%dI" % n, data)

    reg = {}          # reg -> page VA (only valid right after adrp)
    hits = {t: [] for t in targets}

    for i in range(n):
        w = words[i]
        va = base + i * 4
        if (w & 0x9F000000) == 0x90000000:      # ADRP
            rd = w & 0x1F
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            reg[rd] = (va & ~0xFFF) + (imm << 12)
            continue
        if (w & 0x9F000000) == 0x90000000:
            pass
        # ADD (immediate) 64/32-bit
        if (w & 0xFF800000) == 0x91000000 or (w & 0xFF800000) == 0x11000000:
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            if rn in reg:
                tgt = reg[rn] + (imm12 << (12 if sh else 0))
                if tgt in targets:
                    hits[tgt].append((va, "ADRP+ADD"))
            reg.pop(rn, None)
            continue
        # LDR (immediate, unsigned offset) 64-bit
        if (w & 0xFFC00000) == 0xF9400000:
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in reg:
                tgt = reg[rn] + imm12 * 8
                if tgt in targets:
                    hits[tgt].append((va, "ADRP+LDR"))
            reg.pop(rn, None)
            continue
        # LDR (immediate, unsigned offset) 32-bit
        if (w & 0xFFC00000) == 0xB9400000:
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in reg:
                tgt = reg[rn] + imm12 * 4
                if tgt in targets:
                    hits[tgt].append((va, "ADRP+LDR32"))
            reg.pop(rn, None)
            continue
        # B / BL
        if (w & 0xFC000000) == 0x94000000 or (w & 0xFC000000) == 0x14000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            tgt = va + imm * 4
            if tgt in targets:
                hits[tgt].append((va, "BL" if (w >> 26) & 0x3F == 0x25 else "B"))
            reg.clear()
            continue
        # any other write to Rn invalidates adrp tracking for that reg
        rd = w & 0x1F
        if rd != 31:
            reg.pop(rd, None)

    for t in sys.argv[2:]:
        tv = int(t, 0)
        print("\n=== xrefs to %s ===" % hex(tv))
        for site, kind in sorted(hits.get(tv, [])):
            print("  %s  %s" % (hex(site), kind))


if __name__ == "__main__":
    main()
