#!/usr/bin/env python3
"""Annotated ARM64 disassembler for the 目標 App Mach-O.

python3 adis.py <binary> <VA> <N>

Annotations: ObjC method IMP names, dyld stub symbols, __objc_selrefs selectors,
__cstring string literals, and section+offset for plain data.
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

sys.path.insert(0, ".")
from objcdump import MachO, sec_find  # noqa: E402
from objcdump2 import dump  # noqa: E402


def build_imp_map(m):
    imp2name = {}
    for cname, cls, rows in dump(m, None):
        short = cname.split("targetapp")[-1] if "targetapp" in cname else cname
        for nm, tp, imp in rows:
            if imp and nm:
                imp2name.setdefault(imp, "-[%s %s]" % (short, nm))
    return imp2name


def main():
    binary, va_s, n_s = sys.argv[1], sys.argv[2], int(sys.argv[3])
    va = int(va_s, 0)
    m = MachO(binary)
    imp2name = build_imp_map(m)
    stubs = m.stubs()
    selrefs = m.selrefs()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    code = m.b[m.foff(va): m.foff(va) + n_s * 4 + 64]
    insns = list(md.disasm(code, va))

    adrp = {}

    def annot(tgt):
        if tgt in selrefs:
            return "SEL(%s)" % selrefs[tgt]
        if tgt in stubs:
            return "stub(%s)" % stubs[tgt]
        s = sec_find(m, tgt)
        if not s:
            return hex(tgt)
        seg, sn, addr, size, soff = s
        off = soff + (tgt - addr)
        if sn in ("__cstring", "__objc_methname", "__objc_classname", "__objc_methtype"):
            txt = m.cstr(tgt)
            if txt is None:
                return hex(tgt)
            if txt.isprintable():
                return '"%s"' % txt[:80]
            return '"%s"' % txt.encode("unicode_escape").decode()[:80]
        raw = m.b[off:off + 8]
        if len(raw) == 8:
            p = m.cfptr(struct.unpack("<Q", raw)[0])
            if 0x100000000 <= p < 0x100E68000:
                ps = sec_find(m, p)
                if ps and ps[1] in ("__cstring", "__objc_methname", "__objc_classname"):
                    t2 = m.cstr(p)
                    if t2 and t2.isprintable():
                        return "%s+0x%x -> \"%s\"" % (sn, tgt - addr, t2[:60])
        return "%s+0x%x" % (sn, tgt - addr)

    for ins in insns[:n_s]:
        note = ""
        ops = ins.operands
        if ins.mnemonic == "adrp" and len(ops) == 2:
            adrp[ops[0].reg] = ops[1].imm
            note = annot(ops[1].imm)
        elif ins.mnemonic in ("bl", "b") and ops and ops[0].type == ARM64_OP_IMM:
            t = ops[0].imm
            if t in imp2name:
                note = "-> %s" % imp2name[t]
            elif t in stubs:
                note = "-> %s" % stubs[t]
            else:
                note = "-> sub_%x" % t
        elif ins.mnemonic in ("add", "sub") and len(ops) == 3 and ops[1].type == ARM64_OP_REG \
                and ops[1].reg in adrp and ops[2].type == ARM64_OP_IMM:
            note = annot(adrp[ops[1].reg] + (ops[2].imm if ins.mnemonic == "add" else -ops[2].imm))
        elif ops and ops[-1].type == ARM64_OP_MEM and ops[-1].mem.base in adrp:
            note = annot(adrp[ops[-1].mem.base] + ops[-1].mem.disp)
        print("%-12s %-42s %s" % (hex(ins.address), "%s %s" % (ins.mnemonic, ins.op_str), note))


if __name__ == "__main__":
    main()
