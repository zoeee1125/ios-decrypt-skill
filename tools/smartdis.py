#!/usr/bin/env python3
"""ARM64 Mach-O smart disassembler for the 目標 App app.

Annotates:
  * `bl <stub>`      -> imported symbol name (objc_msgSend, swift_once, ...)
  * `adrp+ldr`       -> __objc_selrefs selector name
  * `adrp+add`       -> string literal in __cstring / class name
  * `adrp+ldr/str`   -> __DATA global address
Usage:  python3 smartdis.py <binary> <VA> <num_instrs>
"""
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BASE = 0x100000000


class MachO:
    def __init__(self, path):
        self.b = open(path, "rb").read()
        magic, cput, csub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", self.b, 0)
        assert magic == 0xFEEDFACF, hex(magic)
        self.ncmds = ncmds
        self.sections = {}
        self.sect_list = []
        self.segs = {}
        symtab = dysymtab = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<2I", self.b, off)
            if cmd == 0x2:
                symtab = struct.unpack_from("<4I", self.b, off + 8)
            elif cmd == 0xB:
                dysymtab = struct.unpack_from("<18I", self.b, off + 8)
            elif cmd == 0x19:
                seg = self.b[off + 8:off + 24].split(b"\0")[0].decode()
                vmaddr, vmsize, fo, fs = struct.unpack_from("<4Q", self.b, off + 24)
                self.segs[seg] = (vmaddr, vmsize, fo, fs)
                ns = struct.unpack_from("<I", self.b, off + 64)[0]
                so = off + 72
                for _ in range(ns):
                    sn = self.b[so:so + 16].split(b"\0")[0].decode()
                    addr, siz = struct.unpack_from("<2Q", self.b, so + 32)
                    soff, align, reloff, nreloc, sflags, r1, r2, r3 = struct.unpack_from("<8I", self.b, so + 48)
                    self.sect_list.append((seg, sn, addr, siz, soff, r1))
                    self.sections.setdefault((seg, sn), []).append((addr, siz, soff, r1))
                    so += 80
            off += size
        self.symtab = symtab
        self.dysymtab = dysymtab
        self._stubs = None
        self._selrefs = None

    # ---------- address helpers ----------
    def foff(self, va):
        return va - BASE

    def cstr(self, va):
        o = self.foff(va)
        if o < 0 or o >= len(self.b):
            return None
        e = self.b.index(b"\0", o)
        return self.b[o:e].decode("utf-8", "replace")

    def rawq(self, va):
        return struct.unpack_from("<Q", self.b, self.foff(va))[0]

    @staticmethod
    def cfptr(v):
        if (v >> 62) & 1:
            return v & 0xFFFFFFFFFF
        if (v >> 63) & 1:
            return v & 0xFFFFFFFF
        return (v & 0x7FFFFFFFFFF) | (((v >> 43) & 0xFF) << 56)

    def symname(self, idx):
        symoff, nsyms, stroff, strsize = self.symtab
        if idx >= nsyms:
            return None
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", self.b, symoff + 16 * idx)
        e = self.b.index(b"\0", stroff + n_strx)
        return self.b[stroff + n_strx:e].decode("utf-8", "replace")

    def stubs(self):
        if self._stubs is not None:
            return self._stubs
        res = {}
        indirectsymoff, nindirectsyms = self.dysymtab[12], self.dysymtab[13]
        indirects = struct.unpack_from("<%dI" % nindirectsyms, self.b, indirectsymoff)
        for seg, sn, addr, siz, soff, r1 in self.sect_list:
            if sn in ("__stubs", "__auth_stubs"):
                entry = 16 if sn == "__auth_stubs" else 12
                for i in range(siz // entry):
                    idx = indirects[r1 + i] if r1 + i < len(indirects) else 0
                    nm = self.symname(idx)
                    if nm:
                        res[addr + i * entry] = nm
        self._stubs = res
        return res

    def selrefs(self):
        if self._selrefs is not None:
            return self._selrefs
        res = {}
        for (seg, sn), entries in self.sections.items():
            if sn != "__objc_selrefs":
                continue
            for addr, siz, soff, r1 in entries:
                for i in range(siz // 8):
                    va = addr + i * 8
                    tgt = self.cfptr(self.rawq(va))
                    nm = self.cstr(tgt)
                    if nm:
                        res[va] = nm
        self._selrefs = res
        return res


def disasm(m, va, n):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    stubs = m.stubs()
    selrefs = m.selrefs()
    code = m.b[m.foff(va): m.foff(va) + n * 4]
    lines = list(md.disasm(code, va))
    # first pass: collect adrp page values
    for i in range(len(lines)):
        ins = lines[i]
        note = ""
        if ins.mnemonic == "add" and i > 0 and lines[i - 1].mnemonic == "adrp":
            pass
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
            tgt = int(ins.op_str[1:], 16)
            if tgt in stubs:
                note = "; " + stubs[tgt]
        if ins.mnemonic == "adrp":
            page = int(ins.op_str.split("#")[1], 16)
            # look ahead: add/ldr with same reg
            reg = ins.op_str.split(",")[0].strip()
            for j in range(i + 1, min(i + 4, len(lines))):
                nxt = lines[j]
                if nxt.mnemonic in ("add", "ldr", "ldrb", "str") and nxt.op_str.startswith(reg + ","):
                    off = nxt.op_str.split("#")[-1].rstrip("]")
                    try:
                        delta = int(off, 16)
                    except ValueError:
                        continue
                    tgt = page + delta
                    if tgt in stubs:
                        note += "; %s" % stubs[tgt]
                    if tgt in selrefs:
                        note += "; sel:%s" % selrefs[tgt]
                    s = None
                    try:
                        if 0x1009a0000 <= tgt < 0x100b40000:
                            s = m.cstr(tgt)
                    except Exception:
                        s = None
                    if s:
                        note += "; str:%r" % s[:90]
                    break
        print("0x%x:\t%-8s %-34s %s" % (ins.address, ins.mnemonic, ins.op_str, note))


if __name__ == "__main__":
    mo = MachO(sys.argv[1])
    disasm(mo, int(sys.argv[2], 16), int(sys.argv[3]) if len(sys.argv) > 3 else 40)
