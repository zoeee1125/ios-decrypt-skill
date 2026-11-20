#!/usr/bin/env python3
"""Dump ObjC class/method lists from 目標 App Mach-O (relative/small method lists).

python3 objcdump2.py <binary> [name-filter]
"""
import struct
import sys

sys.path.insert(0, ".")
from objcdump import MachO, sec, sec_find, read_at, ptr as up, cstr_at  # noqa: E402


def name_of(m, va):
    """Resolve a method-name field: may point into __objc_selrefs (SEL slot)."""
    if not va:
        return None
    s = sec_find(m, va)
    if s and s[1] == "__objc_selrefs":
        sel = up(m, va)
        if sel:
            t = m.cstr(sel)
            if t:
                return t
    return m.cstr(va)


def dump(m, flt=None, want_imp=False):
    cl = sec(m, "__DATA", "__objc_classlist") or sec(m, "__DATA_CONST", "__objc_classlist")
    seg, sn, addr, size, soff, r1 = cl
    out = []
    for i in range(size // 8):
        cls = up(m, addr + i * 8)
        if not cls:
            continue
        bits = up(m, cls + 32)
        if not bits:
            continue
        data = bits & 0x00007ffffffffff8
        cname = m.cstr(up(m, data + 24) or 0)
        if not cname:
            continue
        if flt and flt.lower() not in cname.lower():
            continue
        methods = up(m, data + 32)
        rows = []
        if methods:
            raw = read_at(m, methods, 8)
            ef, count = struct.unpack("<II", raw)
            relative = bool(ef & 0x80000000)
            esize = (ef & 0xFFFF) if relative else (ef & 0xFFFFFF)
            for j in range(count):
                e = methods + 8 + j * esize
                ch = read_at(m, e, 12 if relative else 24)
                if not ch or len(ch) < (12 if relative else 24):
                    break
                if relative:
                    a, b, c = struct.unpack("<iii", ch)
                    nm, tp, imp = e + a, e + 4 + b, e + 8 + c
                else:
                    nm, tp, imp = struct.unpack("<QQQ", ch)
                rows.append((name_of(m, nm), m.cstr(tp) if tp else None, imp))
        out.append((cname, cls, rows))
    return out


def main():
    m = MachO(sys.argv[1])
    flt = sys.argv[2] if len(sys.argv) > 2 else None
    for cname, cls, rows in dump(m, flt):
        print("\n=== %s  cls=%s  methods=%d" % (cname, hex(cls), len(rows)))
        for nm, tp, imp in rows:
            print("    %-56s %-32s %s" % (nm, tp, hex(imp) if imp else None))


if __name__ == "__main__":
    main()
