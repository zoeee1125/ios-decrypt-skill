#!/usr/bin/env python3
"""Dump ObjC classes / methods from the 目標 App Mach-O (arm64, chained fixups).

python3 objcdump.py <binary> [class-name-filter]
"""
import struct
import sys

sys.path.insert(0, ".")
from smartdis import MachO  # noqa: E402


def sec(m, seg, name):
    for s in m.sect_list:
        if s[0] == seg and s[1] == name:
            return s
    return None


def sec_find(m, va):
    for seg, sn, addr, size, soff, r1 in m.sect_list:
        if addr <= va < addr + size:
            return seg, sn, addr, size, soff
    return None


def read_at(m, va, n):
    s = sec_find(m, va)
    if not s:
        return None
    seg, sn, addr, size, soff = s
    o = soff + (va - addr)
    return m.b[o:o + n]


def ptr(m, va):
    raw = read_at(m, va, 8)
    if raw is None:
        return None
    return m.cfptr(struct.unpack("<Q", raw)[0])


def cstr_at(m, va):
    s = sec_find(m, va)
    if not s or s[1] not in ("__objc_methname", "__objc_classname", "__cstring", "__objc_methtype"):
        try:
            return m.cstr(va)
        except Exception:
            return None
    return m.cstr(va)


def main():
    m = MachO(sys.argv[1])
    flt = sys.argv[2] if len(sys.argv) > 2 else None
    cl = sec(m, "__DATA", "__objc_classlist") or sec(m, "__DATA_CONST", "__objc_classlist")
    if not cl:
        print("no classlist")
        return
    seg, sn, addr, size, soff, r1 = cl
    n = size // 8
    print("objc classes: %d" % n)
    for i in range(n):
        cls = ptr(m, addr + i * 8)
        if not cls:
            continue
        data = ptr(m, cls + 32)
        if not data:
            continue
        name = cstr_at(m, ptr(m, data + 24) or 0)
        if not name:
            continue
        if flt and flt.lower() not in name.lower():
            continue
        methods = ptr(m, data + 32)
        print("\n=== %s  (class=%s data=%s methods=%s)" % (name, hex(cls), hex(data), hex(methods or 0)))
        if not methods:
            continue
        raw = read_at(m, methods, 8)
        if not raw:
            continue
        entsize_flags = struct.unpack("<I", raw[:4])[0]
        count = struct.unpack("<I", raw[4:8])[0]
        esize = entsize_flags & 0xFFFFFF
        print("    methods: %d (entsize=%d)" % (count, esize))
        for j in range(count):
            e = methods + 8 + j * esize
            nm = ptr(m, e)
            tp = ptr(m, e + 8)
            imp = ptr(m, e + 16)
            sname = cstr_at(m, nm) if nm else None
            stype = cstr_at(m, tp) if tp else None
            print("      %-58s %-30s imp=%s" % (sname, stype, hex(imp) if imp else None))


if __name__ == "__main__":
    main()
