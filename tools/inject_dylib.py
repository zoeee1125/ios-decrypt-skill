#!/usr/bin/env python3
"""
Mach-O dylib injector for arm64 binaries.
Injects an LC_LOAD_DYLIB load command into the target Mach-O binary,
then repacks the IPA with the dylib inside the app bundle Frameworks directory.

Usage:
    python3 inject_dylib.py <mach_o_binary> <dylib_path> <output_binary>
    python3 inject_dylib.py --repack-ipa <injected_binary> <app_dir> <dylib_path> <output_ipa>
"""

import os
import sys
import struct
import shutil
import zipfile
import tempfile

# Mach-O constants
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe

LC_LOAD_DYLIB = 0x0c

def is_macho_64(data):
    if len(data) < 32:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    return magic == MH_MAGIC_64 or magic == MH_CIGAM_64

def parse_macho_header(data):
    magic = struct.unpack_from("<I", data, 0)[0]
    cputype = struct.unpack_from("<I", data, 4)[0]
    cpusubtype = struct.unpack_from("<I", data, 8)[0]
    filetype = struct.unpack_from("<I", data, 12)[0]
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    flags = struct.unpack_from("<I", data, 24)[0]
    reserved = struct.unpack_from("<I", data, 28)[0]
    return {
        'magic': magic, 'cputype': cputype, 'cpusubtype': cpusubtype,
        'filetype': filetype, 'ncmds': ncmds, 'sizeofcmds': sizeofcmds,
        'flags': flags, 'reserved': reserved,
    }

def iterate_load_commands(data, header_size=32):
    off = header_size
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    end = off + sizeofcmds
    for i in range(ncmds):
        if off + 8 > len(data):
            break
        cmd = struct.unpack_from("<I", data, off)[0]
        cmdsize = struct.unpack_from("<I", data, off + 4)[0]
        if cmdsize < 8:
            break
        yield cmd, cmdsize, off, off + 8
        off += cmdsize

def find_dylib_commands(data):
    cmds = []
    for cmd, cmdsize, off, _ in iterate_load_commands(data):
        if cmd == LC_LOAD_DYLIB:
            cmds.append((cmd, cmdsize, off))
    return cmds

def get_dylib_name(data, cmd_off):
    name_offset = struct.unpack_from("<I", data, cmd_off + 8)[0]
    str_off = cmd_off + name_offset
    end = data.index(b'\x00', str_off)
    return data[str_off:end].decode('utf-8', errors='replace')

def inject_load_command(data, dylib_path):
    if not is_macho_64(data):
        raise ValueError("Not a Mach-O 64-bit binary")

    header = parse_macho_header(data)
    ncmds = header['ncmds']
    sizeofcmds = header['sizeofcmds']

    dylib_bytes = dylib_path.encode('utf-8')
    dylib_len = len(dylib_bytes)

    cmd_size = 28 + dylib_len
    cmd_size = (cmd_size + 7) & ~7
    pad_len = cmd_size - (28 + dylib_len)

    new_cmd = struct.pack("<I", LC_LOAD_DYLIB)
    new_cmd += struct.pack("<I", cmd_size)
    new_cmd += struct.pack("<I", 28)
    new_cmd += struct.pack("<I", 0)
    new_cmd += struct.pack("<I", 1)
    new_cmd += struct.pack("<I", 1)
    new_cmd += dylib_bytes
    new_cmd += b'\x00' * pad_len

    load_cmd_end = 32 + sizeofcmds

    new_data = bytearray(data)
    new_data[load_cmd_end:load_cmd_end] = new_cmd

    struct.pack_into("<I", new_data, 16, ncmds + 1)
    struct.pack_into("<I", new_data, 20, sizeofcmds + cmd_size)

    return bytes(new_data)

def inject_dylib(binary_path, dylib_path, output_path):
    with open(binary_path, 'rb') as f:
        data = f.read()

    print(f"[+] Binary size: {len(data)} bytes")
    header = parse_macho_header(data)
    print(f"[+] Mach-O: ncmds={header['ncmds']}, sizeofcmds={header['sizeofcmds']}")

    existing = find_dylib_commands(data)
    for cmd, cmdsize, off in existing:
        name = get_dylib_name(data, off)
        if dylib_path in name or name.endswith(os.path.basename(dylib_path)):
            print(f"[!] Dylib already present: {name}")
            shutil.copy2(binary_path, output_path)
            return

    new_data = inject_load_command(data, dylib_path)

    with open(output_path, 'wb') as f:
        f.write(new_data)

    print(f"[+] Injected LC_LOAD_DYLIB for: {dylib_path}")
    print(f"[+] Output: {output_path} ({len(new_data)} bytes)")

def repack_ipa(injected_binary, app_dir, dylib_path, output_ipa):
    app_name = os.path.basename(app_dir).replace('.app', '')

    tmpdir = tempfile.mkdtemp(prefix='ipa_repack_')
    try:
        payload_dir = os.path.join(tmpdir, 'Payload')
        app_bundle_dir = os.path.join(payload_dir, os.path.basename(app_dir))
        shutil.copytree(app_dir, app_bundle_dir)

        # Replace binary
        binary_dest = os.path.join(app_bundle_dir, app_name)
        shutil.copy2(injected_binary, binary_dest)
        os.chmod(binary_dest, 0o755)

        # Copy dylib into Frameworks directory inside the app bundle
        frameworks_dir = os.path.join(app_bundle_dir, 'Frameworks')
        os.makedirs(frameworks_dir, exist_ok=True)
        dylib_dest = os.path.join(frameworks_dir, os.path.basename(dylib_path))
        shutil.copy2(dylib_path, dylib_dest)
        os.chmod(dylib_dest, 0o755)

        # Create IPA (zip)
        with zipfile.ZipFile(output_ipa, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, tmpdir)
                    zf.write(fpath, arcname)

        print(f"[+] IPA repacked: {output_ipa}")
        print(f"[+] IPA size: {os.path.getsize(output_ipa)} bytes")
        print(f"[+] Dylib placed at: Payload/{os.path.basename(app_dir)}/Frameworks/{os.path.basename(dylib_path)}")
    finally:
        shutil.rmtree(tmpdir)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == '--repack-ipa':
        _, _, injected_binary, app_dir, dylib_path, output_ipa = sys.argv
        repack_ipa(injected_binary, app_dir, dylib_path, output_ipa)
    else:
        _, binary_path, dylib_path, output_path = sys.argv
        inject_dylib(binary_path, dylib_path, output_path)
