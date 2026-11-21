#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Pure-Python 64-bit Mach-O LC_LOAD_DYLIB injector & verifier.

Injects a load command into existing header padding ahead of the first __TEXT
section without shifting any segment/section or LC_CODE_SIGNATURE offsets, so
embedded iOS Mach-O entitlements remain completely intact for sideload re-signing.
"""

from __future__ import annotations

import struct

MH_MAGIC_64 = 0xFEEDFACF
LC_LOAD_DYLIB = 0x0000000C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_SEGMENT_64 = 0x00000019


class MachOError(ValueError):
    pass


def parse_macho64_dylibs(data: bytes) -> tuple[int, int, int, list[str]]:
    """Return (ncmds, sizeofcmds, min_text_section_offset, dylib_paths)."""
    if len(data) < 32:
        raise MachOError("Data too short for Mach-O 64 header")
    magic, _cpu, _sub, _ft, ncmds, sizeofcmds, _flags, _res = struct.unpack_from("<IIIIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise MachOError(f"Unsupported Mach-O magic: {hex(magic)} (expected MH_MAGIC_64)")
    if 32 + sizeofcmds > len(data):
        raise MachOError("Mach-O load commands exceed file length")

    off = 32
    min_sec_off = len(data)
    dylibs: list[str] = []
    for _ in range(ncmds):
        if off + 8 > 32 + sizeofcmds:
            raise MachOError("Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > 32 + sizeofcmds:
            raise MachOError(f"Invalid Mach-O load command size {cmdsize} at {off}")
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8 : off + 24].rstrip(b"\x00").decode("ascii", "ignore")
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            soff = off + 72
            for _s in range(nsects):
                sec_offset = struct.unpack_from("<I", data, soff + 48)[0]
                if segname == "__TEXT" and sec_offset > 0:
                    min_sec_off = min(min_sec_off, sec_offset)
                soff += 80
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, 0x18, 0x8000001F):
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            end = data.find(b"\x00", off + name_off, off + cmdsize)
            if end < 0:
                end = off + cmdsize
            dylibs.append(data[off + name_off : end].decode("utf-8", "replace"))
        off += cmdsize

    return ncmds, sizeofcmds, min_sec_off, dylibs


def inject_lc_load_dylib(data: bytes, dylib_path: str, *, weak: bool = False) -> bytes:
    """Inject LC_LOAD_DYLIB (or LC_LOAD_WEAK_DYLIB) into Mach-O 64 header padding."""
    ncmds, sizeofcmds, min_sec_off, dylibs = parse_macho64_dylibs(data)
    if dylib_path in dylibs:
        return data

    path_bytes = dylib_path.encode("utf-8") + b"\x00"
    raw_len = 24 + len(path_bytes)
    cmdsize = (raw_len + 7) & ~7  # 8-byte alignment required for 64-bit Mach-O

    insert_at = 32 + sizeofcmds
    free_space = min_sec_off - insert_at
    if free_space < cmdsize:
        raise MachOError(
            f"Insufficient Mach-O header padding for {dylib_path}: need {cmdsize} B, have {free_space} B"
        )
    if any(data[insert_at : insert_at + cmdsize]):
        raise MachOError("Mach-O header padding at insertion point is not zeroed")

    cmd_code = LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
    cmd_blob = struct.pack("<IIIIII", cmd_code, cmdsize, 24, 2, 0x00010000, 0x00010000) + path_bytes
    cmd_blob += bytes(cmdsize - len(cmd_blob))

    buf = bytearray(data)
    buf[insert_at : insert_at + cmdsize] = cmd_blob
    struct.pack_into("<II", buf, 16, ncmds + 1, sizeofcmds + cmdsize)

    # Re-parse to guarantee structural validity
    new_ncmds, new_sizeofcmds, _min_off, new_dylibs = parse_macho64_dylibs(bytes(buf))
    if new_ncmds != ncmds + 1 or new_sizeofcmds != sizeofcmds + cmdsize or dylib_path not in new_dylibs:
        raise MachOError("Post-injection Mach-O verification failed")
    return bytes(buf)
