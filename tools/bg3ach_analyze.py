#!/usr/bin/env python3
"""
bg3ach_analyze.py - find BG3's "mods loaded, so no achievements" check in a game executable,
work out MOD_CHECK_SIGNATURE and CALL_OFFSET_IN_SIGNATURE for it, and write them into
src/bg3ach.c.

Requirements: Python 3.8+ (standard library only) and GNU objdump (from binutils). objdump is
only used to disassemble small address ranges.

None of the steps below use the signature in bg3ach.c, so they keep working after a game update.

  1. Steam side (informational)
     - Find the "STEAMUSERSTATS_INTERFACE_VERSIONxxx" string, and the small function that passes
       it to SteamInternal_FindOrCreateUserInterface. That function is the body of the Steam
       SDK's inline SteamUserStats() accessor.
     - Find the static context struct whose first field points at that function (stored as an
       R_X86_64_RELATIVE relocation).
     - In every function that uses the struct and calls SteamInternal_ContextInit, record each
       virtual call made on the ISteamUserStats* it returns. The vtable slots are named using
       libsteam_api.so, whose SteamAPI_ISteamUserStats_* functions are each `jmp [rax+slot]`.
     - Report where SetAchievement and IndicateAchievementProgress are called, the wrapper
       functions they are called from, and the vtable slots those wrappers fill.

  2. Game side (finds the mod check)
     - Find where the Osiris (game script) commands UnlockAchievement, ProgressAchievement,
       SetAchievementProgress and SetAchievementProgressForPlayer are registered, and the
       functions that handle them.
     - Follow direct calls from those handlers, up to two levels deep, looking for the mod check:
       a function that loops over the module list and calls a helper that formats each module's
       UUID with "%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx".
     - List every function that calls the mod check.

  3. Signature
     - Build MOD_CHECK_SIGNATURE from the mod check's code, from its first instruction to the
       jump back to the start of its loop. Bytes likely to change between builds are wildcards:
       jump and call distances, struct field offsets, and small constants added or compared.
       CALL_OFFSET_IN_SIGNATURE is the byte offset of the call to the whitelist helper.
     - Make sure the signature matches exactly one place in the game's code: the mod check.

  4. Update src/bg3ach.c
     - Replace MOD_CHECK_SIGNATURE and CALL_OFFSET_IN_SIGNATURE with the new values. If the file
       already has these values, it is left as it is (keeping its hand-written comments).
     - With --test, compile tests/test_offline.c against the result and run it on the game.

Usage (from the repository root; `make analyze` runs the first form against $(GAME)):
  tools/bg3ach_analyze.py bin/bg3 --test
  tools/bg3ach_analyze.py bin/bg3 --dry-run           # show the values, change nothing
  tools/bg3ach_analyze.py bin/bg3 --file other/bg3ach.c

Exit status: 0 on success (whether or not the file needed changing), 1 if the analysis or the
offline test failed.
"""

import argparse
import bisect
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import NamedTuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SOURCE = os.path.join(REPO, "src", "bg3ach.c")
OFFLINE_TEST = os.path.join(REPO, "tests", "test_offline.c")

EXIT_OK = 0
EXIT_FAILED = 1

# The whitelist helper formats each module's UUID with this string.
UUID_FORMAT = b"%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx"

# Osiris commands that unlock or advance achievements. Each of them checks for mods first.
OSIRIS_ACHIEVEMENT_COMMANDS = [
    "UnlockAchievement",
    "ProgressAchievement",
    "SetAchievementProgress",
    "SetAchievementProgressForPlayer",
]

# ISteamUserStats012 vtable slot names, used when libsteam_api.so isn't available.
USERSTATS012_SLOT_NAMES = {
    0x00: "RequestCurrentStats",
    0x08: "GetStatInt32",
    0x10: "GetStatFloat",
    0x18: "SetStatInt32",
    0x20: "SetStatFloat",
    0x28: "UpdateAvgRateStat",
    0x30: "GetAchievement",
    0x38: "SetAchievement",
    0x40: "ClearAchievement",
    0x48: "GetAchievementAndUnlockTime",
    0x50: "StoreStats",
    0x58: "GetAchievementIcon",
    0x60: "GetAchievementDisplayAttribute",
    0x68: "IndicateAchievementProgress",
    0x70: "GetNumAchievements",
    0x78: "GetAchievementName",
}

# Names used in bg3ach.c.
SIG_NAME = "MOD_CHECK_SIGNATURE"
CALL_OFF_NAME = "CALL_OFFSET_IN_SIGNATURE"


class Fail(Exception):
    """The analysis can't continue. The message says why."""


def log(msg=""):
    print(msg, flush=True)


# =============================================================================================
# Minimal ELF64 reader
# =============================================================================================

EM_X86_64 = 62
PT_LOAD = 1
PF_X = 1                  # segment flag: executable
R_X86_64_RELATIVE = 8
SYMBOL_ENTRY_SIZE = 24    # sizeof(Elf64_Sym)


class Segment(NamedTuple):
    """A loadable (PT_LOAD) segment: the part of the file mapped into memory."""
    vaddr: int
    offset: int
    file_size: int
    flags: int

    @property
    def executable(self):
        return bool(self.flags & PF_X)

    def contains(self, va):
        return self.vaddr <= va < self.vaddr + self.file_size


class Section(NamedTuple):
    addr: int
    offset: int
    size: int


class Elf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        data = self.data

        # e_ident: magic, ELFCLASS64 (2), ELFDATA2LSB (1)
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise Fail(f"{path}: not a little-endian ELF64 file")

        (_e_type, e_machine, _e_version, _e_entry, e_phoff, e_shoff, _e_flags, _e_ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", data, 16)
        if e_machine != EM_X86_64:
            raise Fail(f"{path}: not x86-64")

        # Program headers -> loadable segments
        self.segments = []
        for i in range(e_phnum):
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz,
             _p_align) = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
            if p_type == PT_LOAD:
                self.segments.append(Segment(p_vaddr, p_offset, p_filesz, p_flags))
        self.code_segments = [s for s in self.segments if s.executable]

        # Section headers, by name
        self.sections = {}
        if e_shoff and e_shnum:
            headers = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
                       for i in range(e_shnum)]
            names_offset = headers[e_shstrndx][4]
            for (sh_name, _type, _flags, sh_addr, sh_offset, sh_size, *_rest) in headers:
                name = self._string_at(names_offset + sh_name)
                self.sections[name] = Section(sh_addr, sh_offset, sh_size)

        self._relocations = None
        self._function_starts = None

    def _string_at(self, file_offset):
        end = self.data.index(b"\0", file_offset)
        return self.data[file_offset:end].decode()

    def file_offset(self, va):
        """File offset of virtual address `va`, or None if it isn't backed by the file."""
        for seg in self.segments:
            if seg.contains(va):
                return va - seg.vaddr + seg.offset
        return None

    def read(self, va, length):
        offset = self.file_offset(va)
        if offset is None:
            return None
        return self.data[offset:offset + length]

    def section(self, name):
        sec = self.sections.get(name)
        if not sec:
            raise Fail(f"{self.path}: section {name} missing")
        return sec

    def section_data(self, sec):
        return self.data[sec.offset:sec.offset + sec.size]

    def segment_data(self, seg):
        return self.data[seg.offset:seg.offset + seg.file_size]

    def in_text(self, va):
        text = self.section(".text")
        return text.addr <= va < text.addr + text.size

    def build_id(self):
        sec = self.sections.get(".note.gnu.build-id")
        if not sec:
            return None
        note = self.section_data(sec)
        name_size, desc_size, _note_type = struct.unpack_from("<III", note, 0)
        desc_start = 12 + ((name_size + 3) & ~3)  # name is padded to 4 bytes
        return note[desc_start:desc_start + desc_size].hex()

    def dynamic_symbols(self):
        """{name: address} for every defined dynamic symbol."""
        symbols = {}
        dynsym = self.sections.get(".dynsym")
        if not dynsym:
            return symbols
        dynstr = self.sections[".dynstr"]
        for i in range(dynsym.size // SYMBOL_ENTRY_SIZE):
            st_name, _info, _other, _shndx, st_value, _size = struct.unpack_from(
                "<IBBHQQ", self.data, dynsym.offset + i * SYMBOL_ENTRY_SIZE)
            if st_value:
                symbols[self._string_at(dynstr.offset + st_name)] = st_value
        return symbols

    def relative_relocations(self):
        """
        R_X86_64_RELATIVE relocations, as two dicts:
          by_target:   {pointed-to address: [addresses of the pointers]}
          by_location: {address of the pointer: pointed-to address}
        These are the pointers the loader fills in, such as vtable entries.
        """
        if self._relocations is None:
            by_target, by_location = {}, {}
            sec = self.sections.get(".rela.dyn")
            if sec:
                entries = memoryview(self.data)[sec.offset:sec.offset + sec.size]
                for r_offset, r_info, r_addend in struct.iter_unpack("<QQq", entries):
                    if (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
                        by_target.setdefault(r_addend, []).append(r_offset)
                        by_location[r_offset] = r_addend
            self._relocations = (by_target, by_location)
        return self._relocations

    def function_starts(self):
        """
        Sorted start addresses of every function with unwind info, read from the binary search
        table in .eh_frame_hdr. The binary has no symbols, so this is how we find functions.
        """
        if self._function_starts is None:
            sec = self.section(".eh_frame_hdr")
            hdr = self.section_data(sec)
            version, frame_ptr_enc, count_enc, table_enc = hdr[0], hdr[1], hdr[2], hdr[3]
            # count must be udata4 (0x03); table entries must be datarel|sdata4 (0x3B)
            if version != 1 or count_enc != 0x03 or table_enc != 0x3B:
                raise Fail(f".eh_frame_hdr has unexpected encoding {hdr[:4].hex()}")
            frame_ptr_size = 4 if (frame_ptr_enc & 0x0F) in (0x03, 0x0B) else 8
            pos = 4 + frame_ptr_size
            (count,) = struct.unpack_from("<I", hdr, pos)
            pos += 4
            table = hdr[pos:pos + 8 * count]
            # Each entry is (function start, FDE address), relative to .eh_frame_hdr.
            self._function_starts = sorted(
                sec.addr + start for start, _fde in struct.iter_unpack("<ii", table))
        return self._function_starts

    def function_bounds(self, va):
        """(start, end) of the function containing `va`. The end is the next function's start."""
        starts = self.function_starts()
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None, None
        end = starts[i + 1] if i + 1 < len(starts) else starts[i] + 0x1000
        return starts[i], end


# =============================================================================================
# Byte-level searches over the game's code
# =============================================================================================

# lea r64, [rip + disp32]: REX.W (48 or 4C), 8D, then a ModRM byte with mod=00 and rm=101.
# The whole instruction is 7 bytes, with the displacement in the last 4.
RIP_LEA = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
RIP_LEA_LENGTH = 7

CALL_REL32 = 0xE8
JMP_REL32 = 0xE9


def rip_lea_target(buf, i):
    """Address (relative to buf) that the RIP-relative LEA at buf[i] loads."""
    return i + RIP_LEA_LENGTH + struct.unpack_from("<i", buf, i + 3)[0]


def find_rip_leas(elf, targets):
    """{target: [address of each LEA that loads it]}"""
    targets = set(targets)
    found = {t: [] for t in targets}
    for seg in elf.code_segments:
        code = elf.segment_data(seg)
        for m in RIP_LEA.finditer(code):
            i = m.start()
            if i + RIP_LEA_LENGTH > len(code):
                continue
            target = seg.vaddr + rip_lea_target(code, i)
            if target in targets:
                found[target].append(seg.vaddr + i)
    return found


def find_direct_calls(elf, targets, opcodes=(CALL_REL32, JMP_REL32)):
    """{target: [(address, opcode)]} for every `call rel32` / `jmp rel32` to a target."""
    targets = set(targets)
    found = {t: [] for t in targets}
    for seg in elf.code_segments:
        code = elf.segment_data(seg)
        for opcode in opcodes:
            needle = bytes([opcode])
            i = code.find(needle)
            while i != -1:
                if i + 5 <= len(code):
                    target = seg.vaddr + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
                    if target in targets:
                        found[target].append((seg.vaddr + i, opcode))
                i = code.find(needle, i + 1)
    return found


def data_segments(elf):
    return [seg for seg in elf.segments if not seg.executable]


def find_cstrings(elf, text):
    """Addresses of every complete NUL-terminated copy of `text` in the game's data."""
    needle = b"\0" + text + b"\0"
    found = []
    for seg in data_segments(elf):
        data = elf.segment_data(seg)
        i = data.find(needle)
        while i != -1:
            found.append(seg.vaddr + i + 1)
            i = data.find(needle, i + 1)
    return found


def find_strings_starting_with(elf, prefix):
    """[(address, full string)] for every NUL-terminated string that starts with `prefix`."""
    needle = b"\0" + prefix
    found = []
    for seg in data_segments(elf):
        data = elf.segment_data(seg)
        i = data.find(needle)
        while i != -1:
            end = data.index(b"\0", i + 1)
            found.append((seg.vaddr + i + 1, data[i + 1:end]))
            i = data.find(needle, i + 1)
    return found


def parse_sig(sig):
    """'55 41 ?? ...' -> (pattern bytes, mask bytes). Wildcards are 0 in both."""
    tokens = sig.split()
    pattern = bytes(0 if t.startswith("?") else int(t, 16) for t in tokens)
    mask = bytes(0 if t.startswith("?") else 0xFF for t in tokens)
    return pattern, mask


def sig_scan(elf, sig):
    """Addresses of every place in the game's code that matches the signature."""
    pattern, mask = parse_sig(sig)
    regex = re.compile(b"".join(re.escape(bytes([byte])) if keep else b"."
                                for byte, keep in zip(pattern, mask)), re.S)
    hits = []
    for seg in elf.code_segments:
        # finditer skips overlapping matches. That's fine here: a signature that starts with a
        # run of pushes can't overlap itself.
        hits.extend(seg.vaddr + m.start() for m in regex.finditer(elf.segment_data(seg)))
    return hits


# =============================================================================================
# Disassembly (objdump)
# =============================================================================================

OBJDUMP = shutil.which("objdump")

# "  37675d0:\t55 \t push rbp" -> address, hex bytes, instruction text
OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$")


class Instruction(NamedTuple):
    address: int
    raw: bytes
    text: str     # Intel syntax, whitespace collapsed, e.g. "mov rdi,QWORD PTR [rbx+0x8]"


def disassemble(elf, start, end):
    """Instructions in the address range [start, end)."""
    if not OBJDUMP:
        raise Fail("objdump not found in PATH (install binutils)")
    cmd = [OBJDUMP, "-d", "-M", "intel", "--insn-width=16", "-w",
           f"--start-address={start:#x}", f"--stop-address={end:#x}", elf.path]
    output = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True,
                            errors="replace").stdout
    instructions = []
    for line in output.splitlines():
        m = OBJDUMP_LINE.match(line)
        if m:
            instructions.append(Instruction(
                address=int(m.group(1), 16),
                raw=bytes.fromhex(m.group(2).replace(" ", "")),
                text=re.sub(r"\s+", " ", m.group(3)).strip()))
    return instructions


def without_symbol_names(text):
    """Drop objdump's long <C++ symbol> annotations, but keep <foo@plt>."""
    return re.sub(r"<[^>]*>", lambda m: m.group(0) if "@plt" in m.group(0) else "",
                  text).strip()


def rip_target(text):
    """Address a [rip+disp] operand refers to (objdump writes it after '#'), or None."""
    m = re.search(r"\[rip[+-]0x[0-9a-f]+\]\s*#\s*([0-9a-f]+)", text)
    return int(m.group(1), 16) if m else None


def direct_target(text):
    """Target of a direct `call` or `jmp`, or None."""
    m = re.match(r"(call|jmp)\s+([0-9a-f]+)\b", text)
    return int(m.group(2), 16) if m else None


def conditional_jump_target(text):
    """Target of a conditional jump (je, jne, ...), or None for anything else."""
    m = re.match(r"j(?!mp)\w+ ([0-9a-f]+)\b", text)
    return int(m.group(1), 16) if m else None


# =============================================================================================
# Step 1: how the game uses Steam's ISteamUserStats
# =============================================================================================

STEAM_FLAT_API_PREFIX = "SteamAPI_ISteamUserStats_"


def steam_slot_names(steam_path, interface_version):
    """({vtable slot offset: method name}, description of where the names came from)."""
    names = {}
    if steam_path and os.path.exists(steam_path):
        steam = Elf(steam_path)
        versions = sorted(set(re.findall(rb"STEAMUSERSTATS_INTERFACE_VERSION\d+", steam.data)))
        for symbol, va in steam.dynamic_symbols().items():
            if not symbol.startswith(STEAM_FLAT_API_PREFIX):
                continue
            method = symbol[len(STEAM_FLAT_API_PREFIX):]
            code = steam.read(va, 12)
            # Each flat API function is: mov rax,[rdi]  then one of
            #   jmp [rax+disp8]    FF 60 xx
            #   jmp [rax+disp32]   FF A0 xx xx xx xx
            #   jmp [rax]          FF 20
            if code[:3] == b"\x48\x8b\x07":
                if code[3:5] == b"\xff\x60":
                    names[code[5]] = method
                elif code[3:5] == b"\xff\xa0":
                    names[struct.unpack_from("<i", code, 5)[0]] = method
                elif code[3:5] == b"\xff\x20":
                    names[0] = method
        if interface_version.encode() not in versions:
            log(f"  WARNING: libsteam_api.so implements {versions}, game asks for "
                f"{interface_version}; slot names may be off")
        if names:
            listed = ", ".join(v.decode() for v in versions)
            return names, f"libsteam_api.so flat API ({listed})"
    return dict(USERSTATS012_SLOT_NAMES), "built-in ISteamUserStats012 table"


def find_steam_context(elf, interface_address):
    """Address of the static struct whose first field points at the SteamUserStats() accessor."""
    leas = find_rip_leas(elf, [interface_address])[interface_address]
    if not leas:
        raise Fail("no code references the interface string")
    contexts = []
    by_target, _ = elf.relative_relocations()
    for site in leas:
        start, end = elf.function_bounds(site)
        code = disassemble(elf, start, end)
        if not any("SteamInternal_FindOrCreateUserInterface@plt" in ins.text for ins in code):
            continue
        contexts.extend(by_target.get(start, []))
        log(f"  accessor thunk       {start:#x}  (SteamInternal_FindOrCreateUserInterface)")
    if not contexts:
        raise Fail("could not find SteamUserStats() context struct")
    return contexts[0]


class VirtualCall(NamedTuple):
    address: int
    function: int     # start of the function containing the call
    slot: int         # vtable offset
    kind: str         # "call" or "jmp" (tail call)


def find_userstats_calls(elf, context):
    """
    Every virtual call made on the ISteamUserStats* returned by SteamInternal_ContextInit.

    Within each function that loads the context struct, this follows which registers hold which
    addresses (well enough for these short functions). After a call to SteamInternal_ContextInit
    with the context struct as its argument, the next indirect call is a method call on the
    interface.
    """
    users = find_rip_leas(elf, [context])[context]
    functions = sorted({elf.function_bounds(u) for u in users})
    calls = []
    for start, end in functions:
        registers = {}          # register -> address it holds
        expecting_call = False  # just called ContextInit(context)
        for ins in disassemble(elf, start, end):
            text = ins.text
            m = re.match(r"^lea (\w+),", text)
            if m and rip_target(text) is not None:
                registers[m.group(1)] = rip_target(text)
                continue
            m = re.match(r"mov (\w+),(\w+)$", text)
            if m:
                registers[m.group(1)] = registers.get(m.group(2))
                continue
            if text.startswith("call") and "SteamInternal_ContextInit@plt" in text:
                expecting_call = registers.get("rdi") == context
                continue
            m = re.match(r"(call|jmp) QWORD PTR \[(\w+)(?:\+0x([0-9a-f]+))?\]", text)
            if m and expecting_call:
                slot = int(m.group(3) or "0", 16)
                calls.append(VirtualCall(ins.address, start, slot, m.group(1)))
                expecting_call = False
                continue
            if text.startswith("call"):
                expecting_call = False
    return calls, len(functions)


def describe_vtable_slots(elf, function):
    """Where `function` appears in vtables, e.g. ['vtable fn-array 0x7a35d08 slot +0x60']."""
    by_target, by_location = elf.relative_relocations()
    descriptions = []
    for slot in by_target.get(function, []):
        # Walk back to the start of the vtable: the first earlier pointer-sized entry that
        # isn't relocated.
        table = slot
        while (table - 8) in by_location:
            table -= 8
        descriptions.append(f"vtable fn-array {table:#x} slot +{slot - table:#x}")
    return descriptions


def analyze_steam(elf, steam_path):
    log("== Step 1: Steam ISteamUserStats usage")
    interfaces = find_strings_starting_with(elf, b"STEAMUSERSTATS_INTERFACE_VERSION")
    if not interfaces:
        raise Fail("STEAMUSERSTATS_INTERFACE_VERSION string not found")
    interface_address, interface = interfaces[0]
    interface = interface.decode()
    log(f"  interface string     {interface} @ {interface_address:#x}")

    slot_names, names_source = steam_slot_names(steam_path, interface)
    log(f"  slot names from      {names_source}")
    slot_of = {name: slot for slot, name in slot_names.items()}

    context = find_steam_context(elf, interface_address)
    log(f"  context struct       {context:#x}  (first field -> accessor thunk)")

    calls, function_count = find_userstats_calls(elf, context)
    if not calls:
        raise Fail("no ISteamUserStats virtual calls found")
    log(f"  {len(calls)} ISteamUserStats vcalls in {function_count} functions:")
    for call in calls:
        log(f"    {call.address:#x} in {call.function:#x}: {call.kind:4} "
            f"[vtbl+{call.slot:#04x}] {slot_names.get(call.slot, '?')}")

    for method in ("SetAchievement", "IndicateAchievementProgress"):
        if method not in slot_of:
            raise Fail(f"slot for {method} unknown")
    for method in ("SetAchievement", "IndicateAchievementProgress"):
        sites = [c for c in calls if c.slot == slot_of[method]]
        if not sites:
            raise Fail(f"no call to ISteamUserStats::{method}")
        for call in sites:
            where = "; ".join(describe_vtable_slots(elf, call.function)) or "not in a vtable"
            log(f"  {method:28} call {call.address:#x} in wrapper {call.function:#x}  [{where}]")


# =============================================================================================
# Step 2: the game's mod check
# =============================================================================================

def references_uuid_format(elf, function, format_addresses, search_length=0x100):
    """Does the start of `function` load the address of the UUID format string?"""
    code = elf.read(function, search_length)
    if not code:
        return False
    for m in RIP_LEA.finditer(code):
        i = m.start()
        if i + RIP_LEA_LENGTH <= len(code):
            if function + rip_lea_target(code, i) in format_addresses:
                return True
    return False


def looks_like_mod_check(elf, function, format_addresses):
    """
    Is `function` shaped like `bool HasNonWhitelistedMods(ModuleList *)`? That is: in its first
    0x80 bytes, a direct call to a helper that formats module UUIDs, inside a loop (followed by
    a conditional jump back to before the call).

    Returns (helper address, call address), or None.
    """
    code = disassemble(elf, function, function + 0x80)
    for k, ins in enumerate(code):
        helper = direct_target(ins.text)
        if not (ins.text.startswith("call") and helper
                and references_uuid_format(elf, helper, format_addresses)):
            continue
        for later in code[k + 1:]:
            target = conditional_jump_target(later.text)
            if target is not None and function <= target <= ins.address:
                return helper, ins.address
            if later.text.startswith("ret"):
                break
    return None


def osiris_handlers(elf, command):
    """[(registration address, handler address)] for an Osiris command named `command`."""
    handlers = []
    for name_address in find_cstrings(elf, command.encode()):
        for site in find_rip_leas(elf, [name_address])[name_address]:
            # The registration stores the name and the handler in a newly allocated descriptor.
            # The handler is the first code address loaded in the next ~0x60 bytes.
            for ins in disassemble(elf, site, site + 0x60)[1:]:
                target = rip_target(ins.text)
                if ins.text.startswith("lea") and target and elf.in_text(target):
                    handlers.append((site, target))
                    break
                if ins.text.startswith("call"):
                    break
    return handlers


def direct_callees(elf, function):
    """Functions called directly (not through the PLT) from the first 0x400 bytes."""
    start, end = elf.function_bounds(function)
    if start != function or end <= function:
        return []
    callees = []
    for ins in disassemble(elf, function, min(end, function + 0x400)):
        target = direct_target(ins.text)
        if (target and ins.text.startswith("call") and "@plt" not in ins.text
                and elf.in_text(target)):
            callees.append(target)
    return callees


def analyze_gate(elf):
    log("\n== Step 2: game-side achievement gate")
    format_addresses = set(find_cstrings(elf, UUID_FORMAT))
    if not format_addresses:
        raise Fail("UUID format string not found")
    log(f"  UUID format string   @ {', '.join(hex(a) for a in format_addresses)}")

    shape_cache = {}

    def mod_check_shape(function):
        if function not in shape_cache:
            shape_cache[function] = looks_like_mod_check(elf, function, format_addresses)
        return shape_cache[function]

    candidates = {}  # mod check address -> names of the commands that reach it
    for command in OSIRIS_ACHIEVEMENT_COMMANDS:
        handlers = osiris_handlers(elf, command)
        if not handlers:
            log(f"  Osiris {command:32} not registered")
            continue
        for site, handler in handlers:
            # Breadth-first search: the handler, then what it calls, then what those call.
            level, seen, found = [handler], {handler}, []
            for _depth in range(3):
                next_level = []
                for function in level:
                    if mod_check_shape(function):
                        found.append(function)
                        continue
                    for callee in direct_callees(elf, function):
                        if callee not in seen:
                            seen.add(callee)
                            next_level.append(callee)
                level = next_level
            log(f"  Osiris {command:32} reg@{site:#x} handler {handler:#x} -> gate "
                f"{', '.join(hex(f) for f in found) or 'none found'}")
            for function in found:
                candidates.setdefault(function, set()).add(command)

    if not candidates:
        raise Fail("no gate candidate reachable from Osiris achievement handlers")
    # Prefer the function reached by the most commands, then one reached by UnlockAchievement.
    gate = max(candidates, key=lambda f: (len(candidates[f]),
                                          "UnlockAchievement" in candidates[f]))
    if "UnlockAchievement" not in candidates[gate]:
        raise Fail("UnlockAchievement handler does not reach the gate")
    if len(candidates) > 1:
        log(f"  WARNING: multiple candidates {[hex(c) for c in candidates]}, using {gate:#x}")
    helper, call_site = mod_check_shape(gate)
    log(f"  GATE                 {gate:#x}  "
        f"(reached from: {', '.join(sorted(candidates[gate]))})")
    log(f"  per-module helper    {helper:#x}  (call @ {call_site:#x}, formats module UUID)")

    callers = find_direct_calls(elf, [gate])[gate]
    log(f"  {len(callers)} direct callers of gate:")
    for site, opcode in callers:
        function, _ = elf.function_bounds(site)
        log(f"    {'call' if opcode == CALL_REL32 else 'jmp '} @ {site:#x}  in {function:#x}")
    return gate, helper, call_site


# =============================================================================================
# Step 3: build the signature and update bg3ach.c
# =============================================================================================

# Prefix bytes: operand/address size, rep/repne, and segment overrides.
PREFIXES = {0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65}


def wildcard_mask(raw, text):
    """
    Which bytes of one instruction should be wildcards: those likely to change between builds.

      - jump and call distances
      - displacements in memory operands (struct field offsets, RIP-relative addresses)
      - the 8-bit constant of `add/sub/cmp/... r/m, imm8` (opcode 83), e.g. a struct size
    """
    wild = [False] * len(raw)

    # Skip prefixes and a REX byte to reach the opcode.
    i = 0
    while i < len(raw) and raw[i] in PREFIXES:
        i += 1
    if i < len(raw) and 0x40 <= raw[i] <= 0x4F:
        i += 1
    opcode = raw[i]

    # Short jumps (jcc rel8, jmp rel8, jrcxz): the last byte is the distance.
    if 0x70 <= opcode <= 0x7F or opcode in (0xEB, 0xE3):
        wild[-1] = True
        return wild
    # call rel32, jmp rel32, and near jcc rel32 (0F 80..8F): the last 4 bytes.
    if opcode in (CALL_REL32, JMP_REL32) or (opcode == 0x0F and 0x80 <= raw[i + 1] <= 0x8F):
        wild[-4:] = [True] * 4
        return wild

    # Memory operand (except mov to/from an absolute address, A0..A3): find the displacement
    # from the ModRM byte (and SIB byte, if there is one).
    if opcode == 0x0F:
        opcode_length = 3 if raw[i + 1] in (0x38, 0x3A) else 2
    else:
        opcode_length = 1
    if "[" in text and not (0xA0 <= opcode <= 0xA3):
        modrm_at = i + opcode_length
        modrm = raw[modrm_at]
        mod, rm = modrm >> 6, modrm & 7
        has_sib = mod != 3 and rm == 4
        disp_at = modrm_at + 1 + (1 if has_sib else 0)
        if mod == 1:                                    # [reg + disp8]
            wild[disp_at] = True
        elif mod == 2 or (mod == 0 and rm == 5):        # [reg + disp32] or [rip + disp32]
            wild[disp_at:disp_at + 4] = [True] * 4
        elif has_sib and mod == 0 and (raw[modrm_at + 1] & 7) == 5:   # SIB with no base
            wild[disp_at:disp_at + 4] = [True] * 4

    if opcode == 0x83:
        wild[-1] = True
    return wild


class SignatureLine(NamedTuple):
    tokens: list   # e.g. ["48", "8B", "7B", "??"]
    text: str      # the disassembly


def derive_signature(elf, gate):
    """
    Signature for the mod check: from its first instruction through the conditional jump back
    to the top of its loop.

    Returns (signature string, offset of the first `call` in it, [SignatureLine]).
    """
    selected = []
    for ins in disassemble(elf, gate, gate + 0x100):
        selected.append(ins)
        target = conditional_jump_target(ins.text)
        if target is not None and gate <= target < ins.address:
            break
        if ins.text.startswith("ret"):
            raise Fail("gate has no loop back-edge before ret; shape changed, inspect manually")

    lines, call_offset, offset = [], None, 0
    for ins in selected:
        wild = wildcard_mask(ins.raw, ins.text)
        tokens = ["??" if w else f"{byte:02X}" for byte, w in zip(ins.raw, wild)]
        if ins.raw[0] == CALL_REL32 and call_offset is None:
            call_offset = offset
        lines.append(SignatureLine(tokens, without_symbol_names(ins.text)))
        offset += len(ins.raw)
    if call_offset is None:
        raise Fail("no direct call in signature range")
    signature = " ".join(token for line in lines for token in line.tokens)
    return signature, call_offset, lines


# The signature in bg3ach.c: from "static const char MOD_CHECK_SIGNATURE[] =" up to and
# including the line whose string literal is followed by the final ';'. (The comments on each
# line may contain ';' too, so we can't just stop at the first one.)
SIG_DEF_RE = re.compile(
    r"static const char " + SIG_NAME + r"\[\] =\n(?:.*\n)*?[^\n]*\"\s*;[^\n]*")
CALL_OFF_RE = re.compile(r"#define " + CALL_OFF_NAME + r" (\d+)")


def read_current_values(source, path):
    """(signature, call offset, signature match) as currently written in bg3ach.c."""
    sig_match = SIG_DEF_RE.search(source)
    call_off_match = CALL_OFF_RE.search(source)
    if not sig_match or not call_off_match:
        raise Fail(f"{path}: {SIG_NAME} / {CALL_OFF_NAME} not found")
    without_comments = re.sub(r"/\*.*?\*/", "", sig_match.group(0), flags=re.S)
    literals = "".join(re.findall(r"\"([^\"]*)\"", without_comments))
    return " ".join(literals.split()), int(call_off_match.group(1)), sig_match


def render_sig(lines, call_offset):
    """One instruction per line, in the style of bg3ach.c:   "XX ?? "   /* disassembly */"""
    rendered, offset = [], 0
    for k, line in enumerate(lines):
        last = k == len(lines) - 1
        literal = '"' + " ".join(line.tokens) + ('";' if last else ' "')
        note = line.text.replace("*/", "* /")
        if offset == call_offset:
            note += f"  ; <- {CALL_OFF_NAME}"
        rendered.append(f"    {literal:<24}/* {note:<57} */")
        offset += len(line.tokens)
    return "\n".join(rendered)


def update_source(source, sig_match, lines, call_offset, gate, elf):
    """bg3ach.c's text with the signature and call offset replaced."""
    new_definition = (
        f"static const char {SIG_NAME}[] =\n"
        f"    /* generated by tools/bg3ach_analyze.py for build-id {elf.build_id()},\n"
        f"       function at offset {gate:#x} */\n"
        f"{render_sig(lines, call_offset)}")
    updated = source[:sig_match.start()] + new_definition + source[sig_match.end():]
    return CALL_OFF_RE.sub(f"#define {CALL_OFF_NAME} {call_offset}", updated, 1)


def run_offline_test(source, test_c, game):
    """
    Compile the offline test against `source` (the text of bg3ach.c) and run it.
    Returns True/False, or None if there is no compiler.
    """
    cc = os.environ.get("CC") or shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("  --test: no C compiler, skipped")
        return None
    with tempfile.TemporaryDirectory() as tmp:
        # test_offline.c does #include "bg3ach.c", so both go in the same folder.
        with open(os.path.join(tmp, "bg3ach.c"), "w") as f:
            f.write(source)
        shutil.copy(test_c, os.path.join(tmp, "test_offline.c"))
        exe = os.path.join(tmp, "test_offline")
        compiled = subprocess.run(
            [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-o", exe,
             os.path.join(tmp, "test_offline.c")],
            capture_output=True, text=True)
        if compiled.returncode:
            log("  --test: compile failed:\n" + compiled.stderr)
            return False
        result = subprocess.run([exe, game], capture_output=True, text=True)
        for line in (result.stdout + result.stderr).splitlines():
            log("    " + line)
        return result.returncode == 0


# =============================================================================================
# Main
# =============================================================================================

def write_values(elf, path, lines, call_offset, gate, dry_run):
    """
    Put the new signature and call offset into the bg3ach.c at `path`. Returns the resulting
    text (what the file holds, or would hold with --dry-run).
    """
    with open(path) as f:
        source = f.read()
    old_sig, old_call_offset, sig_match = read_current_values(source, path)
    new_sig = " ".join(token for line in lines for token in line.tokens)

    log(f"\n== Step 4: update {path}")
    if parse_sig(old_sig) == parse_sig(new_sig) and old_call_offset == call_offset:
        log("  already has these values - not changed")
        return source

    updated = update_source(source, sig_match, lines, call_offset, gate, elf)
    if dry_run:
        log(f"  values differ - would update {SIG_NAME} and {CALL_OFF_NAME} (--dry-run)")
    else:
        with open(path, "w") as f:
            f.write(updated)
        offset_note = ("" if old_call_offset == call_offset
                       else f" ({CALL_OFF_NAME} was {old_call_offset}, now {call_offset})")
        log(f"  updated {SIG_NAME} and {CALL_OFF_NAME}{offset_note}")
    return updated


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bg3", help="path to the bg3 executable")
    parser.add_argument("--steam-api", help="libsteam_api.so (default: next to bg3)")
    parser.add_argument("--file", default=DEFAULT_SOURCE,
                        help="bg3ach.c to update (default: src/bg3ach.c)")
    parser.add_argument("--dry-run", action="store_true",
                        help="find and print the values, but don't change the file")
    parser.add_argument("--test", action="store_true",
                        help="compile test_offline.c against the updated bg3ach.c "
                             "and run it on bg3")
    return parser.parse_args()


def main():
    args = parse_args()
    steam_path = args.steam_api or os.path.join(os.path.dirname(os.path.abspath(args.bg3)),
                                                "libsteam_api.so")
    try:
        elf = Elf(args.bg3)
        log(f"bg3: {args.bg3}\n  md5 {hashlib.md5(elf.data).hexdigest()}  "
            f"build-id {elf.build_id()}  functions(eh_frame) {len(elf.function_starts())}\n")

        analyze_steam(elf, steam_path)
        gate, _helper, call_site = analyze_gate(elf)

        log("\n== Step 3: signature")
        signature, call_offset, lines = derive_signature(elf, gate)
        if gate + call_offset != call_site:
            raise Fail(f"signature call offset {call_offset} does not hit helper call "
                       f"{call_site:#x}")
        hits = sig_scan(elf, signature)
        log(f"  derived {SIG_NAME}:")
        for line in lines:
            log(f"    {' '.join(line.tokens):<44} {line.text}")
        log(f"  derived {CALL_OFF_NAME} = {call_offset}; matches: {[hex(x) for x in hits]}")
        if hits != [gate]:
            raise Fail("derived signature is not unique / does not hit the gate; "
                       "extend the range in derive_signature()")

        if not os.path.exists(args.file):
            raise Fail(f"{args.file} not found")
        source = write_values(elf, args.file, lines, call_offset, gate, args.dry_run)

        if args.test:
            log(f"\n== offline test of {args.file}" + (" (with new values)" if args.dry_run
                                                        else ""))
            passed = run_offline_test(source, OFFLINE_TEST, args.bg3)
            log(f"  offline test: "
                f"{'PASS' if passed else 'FAIL' if passed is False else 'skipped'}")
            if passed is False:
                log(f"\nRESULT: mod check at offset {gate:#x}; offline test failed")
                return EXIT_FAILED

        log(f"\nRESULT: mod check at offset {gate:#x}; {CALL_OFF_NAME} = {call_offset}")
        return EXIT_OK
    except Fail as e:
        log(f"\nANALYSIS FAILED: {e}")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
