#!/usr/bin/env python3

# Binary-patch the bytecode of the dex files of a jar or an APK in place, so that nothing but the
# patched instructions changes, rather than disassembling and reassembling everything with apktool.
#
# Usage: patch_dex.py ZIP, where ZIP is the jar or APK to patch. Its classes*.dex are patched where
# they are inside it, which the runtime requires them to be stored uncompressed for anyway, so the
# zip keeps every offset, every other entry and its size, and the only bytes of it that change are
# those of the patched instructions and the CRC-32 of the dex files holding them. The edits to apply
# are read from stdin as NUL-separated arguments, three per edit:
#     method NAME CODE     replace the body of every method called NAME, named as dexdump does but
#                          with the package left out (i.e. "Class.name:signature", where any package
#                          and any enclosing class match), with CODE
#     replace REGEX CODE   replace every run of consecutive instructions whose disassembly matches
#                          REGEX (one instruction per line, as dexdump prints it without its offset
#                          prefix, with the regex anchored to whole lines) with CODE, which can use
#                          \1... to refer to the groups the regex captured
#     replace-if-found REGEX CODE
#                          the same, for code that only some versions have, which is reported rather
#                          than an error if it matches nothing
# CODE is instructions separated by newlines, assembled by the small assembler below; a register is
# named vN, or pN for the N-th argument register as in smali. The new bytecode must fit in the old
# one and the rest of the old one is filled with nops. A class, a method or a field can only be named
# by an instruction if the dex file already refers to it, since a reference cannot be added without
# moving everything that follows it, so CODE can offer several bodies separated by a line holding
# "or" and the first one the dex file has every reference for is the one that gets assembled.
#
# An edit that matches nothing anywhere is an error, but for replace-if-found, and so is a method edit
# whose name matches more than the one method it is meant to patch, so that the build fails loudly
# instead of silently producing an unpatched or over-patched image if Android renames, moves or
# duplicates the code being patched. What was patched is reported, and the patched dex file is checked
# to differ from the original one only where an edit meant to write.

import bisect
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib

# the instructions the assembler knows, as opcode and instruction format, see
# https://source.android.com/docs/core/runtime/instruction-formats
INSNS = {
    "nop": (0x00, "10x"),
    "move": (0x01, "12x"),
    "move-result-object": (0x0c, "11x"),
    "return-void": (0x0e, "10x"),
    "return": (0x0f, "11x"),
    "return-object": (0x11, "11x"),
    "const/4": (0x12, "11n"),
    "const/16": (0x13, "21s"),
    "new-instance": (0x22, "21c"),
    "iput-boolean": (0x5c, "22c"),
    "invoke-direct": (0x70, "35c"),
    "invoke-static": (0x71, "35c"),
    "and-int/2addr": (0xb7, "12x"),
}

# dexdump prints the offset of the code item of each method before disassembling it, e.g.
#     0000fc:                                        |[0000fc] a.b.C.isLoopbackChecksEnabled:()Z
METHOD_RE = re.compile(r"([0-9a-f]+): +\|\[[0-9a-f]+\] (\S+)")
# and then each instruction as its own offset, its code units and its disassembly, e.g.
#     00010c: 1a00 0500                              |0000: const-string v0, "x" // string@0005
INSN_RE = re.compile(r"([0-9a-f]+): [0-9a-f. ]+\|[0-9a-f]+: (.*)")
# where an instruction referring to a class, a method or a field ends with it and its index in the dex
REF_RE = re.compile(r", (\S+) // (?:type|method|field)@([0-9a-f]+)$")


def fail(message):
    sys.exit(f"patch_dex.py: {message}")


def count(number, what):
    """Return the number followed by what, made plural unless there is one of it"""
    return f"{number} {what}" + ("" if number == 1 else "s")


class Method:
    """A method disassembled by dexdump, with the header of its code item"""

    def __init__(self, dex, index, offset, name):
        self.index = index  # of the logical dex file the method is in
        self.offset = offset
        self.name = name
        # the code item is registers_size, ins_size, outs_size and tries_size as 16-bit values
        # followed by debug_info_off and insns_size (in 16-bit code units) as 32-bit values and then
        # the bytecode
        self.registers, self.ins, self.outs, self.tries, _, self.units = struct.unpack_from("<HHHHII", dex, offset)
        self.start = offset + 16
        self.end = self.start + self.units * 2
        self.insns = []  # the (offset, disassembly) of each instruction of the method

    def register(self, name, bits):
        """Return the number of the register called vN or pN, checking that it fits in bits bits"""
        if name[:1] == "v":
            number = int(name[1:])
        elif name[:1] == "p":
            number = self.registers - self.ins + int(name[1:])
        else:
            fail(f"{name} is not a register")
        if number >= self.registers or number >> bits:
            fail(f"{self.name} has {self.registers} registers, so {name} cannot be used in it")
        return number


def parse(code):
    """Split newline-separated instructions into (line, opcode, format, registers, reference), the
    reference being the literal, class or method that follows the registers, if any"""
    out = []
    for line in code.split("\n"):
        line = line.strip()
        if not line:
            continue
        name, _, rest = line.partition(" ")
        if name not in INSNS:
            fail(f"unknown instruction: {line}")
        opcode, fmt = INSNS[name]
        if fmt == "35c":
            # a call is the registers holding its arguments, in braces, and then what it calls
            match = re.fullmatch(r"\{([^}]*)\}, (\S+)", rest)
            if not match:
                fail(f"a call takes its argument registers in braces: {line}")
            regs = match.group(1).split(", ") if match.group(1) else []
            ref = match.group(2)
        else:
            args = [a.strip() for a in rest.split(",")] if rest else []
            # the registers come first and are followed by at most a literal or a class
            regs = [a for a in args if a[:1] in ("v", "p")]
            ref = args[len(regs)] if len(args) > len(regs) else None
        out.append((line, opcode, fmt, regs, ref))
    return out


def registers(insns):
    """Return the number of registers the instructions need, i.e. one past the highest vN they use"""
    return max((int(r[1:]) + 1 for _, _, _, regs, _ in insns for r in regs if r[0] == "v"), default=0)


def outs(insns):
    """Return the number of argument registers the calls among the instructions need"""
    return max((len(regs) for _, _, fmt, regs, _ in insns if fmt == "35c"), default=0)


def missing(insns, refs):
    """Return the classes, methods and fields the instructions name that the dex file does not refer
    to"""
    return [ref for _, _, fmt, _, ref in insns if fmt in ("21c", "22c", "35c") and ref not in refs]


def literal(text, bits):
    """Return the bits that encode a signed literal of the given width"""
    value = int(text, 0)
    if not -(1 << bits - 1) <= value < 1 << bits - 1:
        fail(f"the literal {text} does not fit in {bits} bits")
    return value & (1 << bits) - 1


def encode(insns, method, refs):
    """Assemble instructions into the bytes of the bytecode of a method and their code unit counts"""
    out = bytearray()
    units = []
    for line, opcode, fmt, regs, ref in insns:
        at = len(out)
        if fmt == "10x":
            out += bytes((opcode, 0))
        elif fmt == "11x":
            out += bytes((opcode, method.register(regs[0], 8)))
        elif fmt == "12x":
            out += bytes((opcode, method.register(regs[1], 4) << 4 | method.register(regs[0], 4)))
        elif fmt == "11n":
            out += bytes((opcode, literal(ref, 4) << 4 | method.register(regs[0], 4)))
        elif fmt == "21s":
            out += bytes((opcode, method.register(regs[0], 8))) + struct.pack("<H", literal(ref, 16))
        elif fmt == "21c":
            out += bytes((opcode, method.register(regs[0], 8))) + struct.pack("<H", refs[ref])
        elif fmt == "22c":
            out += bytes((opcode, method.register(regs[1], 4) << 4 | method.register(regs[0], 4)))
            out += struct.pack("<H", refs[ref])
        elif fmt == "35c":
            # the argument registers are one nibble each, the fifth of them going next to the count
            if len(regs) > 5:
                fail(f"a call takes at most five argument registers: {line}")
            nibbles = 0
            for i, reg in enumerate(regs):
                nibbles |= method.register(reg, 4) << i * 4
            out += bytes((opcode, len(regs) << 4 | nibbles >> 16))
            out += struct.pack("<HH", refs[ref], nibbles & 0xffff)
        units.append((len(out) - at) // 2)
    return bytes(out), units


def uleb128(dex, pos):
    """Decode the unsigned LEB128 at pos, returning it and the position just past it"""
    value = shift = 0
    while True:
        byte = dex[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def sleb128(dex, pos):
    """Decode the signed LEB128 at pos, returning it and the position just past it"""
    start = pos
    value, pos = uleb128(dex, pos)
    bits = (pos - start) * 7
    return value - (1 << bits) if value >> bits - 1 else value, pos


def leb128(value, width):
    """Encode an unsigned LEB128 padded with redundant continuation bytes to exactly width bytes"""
    out = bytearray()
    for i in range(width):
        out.append(value & 0x7f | (0x80 if i < width - 1 else 0))
        value >>= 7
    if value:
        fail(f"{value} does not fit in {width} LEB128 bytes")
    return bytes(out)


def catches(dex, method):
    """Return where the try blocks of a method are, the address each one starts at and the (offset,
    width, address) of every exception handler they point at, the width being the number of bytes of
    the LEB128 that holds the address"""
    if not method.tries:
        return 0, [], []
    # the try blocks follow the bytecode, 4-byte aligned, and then the handlers they point into
    tries = method.end + 3 & ~3
    starts = [struct.unpack_from("<I", dex, tries + i * 8)[0] for i in range(method.tries)]
    handlers = []
    pos = tries + method.tries * 8
    size, pos = uleb128(dex, pos)
    for _ in range(size):
        # a handler is the number of types it catches, negated if it also catches everything else,
        # then that many (type, address) pairs and then the address catching everything else
        count, pos = sleb128(dex, pos)
        for i in range(abs(count) + (count <= 0)):
            if i < abs(count):
                _, pos = uleb128(dex, pos)
            address, end = uleb128(dex, pos)
            handlers.append((pos, end - pos, address))
            pos = end
    return tries, starts, handlers


def ranges(path, dex):
    """Return the (start, end) of each logical dex file in a dex file"""
    if dex[:4] != b"dex\n" or not dex[4:7].isdigit() or dex[7] != 0:
        fail(f"{path} is not a dex file")
    version = int(dex[4:7])
    if version in (35, 37, 38, 39, 40):
        return [(0, len(dex))]
    if version < 41:
        fail(f"{path} is a dex file of unsupported version {version:03d}")

    # 041 introduced a container format that concatenates several logical dexes into one file: each
    # keeps a full header, but header_size grows to 0x78 for the added container_size (the whole
    # file's size) and header_offset (this header's own offset) fields, file_size becomes the
    # logical dex's own size so that the dexes tile the container, and each dex is signed over its
    # own range only. Offsets stay relative to the whole file, so nothing else cares about any of it
    container_size, = struct.unpack_from("<I", dex, 0x70)
    if container_size != len(dex):
        fail(f"{path} declares a container size of {container_size:#x} but is {len(dex):#x} bytes")
    out = []
    at = 0
    while at < len(dex):
        if dex[at:at + 4] != b"dex\n":
            fail(f"{path} has no dex header at offset {at:#x}")
        file_size, header_size = struct.unpack_from("<II", dex, at + 0x20)
        header_offset, = struct.unpack_from("<I", dex, at + 0x74)
        if header_size < 0x78 or header_offset != at or not 0 < file_size <= len(dex) - at:
            fail(f"{path} has a malformed dex header at offset {at:#x}")
        out.append((at, at + file_size))
        at += file_size
    return out


def disassemble(path, dex, starts):
    """Disassemble a dex file, returning its methods and, for each logical dex file in it, the index
    of every method it refers to"""
    methods = []
    refs = [{} for _ in starts]
    dexdump = subprocess.Popen(["dexdump", "-d", path], stdout=subprocess.PIPE,
                               # a string constant can hold anything and none of it matters here
                               encoding="utf-8", errors="replace")
    for line in dexdump.stdout:
        line = line.rstrip("\n")
        match = METHOD_RE.fullmatch(line)
        if match:
            offset = int(match.group(1), 16)
            methods.append(Method(dex, bisect.bisect_right(starts, offset) - 1, offset, match.group(2)))
            continue
        match = INSN_RE.fullmatch(line)
        if match and methods:
            methods[-1].insns.append((int(match.group(1), 16), match.group(2)))
            ref = REF_RE.search(match.group(2))
            if ref:
                refs[methods[-1].index][ref.group(1)] = int(ref.group(2), 16)
    if dexdump.wait() != 0:
        fail(f"failed to disassemble {path}")
    return methods, refs


def spans(op, target, method):
    """Return the (start, end, match) of every run of bytecode of a method that an edit replaces"""
    if op == "method":
        if method.name == target or method.name.endswith("." + target):
            return [(method.start, method.end, None)]
        return []

    # the disassembly of the whole method, so that a regex can match across instructions, with the
    # position in it of each instruction, so that a match can be mapped back to the bytecode
    text = "\n".join(insn[1] for insn in method.insns)
    index = {}
    at = 0
    for i, insn in enumerate(method.insns):
        index[at] = i
        at += len(insn[1]) + 1

    out = []
    for match in target.finditer(text):
        # the regex is anchored to whole lines, so a match starts at an instruction and covers one
        # instruction more than the number of newlines in it
        first = index[match.start()]
        last = first + match.group().count("\n")
        end = method.insns[last + 1][0] if last + 1 < len(method.insns) else method.end
        out.append((method.insns[first][0], end, match))
    return out


def replace(dex, method, refs, op, code, start, end, changes):
    """Replace the bytecode of a method between start and end, filling what is left with nops, and
    record in changes every range of the dex file that is written"""
    bodies = [parse(body) for body in code.split("\nor\n")]
    insns = next((body for body in bodies if not missing(body, refs)), None)
    if insns is None:
        fail(f"{method.name} cannot be patched: of the {len(refs)} classes and methods its dex file "
             "refers to, none is " +
             ", ".join(dict.fromkeys(ref for body in bodies for ref in missing(body, refs))))

    # a vN register is a local and the locals of a method come before the parameters its pN name, so
    # a body using both needs the method to have room for as many locals as it uses below them
    needed = registers(insns)
    if any(reg[0] == "p" for _, _, _, regs, _ in insns for reg in regs):
        needed += method.ins
    if needed > method.registers:
        if op != "method":
            fail(f"{method.name} has {method.registers} registers, too few for: {code}")
        # the whole body is replaced, so nothing refers any more to the parameters that raising
        # registers_size shifts to higher register numbers (a try block holds code offsets rather
        # than registers, and debug info only needs each register it names to stay below the count)
        method.registers = needed
        struct.pack_into("<H", dex, method.offset, needed)
        changes.append((method.offset, method.offset + 2))
    # a call also needs outs_size to declare at least as many argument registers as it passes
    if outs(insns) > method.outs:
        method.outs = outs(insns)
        struct.pack_into("<H", dex, method.offset + 4, method.outs)
        changes.append((method.offset + 4, method.offset + 6))

    body, widths = encode(insns, method, refs)
    if len(body) > end - start:
        fail(f"the {len(body)} bytes of new bytecode do not fit in the {end - start} bytes "
             f"at {start:#x} of {method.name}")
    if op != "method" and any(width != 1 for width in widths):
        # anything else could leave a branch into the replaced run pointing inside an instruction
        fail(f"a replacement inside a method must use single code unit instructions: {code}")
    dex[start:end] = body.ljust(end - start, b"\0")
    changes.append((start, end))

    if op == "method":
        # the replacement ends in a return and a nop never throws, so the try blocks of the method
        # are now unreachable dead code; the bytecode kept its size, so they stay in bounds, but an
        # address pointing inside the replacement (rather than into the nops after it, where every
        # code unit starts an instruction) has to be moved past it to stay instruction-aligned
        units = len(body) // 2
        tries, starts, handlers = catches(dex, method)
        if any(0 < address < units for address in starts + [h[2] for h in handlers]):
            if units + method.tries > method.units:
                fail(f"{method.name} has no room after the replacement for its try blocks")
            # a try block can cover no fewer than one instruction and they have to stay ordered and
            # non-overlapping, so give each of them one of the nops of its own
            for i in range(method.tries):
                struct.pack_into("<IH", dex, tries + i * 8, units + i, 1)
                changes.append((tries + i * 8, tries + i * 8 + 6))
            for offset, width, address in handlers:
                if 0 < address < units:
                    dex[offset:offset + width] = leb128(units, width)
                    changes.append((offset, offset + width))


def dexes(path, data):
    """Return the name, the offset and the size of the data and the offsets of the two copies of the
    CRC-32 of every dex file a zip holds uncompressed"""
    # a zip ends with the end of central directory record, which holds the number of files and where
    # the central directory listing them is
    end = data.rfind(b"PK\x05\x06")
    if end < 0:
        fail(f"{path} is not a zip file")
    count, central_size, central = struct.unpack_from("<HII", data, end + 10)
    if count == 0xffff or 0xffffffff in (central_size, central):
        fail(f"{path} is a zip64 file, which patching in place doesn't support")

    out = []
    at = central
    for _ in range(count):
        # each entry of the central directory holds where the local header of the file is, which is
        # followed by its name, its extra field and then its data
        if data[at:at + 4] != b"PK\x01\x02":
            fail(f"{path} has no central directory entry at offset {at:#x}")
        flags, method = struct.unpack_from("<HH", data, at + 8)
        stored, size, name_length, extra_length, comment_length = struct.unpack_from("<IIHHH", data, at + 20)
        offset, = struct.unpack_from("<I", data, at + 42)
        name = data[at + 46:at + 46 + name_length].decode(errors="replace")
        if re.fullmatch(r"classes[0-9]*\.dex", name):
            # the runtime maps the dex file out of the zip rather than unpacking it, so it is always
            # stored uncompressed and there is nothing to do if that ever stops being the case
            if method != 0 or stored != size:
                fail(f"{name} is compressed in {path}, so it cannot be patched in place")
            if flags & 8:
                fail(f"{name} has its CRC-32 in a data descriptor in {path}")
            if data[offset:offset + 4] != b"PK\x03\x04":
                fail(f"{path} has no local header for {name} at offset {offset:#x}")
            # the extra field of the local header is not the one of the central directory entry
            local_name_length, local_extra_length = struct.unpack_from("<HH", data, offset + 26)
            start = offset + 30 + local_name_length + local_extra_length
            out.append((name, start, size, (offset + 14, at + 16)))
        at += 46 + name_length + extra_length + comment_length
    return out


def check(path, before, after, changes):
    """Fail unless the only bytes of the dex file that changed are the ones that were meant to, so
    that a write landing anywhere else stops the build rather than leaving a subtly broken dex"""
    if len(before) != len(after):
        fail(f"{path} is {len(after)} bytes after patching instead of {len(before)}")
    # blanking what was meant to change leaves two identical files if nothing else did
    masked = bytearray(before), bytearray(after)
    for start, end in changes:
        for one in masked:
            one[start:end] = bytes(end - start)
    if masked[0] != masked[1]:
        at = next(i for i in range(len(after)) if masked[0][i] != masked[1][i])
        fail(f"patching {path} changed the byte at {at:#x}, which no edit was meant to touch")


def patch(path, dex, edits, matched):
    """Apply the edits to the contents of one dex file, recording where each of them matched, and
    return whether they changed"""
    before = bytes(dex)
    logical = ranges(path, dex)
    starts = [start for start, _ in logical]
    methods, refs = disassemble(path, dex, starts)
    # rather than silently finding nothing to patch if dexdump ever changes how it prints a method
    if methods and not any(method.insns for method in methods):
        fail(f"no instruction of {path} could be read back from its disassembly")

    changes = []
    for i, (op, target, code) in enumerate(edits):
        for method in methods:
            for start, end, match in spans(op, target, method):
                replace(dex, method, refs[method.index], op,
                        match.expand(code) if match else code, start, end, changes)
                matched[i].append((method.name, os.path.basename(path)))

    if changes:
        for start, end in logical:
            # the SHA-1 signature of everything past it up to the end of the logical dex and then
            # the Adler-32 checksum of everything past the checksum, which includes the signature,
            # have to be recomputed, or the runtime rejects the dex
            dex[start + 12:start + 32] = hashlib.sha1(dex[start + 32:end]).digest()
            dex[start + 8:start + 12] = struct.pack("<I", zlib.adler32(dex[start + 12:end]))
            changes += [(start + 8, start + 12), (start + 12, start + 32)]
        check(path, before, dex, changes)
    return bool(changes)


def patch_zip(path, edits, names):
    """Apply the edits to the dex files of a zip, writing back the ones that changed where they are.
    Nothing is written unless every edit matched something, so that a failure leaves the zip alone"""
    matched = [[] for _ in edits]
    # the zip is patched where it is, so it has to be written to even though the file it was copied
    # from can be read-only, as the files of an APEX payload are
    mode = os.stat(path).st_mode
    if not mode & 0o200:
        os.chmod(path, mode | 0o200)
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        found = dexes(path, data)
        if not found:
            fail(f"{path} holds no dex file to patch")

        # dexdump reads the dex file from a path of its own, so each one is written out to be
        # disassembled and then patched as the bytes of the zip rather than as that file
        with tempfile.TemporaryDirectory() as work:
            for name, start, size, crcs in found:
                dex = bytearray(data[start:start + size])
                dump = os.path.join(work, name)
                with open(dump, "wb") as g:
                    g.write(dex)

                if not patch(dump, dex, edits, matched):
                    continue
                data[start:start + size] = dex
                for crc in crcs:
                    struct.pack_into("<I", data, crc, zlib.crc32(dex))

        for (op, _, _), target, where in zip(edits, names, matched):
            if not where and op == "replace-if-found":
                print(f"patch_dex.py: found nothing to patch for {target} in {path}", file=sys.stderr)
                continue
            if not where:
                fail(f"failed to find {target} to patch")
            if op == "method":
                # the name of a method is matched with its package and enclosing classes left out,
                # so more than one match means it now names something else as well
                if len(where) != 1:
                    fail(f"{target} names {count(len(where), 'method')} rather than the one it is "
                         "meant to patch: " + ", ".join(f"{name} in {dex}" for name, dex in where))
                print(f"patch_dex.py: patched {where[0][0]} in {where[0][1]} of {path}", file=sys.stderr)
            else:
                print(f"patch_dex.py: patched {count(len(where), 'instruction run')} in "
                      f"{count(len(set(where)), 'method')} of {path}", file=sys.stderr)

        f.seek(0)
        f.write(data)

    if not mode & 0o200:
        os.chmod(path, mode)


def main():
    if len(sys.argv) != 2:
        fail("usage: patch_dex.py ZIP, with the edits as NUL-separated arguments on stdin")
    args = sys.stdin.buffer.read().decode().split("\0")
    if args and not args[-1]:
        args.pop()
    if len(args) % 3:
        fail("every edit takes three arguments")

    edits = []
    names = []
    for op, target, code in zip(*[iter(args)] * 3):
        if op in ("replace", "replace-if-found"):
            # anchoring to whole lines keeps a match aligned with the instructions it covers
            edits.append((op, re.compile(f"^(?:{target})$", re.MULTILINE), code))
        elif op == "method":
            edits.append((op, target, code))
        else:
            fail(f"unknown edit: {op}")
        names.append(target)

    patch_zip(sys.argv[1], edits, names)


if __name__ == "__main__":
    main()
