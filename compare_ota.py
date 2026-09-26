#!/usr/bin/env python3
# The helpers of compare-ota, which recursively compares two OTA packages:
#
#     compare_ota.py step WORK
#         compare WORK/a with WORK/b: hard link each regular file that is the same on both sides (b to
#         a) to save space, and move each one that differs, or is only on one side, and is an archive
#         of a known kind to WORK/.packed/SIDE/PATH, listing it as SIDE/PATH in WORK/todo/KIND,
#         NUL-separated, for compare-ota to unpack all the files of each kind at once; X.m next to an
#         unpacked X.d is the metadata compare-ota wrote, and is left alone
#     compare_ota.py payload-meta PAYLOAD
#         print the header, the manifest (with the operations of each partition counted by type rather
#         than listed) and the signatures of the payload.bin PAYLOAD
#     compare_ota.py ext4-meta IMAGE
#         print the type, mode, owner, SELinux label and capabilities of each file of the ext4 IMAGE
#     compare_ota.py cpio-extract ARCHIVE DIR
#         extract the newc cpio ARCHIVE, such as a ramdisk, into DIR without being root: the device
#         nodes are left out, since only root can make them, and are in the listing of the archive
#     compare_ota.py split-bootconfig RAMDISK BOOTCONFIG
#         write RAMDISK without the bootconfig appended to it, which the decompressors refuse, to
#         stdout, and the bootconfig, if it has one, to the file BOOTCONFIG
#     compare_ota.py dexdump-classes DEXDUMP DEX OUTDIR < CLASSES
#         write the dexdump disassembly of each class of DEX listed in CLASSES (descriptors like
#         Lfoo/Bar;, one per line) to OUTDIR/<descriptor>.txt, without what moves with any change of
#         the dex file elsewhere: the file offsets and the indexes into the pools
#     compare_ota.py restore-packed PACKED DIR
#         hard link back into the extraction directory DIR of another comparison the files of its
#         .packed counterpart PACKED that were moved out of DIR itself, replacing what was unpacked
#         from them, which gives what extracting it again would

import collections
import filecmp
import os
import re
import shutil
import stat
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "extract_android_ota_manifest"))
from target_files_inputs import Ext4, fail

# the kinds of archives, by what the file starts with, and for ext4 and erofs by the magic of their
# superblock at 1024 bytes into the image
MAGICS = (
    (b"dex\n", "dex"),
    (b"CrAU", "payload"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"ANDROID!", "bootimg"),
    (b"VNDRBOOT", "bootimg"),
    (b"AVB0", "vbmeta"),
    (b"\x02\x21\x4c\x18", "lz4"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x1f\x8b", "gzip"),
    (b"070701", "cpio"),
    (b"070702", "cpio"),
)
SUPERBLOCK_MAGICS = ((1080, b"\x53\xef", "ext4"), (1024, b"\xe2\xe1\xf5\xe0", "erofs"))
BOOTCONFIG_MAGIC = b"#BOOTCONFIG\n"


def kind(path):
    with open(path, "rb") as f:
        head = f.read(max(offset + len(magic) for offset, magic, _ in SUPERBLOCK_MAGICS))
    for magic, name in MAGICS:
        if head.startswith(magic):
            return name
    for offset, magic, name in SUPERBLOCK_MAGICS:
        if head[offset:offset + len(magic)] == magic:
            return name
    return None


def step(work):
    def files(side):
        root = os.path.join(work, side)
        found = {}
        for d, dirs, names in os.walk(root):
            for name in names:
                path = os.path.join(d, name)
                if not (name.endswith(".m") and os.path.isdir(path[:-2] + ".d")):
                    found[os.path.relpath(path, root)] = os.lstat(path)
        return found

    a, b = files("a"), files("b")
    todo = collections.defaultdict(list)
    counts = collections.Counter()
    for rel in sorted(a.keys() | b.keys()):
        sa, sb = a.get(rel), b.get(rel)
        pa, pb = os.path.join(work, "a", rel), os.path.join(work, "b", rel)
        if sa and sb:
            if not (stat.S_ISREG(sa.st_mode) and stat.S_ISREG(sb.st_mode)):
                # symbolic links and the like are left for the diff
                continue
            if (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino):
                counts["same"] += 1
                continue
            if sa.st_size == sb.st_size and filecmp.cmp(pa, pb, shallow=False):
                os.link(pa, pb + ".link")
                os.replace(pb + ".link", pb)
                counts["same"] += 1
                continue
        for side, st, path in (("a", sa, pa), ("b", sb, pb)):
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            k = kind(path)
            if k is None:
                counts["differing, left for the diff"] += 1
                continue
            packed = os.path.join(work, ".packed", side, rel)
            os.makedirs(os.path.dirname(packed), exist_ok=True)
            os.rename(path, packed)
            todo[k].append(os.path.join(side, rel))
            counts["to unpack"] += 1

    todo_dir = os.path.join(work, "todo")
    os.makedirs(todo_dir, exist_ok=True)
    for name in os.listdir(todo_dir):
        os.unlink(os.path.join(todo_dir, name))
    for k, rels in todo.items():
        with open(os.path.join(todo_dir, k), "wb") as f:
            f.write(b"".join(os.fsencode(rel) + b"\0" for rel in rels))
    print(", ".join(f"{n} {what}" for what, n in counts.items()), file=sys.stderr)


def payload_meta(path):
    import update_metadata_pb2 as pb
    from google.protobuf import text_format

    with open(path, "rb") as f:
        magic, version, manifest_size, signature_size = struct.unpack(">4sQQI", f.read(24))
        if magic != b"CrAU":
            fail(f"{path} is not a payload")
        manifest = pb.DeltaArchiveManifest.FromString(f.read(manifest_size))
        metadata_signature = pb.Signatures.FromString(f.read(signature_size))
        print(f"version: {version}\nmanifest size: {manifest_size}\nmetadata signature size: {signature_size}")
        # the operations are as many as the blocks of data, and what they write is compared as the
        # extracted images
        for partition in manifest.partitions:
            for field in ("operations", "merge_operations"):
                if field in partition.DESCRIPTOR.fields_by_name:
                    operations = getattr(partition, field)
                    counts = collections.Counter(pb.InstallOperation.Type.Name(o.type) for o in operations)
                    print(f"partition {partition.partition_name} {field}: {len(operations)} {dict(sorted(counts.items()))}")
                    del operations[:]
        print("# manifest")
        print(text_format.MessageToString(manifest), end="")
        print("# metadata signature")
        print(text_format.MessageToString(metadata_signature), end="")
        if manifest.signatures_size:
            f.seek(24 + manifest_size + signature_size + manifest.signatures_offset)
            print("# payload signature")
            print(text_format.MessageToString(pb.Signatures.FromString(f.read(manifest.signatures_size))), end="")


def ext4_meta(image):
    for path, f in sorted(Ext4(image).files().items()):
        print(f"{path!r} {f['type']} {f['mode']:o} {f['uid']}:{f['gid']} {f['label']} caps={f['caps']:#x}")


def cpio_extract(archive, out):
    with open(archive, "rb") as f:
        data = f.read()
    offset = 0
    while True:
        magic = data[offset:offset + 6]
        if magic not in (b"070701", b"070702"):
            fail(f"{archive} has no newc cpio header at {offset}")
        fields = [int(data[offset + 6 + 8 * i:offset + 14 + 8 * i], 16) for i in range(13)]
        mode, nlink, size, name_size = fields[1], fields[4], fields[6], fields[11]
        name_start = offset + 110
        name = os.fsdecode(data[name_start:name_start + name_size - 1])
        start = name_start + name_size + (-(name_start + name_size) % 4)
        contents = data[start:start + size]
        offset = start + size + (-(start + size) % 4)
        if name == "TRAILER!!!":
            return
        parts = name.split("/")
        if name.startswith("/") or ".." in parts:
            fail(f"{archive} has the unsafe path {name}")
        path = os.path.join(out, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # an entry repeated later replaces the earlier one, as when the kernel unpacks a ramdisk, and
        # nothing is written through a symbolic link of an earlier entry
        if os.path.lexists(path) and not (stat.S_ISDIR(mode) and os.path.isdir(path) and not os.path.islink(path)):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        if stat.S_ISDIR(mode):
            os.makedirs(path, exist_ok=True)
        elif stat.S_ISLNK(mode):
            os.symlink(os.fsdecode(contents), path)
        elif stat.S_ISREG(mode):
            if nlink > 1:
                fail(f"{archive} has the hard link {name}, which extracting it doesn't support")
            with open(path, "wb") as f:
                f.write(contents)
        else:
            continue
        if not stat.S_ISLNK(mode):
            os.chmod(path, stat.S_IMODE(mode) | stat.S_IRUSR | (stat.S_IWUSR | stat.S_IXUSR if stat.S_ISDIR(mode) else 0))


def split_bootconfig(ramdisk, out):
    with open(ramdisk, "rb") as f:
        data = f.read()
    if data.endswith(BOOTCONFIG_MAGIC):
        # the bootconfig text is followed by its size and checksum as 32-bit little endian values
        end = len(data) - len(BOOTCONFIG_MAGIC) - 8
        size, checksum = struct.unpack_from("<II", data, end)
        text = data[end - size:end]
        state = "right" if sum(text) & 0xffffffff == checksum else "WRONG"
        with open(out, "wb") as f:
            f.write(text.rstrip(b"\0") + f"\n# size {size}, checksum {checksum:#x} ({state})\n".encode())
        data = data[:end - size]
    sys.stdout.buffer.write(data)


def dexdump_classes(dexdump, dex, out):
    wanted = {line.strip() for line in sys.stdin if line.strip()}
    if not wanted:
        return
    os.makedirs(out, exist_ok=True)
    dump = subprocess.run([dexdump, "-d", dex], check=True, stdout=subprocess.PIPE).stdout.decode(errors="surrogateescape")
    for section in re.split(r"^(?=Class #\d+)", dump, flags=re.M):
        m = re.search(r"^  Class descriptor  : '(.*)'$", section, re.M)
        if not m or m.group(1) not in wanted:
            continue
        section = re.sub(r"^Class #\d+", "Class", section)
        section = re.sub(r"^[0-9a-f]{6}: [^|]*\|", "", section, flags=re.M)
        section = re.sub(r" // (?:method|field|string|type|call_site|method_handle|proto)@[0-9a-f]+", "", section)
        with open(os.path.join(out, m.group(1).replace("/", ".") + ".txt"), "w", errors="surrogateescape") as f:
            f.write(section)
        wanted.remove(m.group(1))
    if wanted:
        fail(f"dexdump found no class {' '.join(sorted(wanted))} in {dex}")


def restore_packed(packed, out):
    files = set()
    for root, dirs, names in os.walk(packed):
        for name in names:
            files.add(os.path.relpath(os.path.join(root, name), packed))

    def nested(path):
        """Whether path was packed from inside the extraction of another packed file, which goes whole"""
        parts = path.split(os.sep)
        return any(parts[i].endswith(".d") and os.sep.join(parts[:i] + [parts[i][:-2]]) in files
                   for i in range(len(parts) - 1))

    for path in sorted(files):
        if nested(path):
            continue
        shutil.rmtree(os.path.join(out, path + ".d"), ignore_errors=True)
        if os.path.lexists(os.path.join(out, path + ".m")):
            os.unlink(os.path.join(out, path + ".m"))
        os.link(os.path.join(packed, path), os.path.join(out, path))


def main(args):
    commands = {
        "step": (1, step),
        "payload-meta": (1, payload_meta),
        "ext4-meta": (1, ext4_meta),
        "cpio-extract": (2, cpio_extract),
        "split-bootconfig": (2, split_bootconfig),
        "dexdump-classes": (3, dexdump_classes),
        "restore-packed": (2, restore_packed),
    }
    if not args or args[0] not in commands or len(args) - 1 != commands[args[0]][0]:
        fail(f"usage: see the start of {sys.argv[0]}")
    commands[args[0]][1](*args[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
