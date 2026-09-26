#!/usr/bin/env python3
"""Recover target-files super geometry from verified factory images, including split sparse images.

Usage: super_geometry.py OTATOOLS FACTORY_IMAGE_DIRECTORY
Only metadata is read; the sparse images are not expanded or copied.
"""

from contextlib import ExitStack
import hashlib
from pathlib import Path
import re
import struct
import sys

# system/core/fs_mgr/liblp/include/liblp/metadata_format.h
LP_RESERVED = 4096
LP_GEOMETRY_SIZE = 4096
LP_GEOMETRY_MAGIC = 0x616c4467
LP_HEADER_MAGIC = 0x414c5030
LP_SECTOR_SIZE = 512
SPARSE_MAGIC = 0xed26ff3a


def super_geometry(tools, directory):
    # Reuse the sparse reader shipped with the same Android tools that build the images.
    sys.path.insert(0, str(Path(tools) / "releasetools"))
    from sparse_img import SparseImage
    from rangelib import RangeSet

    directory = Path(directory)
    images = sorted(directory.glob("super_[0-9]*.img"))
    if (directory / "super.img").exists():
        if images:
            raise ValueError("factory images contain both super.img and split super images")
        images = [directory / "super.img"]
    elif not images and (directory / "super_empty.img").exists():
        images = [directory / "super_empty.img"]
    elif not images or {p.name for p in images} != {f"super_{i}.img" for i in range(1, len(images) + 1)}:
        raise ValueError("factory images have no complete sequence of super images")

    with ExitStack() as stack:
        sources = []
        for path in images:
            f = stack.enter_context(path.open("rb"))
            if f.read(4) == struct.pack("<I", SPARSE_MAGIC):
                sparse = SparseImage(str(path))
                stack.callback(sparse.simg_f.close)
                sources.append(sparse)
            else:
                if len(images) != 1:
                    raise ValueError("split super images must be sparse")
                sources.append(f)

        def read(offset, size):
            data = bytearray(size)
            covered = bytearray(size)
            for source in sources:
                if not isinstance(source, SparseImage):
                    source.seek(offset)
                    contents = source.read(size)
                    if len(contents) != size:
                        raise ValueError("truncated super metadata")
                    return contents
                block = source.blocksize
                ranges = RangeSet(data=(offset // block, (offset + size + block - 1) // block))
                for start, end in ranges.intersect(source.care_map):
                    contents = b"".join(source.ReadBlocks(start, end - start))
                    if len(contents) != (end - start) * block:
                        raise ValueError("truncated sparse super metadata")
                    low, high = max(offset, start * block), min(offset + size, end * block)
                    contents = contents[low - start * block:high - start * block]
                    low, high = low - offset, high - offset
                    if any(covered[i] and data[i] != contents[i - low] for i in range(low, high)):
                        raise ValueError("split super images have conflicting metadata")
                    data[low:high] = contents
                    covered[low:high] = b"\1" * (high - low)
            if not all(covered):
                raise ValueError("super metadata is missing from the sparse images")
            return bytes(data)

        # Older factory zips ship a compact super_empty.img: one geometry block and one metadata
        # header, without the reserved block or the backups of a flashable super image.
        compact = len(sources) == 1 and not isinstance(sources[0], SparseImage) and read(0, 4) == struct.pack("<I", LP_GEOMETRY_MAGIC)
        geometry = read(0 if compact else LP_RESERVED, LP_GEOMETRY_SIZE)
        magic, size = struct.unpack_from("<II", geometry)
        if magic != LP_GEOMETRY_MAGIC or size != 52:
            raise ValueError("unsupported super geometry header")
        geometry = geometry[:size]
        if hashlib.sha256(geometry[:8] + bytes(32) + geometry[40:]).digest() != geometry[8:40]:
            raise ValueError("bad super geometry checksum")
        if not compact and read(LP_RESERVED + LP_GEOMETRY_SIZE, size) != geometry:
            raise ValueError("super geometry copies disagree")
        metadata_size, slots, block_size = struct.unpack_from("<III", geometry, 40)
        # build_super_image fixes these for A/B images. Reject layouts it cannot reproduce.
        if (metadata_size, slots, block_size) != (65536, 3, 4096):
            raise ValueError(f"build_super_image cannot reproduce super geometry {(metadata_size, slots, block_size)}")

        offset = LP_GEOMETRY_SIZE if compact else LP_RESERVED + 2 * LP_GEOMETRY_SIZE
        header = read(offset, 128)
        magic, major, minor, header_size = struct.unpack_from("<IHHI", header)
        if magic != LP_HEADER_MAGIC or major != 10 or minor > 2 or header_size not in (128, 256):
            raise ValueError("unsupported super metadata header")
        header = read(offset, header_size)
        if hashlib.sha256(header[:12] + bytes(32) + header[44:]).digest() != header[12:44]:
            raise ValueError("bad super metadata header checksum")
        tables_size, = struct.unpack_from("<I", header, 44)
        if header_size + tables_size > metadata_size:
            raise ValueError("super metadata tables exceed their reserved space")
        tables = read(offset + header_size, tables_size)
        if hashlib.sha256(tables).digest() != header[48:80]:
            raise ValueError("bad super metadata tables checksum")
        start, count, entry_size = struct.unpack_from("<III", header, 116)
        if not count or entry_size != 64 or start + count * entry_size > len(tables):
            raise ValueError("invalid super block-device table")
        devices = {}
        for i in range(count):
            first, alignment, alignment_offset, size, name, flags = struct.unpack_from(
                "<QIIQ36sI", tables, start + i * entry_size)
            name = name.rstrip(b"\0").decode("ascii")
            if not re.fullmatch(r"[a-zA-Z0-9_]+", name) or name in devices or flags:
                raise ValueError("unsupported super block-device name or flags")
            # build_super_image passes only the size to lpmake, which uses its default alignment.
            if alignment != 1024 * 1024 or alignment_offset != 0:
                raise ValueError(f"build_super_image cannot reproduce the alignment of {name}")
            reserved = LP_RESERVED + 2 * LP_GEOMETRY_SIZE + 2 * slots * metadata_size if i == 0 else LP_SECTOR_SIZE
            expected_first = ((reserved + alignment - 1) // alignment) * alignment // LP_SECTOR_SIZE
            if first != expected_first or size <= first * LP_SECTOR_SIZE or size % block_size:
                raise ValueError(f"unsupported super block-device bounds for {name}")
            devices[name] = size

    return {"super_metadata_device": next(iter(devices)), "super_block_devices": " ".join(devices),
            "super_partition_size": sum(devices.values()),
            **{f"super_{name}_device_size": size for name, size in devices.items()}}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: super_geometry.py OTATOOLS FACTORY_IMAGE_DIRECTORY")
    try:
        for key, value in super_geometry(*sys.argv[1:]).items():
            print(f"{key}={value}")
    except (OSError, ValueError, struct.error) as error:
        sys.exit(f"super_geometry.py: {error}")
