#!/usr/bin/env python3
import argparse
import struct
import sys
import zipfile
from pathlib import Path


def varint(data, pos):
    value = shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ValueError("invalid protobuf varint")


def fields(data):
    """Return {field_number: [(wire_type, value), ...]}."""
    out = {}
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if not number:
            raise ValueError("invalid protobuf field 0")

        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 2:
            size, pos = varint(data, pos)
            value, pos = data[pos:pos + size], pos + size
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")

        if pos > len(data):
            raise ValueError("truncated protobuf field")
        out.setdefault(number, []).append((wire, value))
    return out


def last_int(message, number):
    for wire, value in reversed(message.get(number, [])):
        if wire == 0:
            return value
    return None


def last_bytes(message, number):
    for wire, value in reversed(message.get(number, [])):
        if wire == 2:
            return value
    return None


def all_bytes(message, number):
    return [value for wire, value in message.get(number, []) if wire == 2]


def payload_manifest(path):
    def read_manifest(fp):
        if fp.read(4) != b"CrAU":
            raise ValueError("not an Android payload")
        major = struct.unpack(">Q", fp.read(8))[0]
        size = struct.unpack(">Q", fp.read(8))[0]
        if major >= 2:
            fp.read(4)
        manifest = fp.read(size)
        if len(manifest) != size:
            raise ValueError("truncated payload manifest")
        return manifest

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as ota:
            names = [n for n in ota.namelist()
                     if n == "payload.bin" or n.endswith("/payload.bin")]
            if len(names) != 1:
                raise ValueError(f"expected one payload.bin, found {len(names)}")
            with ota.open(names[0]) as fp:
                return read_manifest(fp)

    with open(path, "rb") as fp:
        return read_manifest(fp)


def yes_no(value):
    return "true" if value else "false"


def add_vabc(lines, meta, include_ublk=False):
    mapping = [
        (2, "virtual_ab", lambda x: yes_no(x)),
        (3, "virtual_ab_compression", lambda x: yes_no(x)),
        (4, "virtual_ab_compression_method",
         lambda x: x.decode("utf-8")),
        (5, "virtual_ab_cow_version", str),
        (7, "virtual_ab_compression_factor", str),
    ]
    for number, key, convert in mapping:
        value = last_bytes(meta, number) if number == 4 else last_int(meta, number)
        if value is not None:
            lines.append(f"{key}={convert(value)}")

    if include_ublk:
        value = last_int(meta, 8)
        if value is not None:
            lines.append(f"disable_ublk={yes_no(value)}")


def main():
    parser = argparse.ArgumentParser(
        description="Create minimal target-files metadata from an OTA payload.")
    parser.add_argument("ota", type=Path, help="OTA ZIP or payload.bin")
    parser.add_argument("-o", "--output", type=Path, default=Path("META"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    manifest = fields(payload_manifest(args.ota))
    # DeltaArchiveManifest.dynamic_partition_metadata = field 15.
    encoded_meta = last_bytes(manifest, 15)
    if encoded_meta is None:
        raise ValueError("payload has no dynamic_partition_metadata")
    meta = fields(encoded_meta)

    groups = []
    dynamic_partitions = []
    for encoded_group in all_bytes(meta, 1):
        group = fields(encoded_group)
        name = last_bytes(group, 1).decode("utf-8")
        size = last_int(group, 2)
        partitions = [p.decode("utf-8") for p in all_bytes(group, 3)]
        groups.append((name, size, partitions))
        for partition in partitions:
            if partition not in dynamic_partitions:
                dynamic_partitions.append(partition)

    misc = [
        "# Minimal fragment reconstructed from payload.bin.",
        "# Merge with your existing synthesized misc_info.txt.",
        "ab_update=true",
        "use_dynamic_partitions=true",
    ]
    add_vabc(misc, meta)

    dynamic = [
        "# Reconstructed from payload.bin.",
        "use_dynamic_partitions=true",
        "lpmake=lpmake",
    ]
    if dynamic_partitions:
        dynamic.append("dynamic_partition_list=" +
                       " ".join(dynamic_partitions))
    if groups:
        dynamic.append("super_partition_groups=" +
                       " ".join(name for name, _, _ in groups))
    for name, size, partitions in groups:
        if size is not None:
            dynamic.append(f"super_{name}_group_size={size}")
        dynamic.append(f"super_{name}_partition_list=" +
                       " ".join(partitions))
    add_vabc(dynamic, meta, include_ublk=True)

    args.output.mkdir(parents=True, exist_ok=True)
    outputs = {
        args.output / "misc_info.txt": "\n".join(misc) + "\n",
        args.output / "dynamic_partitions_info.txt":
            "\n".join(dynamic) + "\n",
    }
    for path, content in outputs.items():
        if path.exists() and not args.force:
            raise FileExistsError(f"{path} exists; use --force")
        path.write_text(content, encoding="utf-8")
        print(f"Wrote {path}")

    if not groups:
        print("Warning: no groups found; this may be a partial OTA.",
              file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
