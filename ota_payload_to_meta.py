#!/usr/bin/env python3
import argparse
import sys
import zipfile
from pathlib import Path

from ota_protobuf import all_bytes, fields, last_bytes, last_int, payload_manifest


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
        "ab_update=true",
        "use_dynamic_partitions=true",
    ]
    add_vabc(misc, meta)

    dynamic = [
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
