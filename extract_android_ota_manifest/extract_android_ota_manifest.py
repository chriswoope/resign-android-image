#!/usr/bin/env python3

# Write to the directory OUT (the current one by default) the ab_partitions.txt and
# postinstall_config.txt of the target files that the payload of the OTA zip, or the payload.bin, OTA
# was made from, as its manifest has them.
#
# Usage: extract_android_ota_manifest.py OTA [OUT]

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from ota_protobuf import all_bytes, fields, last_bytes, last_int, payload_manifest

# the fields of DeltaArchiveManifest and of PartitionUpdate in update_metadata.proto of update_engine
MANIFEST_PARTITIONS = 13
PARTITION_NAME = 1
RUN_POSTINSTALL = 2
POSTINSTALL_PATH = 3
FILESYSTEM_TYPE = 4
POSTINSTALL_OPTIONAL = 9


def main(ota, out):
    partitions = [fields(partition) for partition in all_bytes(fields(payload_manifest(ota)), MANIFEST_PARTITIONS)]
    os.makedirs(out, exist_ok=True)

    with open(os.path.join(out, "ab_partitions.txt"), "w") as f:
        for partition in partitions:
            print(last_bytes(partition, PARTITION_NAME).decode(), file=f)

    # what the payload runs once it is written, as the build tells it to the payload generator, in lines
    # that only hold a value without whitespace or backslashes as it is
    with open(os.path.join(out, "postinstall_config.txt"), "w") as f:
        for partition in partitions:
            if last_int(partition, RUN_POSTINSTALL):
                name, path, filesystem = ((last_bytes(partition, number) or b"").decode()
                                          for number in (PARTITION_NAME, POSTINSTALL_PATH, FILESYSTEM_TYPE))
                if not (re.fullmatch(r"[a-z0-9_]+", name) and re.fullmatch(r"[^\s\\]+", path)
                        and re.fullmatch(r"[a-z0-9]+", filesystem)):
                    sys.exit(f"Unexpected postinstall of {name!r}: {path!r} {filesystem!r}")
                print(f"RUN_POSTINSTALL_{name}=true", file=f)
                print(f"POSTINSTALL_PATH_{name}={path}", file=f)
                print(f"FILESYSTEM_TYPE_{name}={filesystem}", file=f)
                print(f"POSTINSTALL_OPTIONAL_{name}={'true' if last_int(partition, POSTINSTALL_OPTIONAL) else 'false'}",
                      file=f)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(f"Usage: {sys.argv[0]} OTA [OUT]")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else os.getcwd())
