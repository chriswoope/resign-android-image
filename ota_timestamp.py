#!/usr/bin/env python3
import argparse
import sys
import zipfile
from pathlib import Path

from ota_protobuf import fields, last_bytes, last_int

METADATA = "META-INF/com/android/metadata"


def timestamp_from_text(data):
    for line in data.decode("utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "post-timestamp":
            return int(value.strip())
    return None


def timestamp_from_proto(data):
    # OtaMetadata.postcondition = field 6, DeviceState.timestamp = field 4.
    postcondition = last_bytes(fields(data), 6)
    if postcondition is None:
        return None
    return last_int(fields(postcondition), 4)


def main():
    parser = argparse.ArgumentParser(
        description="Print the build timestamp of an Android OTA ZIP, that is "
                    "the ro.build.date.utc of the build it installs.")
    parser.add_argument("ota", type=Path, help="OTA ZIP")
    args = parser.parse_args()

    # The protobuf metadata is only a fallback: the legacy text one is still
    # written by ota_from_target_files and is the authoritative copy for the
    # updaters that read it.
    sources = [
        (METADATA, timestamp_from_text),
        (METADATA + ".pb", timestamp_from_proto),
    ]
    with zipfile.ZipFile(args.ota) as ota:
        names = set(ota.namelist())
        for name, extract in sources:
            if name not in names:
                continue
            timestamp = extract(ota.read(name))
            if timestamp is not None:
                print(timestamp)
                return

    raise ValueError("OTA has no metadata with a post-timestamp")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
