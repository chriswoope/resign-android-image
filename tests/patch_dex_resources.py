#!/usr/bin/env python3
"""Checks of the in-place patching of the strings of resources.arsc by patch_dex.py, as the build uses it
to replace the update URL of the Updater, on zips made to be patchable or not."""

from pathlib import Path
import io
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from patch_dex import check_zip

OLD = "https://releases.grapheneos.org/"
NEW = "https://updates.example.invalid/"
RESOURCES = b"\x02\x00\x0c\x00" + OLD.encode() + b"\x00strings" + OLD.encode() + b"api/\x00"


def central_entry(data, name):
    """The offset of the entry of the central directory of the zip data for the file called name."""
    end = data.rfind(b"PK\x05\x06")
    count, = struct.unpack_from("<H", data, end + 10)
    at, = struct.unpack_from("<I", data, end + 16)
    for _ in range(count):
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", data, at + 28)
        if data[at + 46:at + 46 + name_length] == name.encode():
            return at
        at += 46 + name_length + extra_length + comment_length
    raise KeyError(name)


class Unseekable(io.RawIOBase):
    """A file that zipfile can't seek in, so that it writes a data descriptor after each file."""

    def __init__(self, f):
        self.f = f

    def writable(self):
        return True

    def write(self, data):
        return self.f.write(data)


class ResourceString(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make_zip(self, entries, *, descriptor=False):
        """Make a zip of (name, data, compression) entries."""
        path = self.root / f"{len(list(self.root.iterdir()))}.apk"
        with open(path, "wb") as f, warnings.catch_warnings():
            # a duplicate name is what one of the tests is about
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(Unseekable(f) if descriptor else f, "w") as z:
                for name, data, compression in entries:
                    z.writestr(name, data, compress_type=compression)
        return path

    def apk(self, resources=RESOURCES, compression=zipfile.ZIP_STORED, **kwargs):
        return self.make_zip([("AndroidManifest.xml", b"manifest" * 100, zipfile.ZIP_DEFLATED),
                              ("classes.dex", b"dex\n039\0" + bytes(100), zipfile.ZIP_STORED),
                              ("resources.arsc", resources, compression),
                              ("res/layout/main.xml", b"layout" * 100, zipfile.ZIP_DEFLATED)], **kwargs)

    def patch(self, path, *args):
        # as patch_dex_in_zip runs it, with a dexdump that a resource edit must not need
        return subprocess.run([sys.executable, str(REPO / "patch_dex.py"), "/nonexistent/dexdump", str(path)],
                              input=b"".join(arg.encode() + b"\0" for arg in args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assert_fails(self, path, message, *args):
        before = path.read_bytes()
        result = self.patch(path, *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr.decode())
        self.assertEqual(path.read_bytes(), before, "a failed patch must leave the zip as it was")

    def test_replaced_in_place(self):
        path = self.apk()
        before = path.read_bytes()
        result = self.patch(path, "resource-string", OLD, NEW)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("replaced 2 occurrences", result.stderr.decode())
        after = path.read_bytes()

        with zipfile.ZipFile(path) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.read("resources.arsc"), RESOURCES.replace(OLD.encode(), NEW.encode()))
            arsc = z.getinfo("resources.arsc")
            with zipfile.ZipFile(io.BytesIO(before)) as original:
                # every other file is as it was, compressed as it was
                for info in original.infolist():
                    new = z.getinfo(info.filename)
                    self.assertEqual((new.compress_type, new.compress_size, new.header_offset),
                                     (info.compress_type, info.compress_size, info.header_offset))
                    if info.filename != "resources.arsc":
                        self.assertEqual(z.read(info.filename), original.read(info.filename))
        # and the only bytes that changed are those of the strings and the two copies of the CRC-32
        self.assertEqual(len(before), len(after))
        start = arsc.header_offset + 30 + len(arsc.filename) + len(arsc.extra)
        strings = {start + i for i in range(len(RESOURCES)) if before[start + i] != after[start + i]}
        crcs = {at + i for at in (arsc.header_offset + 14, central_entry(after, "resources.arsc") + 16)
                for i in range(4)}
        changed = {i for i in range(len(before)) if before[i] != after[i]}
        self.assertEqual(changed - crcs, strings)
        self.assertTrue(strings and changed & crcs)

    def test_string_missing(self):
        missing = OLD.replace("releases", "reliases")
        self.assert_fails(self.apk(), f"failed to find {missing} to patch", "resource-string", missing, NEW)

    def test_string_of_another_length(self):
        self.assert_fails(self.apk(), "bytes rather than the 32", "resource-string", OLD, NEW + "x")

    def test_empty_string(self):
        self.assert_fails(self.apk(), "an empty string cannot be replaced", "resource-string", "", "")

    def test_no_resources(self):
        path = self.make_zip([("classes.dex", b"dex\n039\0", zipfile.ZIP_STORED)])
        self.assert_fails(path, "has 0 resources.arscs rather than one", "resource-string", OLD, NEW)

    def test_two_resources(self):
        path = self.make_zip([("resources.arsc", RESOURCES, zipfile.ZIP_STORED),
                              ("resources.arsc", RESOURCES, zipfile.ZIP_STORED)])
        self.assert_fails(path, "has 2 resources.arscs rather than one", "resource-string", OLD, NEW)

    def test_compressed_resources(self):
        self.assert_fails(self.apk(compression=zipfile.ZIP_DEFLATED), "resources.arsc is compressed",
                          "resource-string", OLD, NEW)

    def test_data_descriptor(self):
        self.assert_fails(self.apk(descriptor=True), "has its CRC-32 in a data descriptor",
                          "resource-string", OLD, NEW)

    def test_wrong_crc_is_caught(self):
        path = self.apk()
        data = bytearray(path.read_bytes())
        with zipfile.ZipFile(path) as z:
            arsc = z.getinfo("resources.arsc")
        start = arsc.header_offset + 30 + len(arsc.filename) + len(arsc.extra)
        data[start] ^= 1
        path.write_bytes(data)
        with self.assertRaises(SystemExit):
            check_zip(str(path), {})


if __name__ == "__main__":
    unittest.main()
