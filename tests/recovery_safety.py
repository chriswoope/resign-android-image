#!/usr/bin/env python3
"""Recovery safety regressions. Run with the otatools bin directory on PATH."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from target_files_inputs import boot_verify


class BootVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.original = self.make_image("original", {"init": b"original init", "other": b"unchanged"})

    def make_image(self, name, files, *, kernel=b"kernel", cmdline="", mode=0o644, corrupt=False):
        work = self.root / name
        work.mkdir()
        tree = work / "tree"
        tree.mkdir()
        for path, contents in files.items():
            target = tree / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
            target.chmod(mode)
        config = work / "fs_config"
        config.write_text(" 0 0 755\n" + "".join(f"{path} 0 0 {mode:o}\n" for path in files))
        archive = subprocess.run(["mkbootfs", "-f", str(config), str(tree)], check=True,
                                 stdout=subprocess.PIPE).stdout
        compressed = subprocess.run(["lz4", "-l", "-c"], input=archive, check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        (work / "ramdisk").write_bytes(b"broken ramdisk" if corrupt else compressed)
        (work / "kernel").write_bytes(kernel)
        image = work / "boot.img"
        subprocess.run(["mkbootimg", "--header_version", "4", "--kernel", str(work / "kernel"),
                        "--ramdisk", str(work / "ramdisk"), "--cmdline", cmdline, "--output", str(image)],
                       check=True, stdout=subprocess.DEVNULL)
        return str(image)

    def test_identical_and_corrupt(self):
        boot_verify(self.original, self.original, set())
        corrupt = self.make_image("corrupt", {"init": b"original init", "other": b"unchanged"}, corrupt=True)
        with self.assertRaises(SystemExit):
            boot_verify(corrupt, self.original, set(), allow_new_files=True)

    def test_changes_require_exact_allowlist(self):
        changed = self.make_image("changed", {"init": b"modified init", "other": b"unchanged"})
        for allowed, new_files in [(set(), False), ({b"ini*"}, False), (set(), True)]:
            with self.subTest(allowed=allowed, new_files=new_files), self.assertRaises(SystemExit):
                boot_verify(changed, self.original, allowed, allow_additions=True, allow_new_files=new_files)
        boot_verify(changed, self.original, {b"init"}, allow_additions=True)

    def test_additions(self):
        added = self.make_image("added", {"init": b"original init", "other": b"unchanged", "new": b"new"})
        for allowed, additions in [(set(), True), ({b"new"}, False)]:
            with self.subTest(allowed=allowed), self.assertRaises(SystemExit):
                boot_verify(added, self.original, allowed, allow_additions=additions)
        boot_verify(added, self.original, {b"new"}, allow_additions=True)
        boot_verify(added, self.original, set(), allow_new_files=True)

    def test_deletion_metadata_kernel_and_header_stay_protected(self):
        variants = [
            ("removed", {"other": b"unchanged"}, {}),
            ("metadata", {"init": b"original init", "other": b"unchanged"}, {"mode": 0o755}),
            ("kernel", {"init": b"original init", "other": b"unchanged"}, {"kernel": b"another kernel"}),
            ("header", {"init": b"original init", "other": b"unchanged"}, {"cmdline": "init=/wrong"}),
        ]
        for name, files, options in variants:
            with self.subTest(name=name), self.assertRaises(SystemExit):
                boot_verify(self.make_image(name, files, **options), self.original, {b"init", b"other"},
                            allow_additions=True, allow_new_files=True)


if __name__ == "__main__":
    unittest.main()
