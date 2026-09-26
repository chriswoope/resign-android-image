"""Validate debugfs extraction against real ext4 images before allowing any modifications."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from target_files_inputs import fs_extracted_verify


class Extraction(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.tree = self.root / "tree"
        self.tree.mkdir()
        (self.tree / "dir").mkdir()
        (self.tree / "dir/file").write_bytes(b"original contents" * 8192)
        (self.tree / "empty").touch()
        (self.tree / "short-link").symlink_to("dir/file")
        (self.tree / "long-link").symlink_to("missing/" * 16)
        self.image = self.root / "image"
        with self.image.open("wb") as f:
            f.truncate(16 * 1024 * 1024)
        contexts = self.root / "contexts"
        contexts.write_text("/.* u:object_r:system_file:s0\n")
        for cmd in (["mke2fs", "-q", "-F", "-t", "ext4", str(self.image)],
                    ["e2fsdroid", "-e", "-S", str(contexts), "-f", str(self.tree), "-a", "/", str(self.image)]):
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_exact_extraction(self):
        extracted = self.root / "extracted"
        extracted.mkdir()
        subprocess.run(["debugfs_static", "-R", f"rdump / {extracted}", str(self.image)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        fs_extracted_verify(self.image, extracted)

    def test_missing_truncated_changed_and_unexpected_files(self):
        for mutation in ("missing", "truncated", "changed", "unexpected", "symlink", "type", "ancestor"):
            tree = self.root / mutation
            shutil.copytree(self.tree, tree, symlinks=True)
            file = tree / "dir/file"
            if mutation == "missing":
                file.unlink()
            elif mutation == "truncated":
                file.write_bytes(b"short")
            elif mutation == "changed":
                file.write_bytes(b"x" * file.stat().st_size)
            elif mutation == "unexpected":
                (tree / "extra").touch()
            elif mutation == "symlink":
                (tree / "short-link").unlink()
                (tree / "short-link").symlink_to("empty")
            elif mutation == "type":
                file.unlink()
                file.symlink_to(self.tree / "dir/file")
            else:
                shutil.rmtree(tree / "dir")
                (tree / "dir").symlink_to(self.tree / "dir", target_is_directory=True)
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                fs_extracted_verify(self.image, tree)


if __name__ == "__main__":
    unittest.main()
