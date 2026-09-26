#!/usr/bin/env python3
"""Recovery safety regressions. Run with the otatools bin directory on PATH, as tests/run unit does."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from target_files_inputs import boot_verify, recovery_cert_check


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

    def test_replaced_contents_must_be_exact(self):
        changed = self.make_image("changed", {"init": b"modified init", "other": b"unchanged"})
        boot_verify(changed, self.original, set(), replaced={b"init": b"modified init"})
        for replaced in [{b"init": b"other init"}, {b"init": b"modified init", b"missing": b""}]:
            with self.subTest(replaced=replaced), self.assertRaises(SystemExit):
                boot_verify(changed, self.original, set(), replaced=replaced)

    def test_additions(self):
        added = self.make_image("added", {"init": b"original init", "other": b"unchanged", "new": b"new"})
        for allowed, additions in [(set(), True), ({b"new"}, False)]:
            with self.subTest(allowed=allowed), self.assertRaises(SystemExit):
                boot_verify(added, self.original, allowed, allow_additions=additions)
        boot_verify(added, self.original, {b"new"}, allow_additions=True)
        boot_verify(added, self.original, set(), allow_new_files=True)

    def test_new_files_cannot_replace_those_of_the_ramdisks_loaded_along(self):
        # like the recovery in the ramdisk of vendor_boot, which that of boot is unpacked over
        recovery = self.make_image("recovery", {"new": b"recovery"})
        added = self.make_image("added", {"init": b"original init", "other": b"unchanged", "new": b"new"})
        with self.assertRaises(SystemExit):
            boot_verify(added, self.original, set(), allow_new_files=True, loaded_with=[recovery])
        boot_verify(added, self.original, {b"new"}, allow_additions=True, allow_new_files=True,
                    loaded_with=[recovery])

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


    def test_ramdisk_file_must_be_in_a_single_ramdisk(self):
        other = self.make_image("other", {"otacerts.zip": b"certificates"})
        script = Path(__file__).resolve().parents[1] / "target_files_inputs.py"

        def ramdisk_file(*images):
            return subprocess.run([sys.executable, str(script), "ramdisk-file", "otacerts.zip", *images],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        self.assertEqual(ramdisk_file(self.original, other).stdout, b"certificates")
        for images in [(self.original,), (other, other)]:
            with self.subTest(images=images):
                self.assertNotEqual(ramdisk_file(*images).returncode, 0)


class RecoveryCertificate(unittest.TestCase):
    def test_supported_and_unsupported_certificates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bits, exponent, supported in [(2048, 65537, True), (4096, 3, True),
                                               (2048, 17, False), (3072, 65537, False)]:
                key = root / f"{bits}-{exponent}.pem"
                subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}",
                                "-pkeyopt", f"rsa_keygen_pubexp:{exponent}", "-out", str(key)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for digest in ("sha256", "sha384"):
                    cert = root / "cert.pem"
                    subprocess.run(["openssl", "req", "-new", "-x509", f"-{digest}", "-key", str(key),
                                    "-out", str(cert), "-subj", "/CN=recovery-test/"],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    with self.subTest(bits=bits, exponent=exponent, digest=digest):
                        if supported and digest == "sha256":
                            recovery_cert_check(str(cert))
                        else:
                            with self.assertRaises(SystemExit):
                                recovery_cert_check(str(cert))


if __name__ == "__main__":
    unittest.main()
