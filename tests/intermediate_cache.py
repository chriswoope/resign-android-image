"""A discarded intermediate tree must regain configs even when fs_expected survives."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class IntermediateCache(unittest.TestCase):
    def test_recreate_configs_with_existing_expectations(self):
        script = (Path(__file__).resolve().parents[1] / "resign-android-image").read_text()
        names = ("with_temp", "make_any", "make_any_unlocked", "make_dir", "make_file",
                 "make_target_files_intermediates")
        functions = "\n".join(re.search(r"^function " + name + r"\s*\{.*?^\}", script,
                                          re.M | re.S)[0] for name in names)
        with tempfile.TemporaryDirectory() as tmp:
            # Stub the expensive producers; run the real intermediate lifecycle and cache helpers.
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + functions + r'''
outdir=$1/out
dir=$1
var_dir=$1/shared
build_method=resign
make_indent=
keep_tmp=
timing=
replace_boot=
otatools=$1/tools
mkdir -p "$outdir" "$dir/ota_payload" "$otatools/bin"
printf '#!/bin/bash\nexit 0\n' > "$otatools/bin/avbtool"
chmod +x "$otatools/bin/avbtool"
function make_target_files_intermediates_base { mkdir "$1/META"; }
function make_certs_mac { touch "$1"; }
function make_certs { touch "$1"; }
function make_product_security { :; }
function make_apk_keys { touch "$1/apkcerts.txt" "$1/apexkeys.txt"; }
function make_hardlink { ln "$2" "$1"; }
function make_dynamic_partitions_info { touch "$1"; }
function make_otakeys { touch "$1"; }
function make_update_engine_config { touch "$1"; }
function get_avbtool_partitions { :; }
function make_fs_config {
    printf expected > "$1/vendor.json"
    printf config > "$outdir/target_files_intermediates/META/vendor_filesystem_config.txt"
    printf contexts > "$outdir/target_files_intermediates/META/file_contexts.bin"
}
function make_misc_info { touch "$1"; }
make_file "$outdir/target_files_intermediates.done" make_target_files_intermediates
rm -r "$outdir/target_files_intermediates" "$outdir/target_files_intermediates.done"
test -e "$outdir/fs_expected/vendor.json"
make_file "$outdir/target_files_intermediates.done" make_target_files_intermediates
test -s "$outdir/target_files_intermediates/META/vendor_filesystem_config.txt"
test -s "$outdir/target_files_intermediates/META/file_contexts.bin"
''', "test", tmp], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
