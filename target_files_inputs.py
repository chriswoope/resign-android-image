#!/usr/bin/env python3

# Reconstruct, from the images of an Android build, the inputs that the standard Android image building
# code (add_img_to_target_files.py, which sign_target_files_apks.py runs at the end of signing) builds
# them from in target files, so that the images can be rebuilt from their files as a normal build
# does rather than patched in place. Since the images of a release are built this way, whatever the
# target files can't express can't be in them, and it is an error rather than something silently
# dropped if it is.
#
# Usage:
#     target_files_inputs.py fs-dump IMAGE
#         print the metadata of every file of the ext4 IMAGE as JSON, read from the image itself so
#         that nothing needs to be mounted
#     target_files_inputs.py fs-config TARGET_FILES EXPECTED PARTITION METADATA [PARTITION METADATA...]
#         write the META/*filesystem_config.txt and META/file_contexts.bin to build each PARTITION
#         from the files in the TARGET_FILES directory with, and write to the EXPECTED directory the
#         metadata the files of each built image are expected to have: a file that METADATA, the dump
#         of the original image, has keeps the metadata it had there, and any other file gets the
#         default owner, mode and capabilities that the build would give it, and the label the policy
#         gives it
#     target_files_inputs.py fs-verify IMAGE EXPECTED
#         check that the files of the built IMAGE have exactly the metadata in the EXPECTED file
#     target_files_inputs.py boot-inputs OUT PARTITION IMAGE [PARTITION IMAGE...]
#         write to OUT/target_files the BOOT, INIT_BOOT and VENDOR_BOOT directories and the META files
#         that the boot images IMAGE of each PARTITION (boot, init_boot or vendor_boot) are built from,
#         to OUT/misc_info.txt the misc_info.txt entries they are built with, and to OUT/expected what
#         the built images are expected to be like. A boot image without a ramdisk is left to be used
#         as a prebuilt one, as it is by a normal build
#     target_files_inputs.py boot-verify IMAGE EXPECTED
#         check that the built boot IMAGE has exactly the header, the kernel, the other files and the
#         names and metadata of the files in its ramdisks described in the EXPECTED file
#     target_files_inputs.py avb-args PARTITION IMAGE
#         print the misc_info.txt entries that make the build add the same AVB hash or hashtree footer
#         to PARTITION as the one IMAGE has
#     target_files_inputs.py apk-keys TARGET_FILES CERTS META
#         write to the META directory the apkcerts.txt and apexkeys.txt files naming the key that
#         each APK and APEX in the TARGET_FILES directory, and each APK in the payload of an APEX, is
#         to be signed with: the one whose certificate it is signed with in the CERTS file, or none if
#         it is signed with a key that isn't there, to leave it signed as it is, and the tool that
#         signs the files in the payload of an APEX that are signed with its payload key with the
#         payload key the APEX is signed with, if it has any
#     target_files_inputs.py stale-preopt TARGET_FILES PATCHED [PATCHED...]
#         remove from the TARGET_FILES directory, printing each of them, the files that dexpreopt
#         compiled that are stale once the dex code of the APKs and jars at the paths PATCHED in it has
#         been changed, which go on into the payload of an APEX if a directory in them is an APEX file:
#         the compiled code of the files themselves and of everything compiled against them, and the
#         whole boot image if any of it is stale, for the device to compile them again
#     target_files_inputs.py apex-verify ORIGINAL SIGNED
#         check that each APEX that the ORIGINAL target files zip gives a sign tool for has, in the
#         SIGNED target files zip, a payload with the same type of filesystem and the same files in it
#         signed with its payload key as the original one
#
# The SELinux labels of the files of a filesystem image come from the file_contexts of the SELinux
# policy in the image, which is what a normal build labels the files with, so that files added to the
# image are labeled as the policy says. A file of the original image is checked to get back the label
# it had, which it does unless its image wasn't labeled by a normal build with the same policy.

import functools
import glob
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

from ota_protobuf import fields, last_bytes

# the partitions whose images are built from a directory of the target files with the same name in
# upper case and are mounted at the directory of their own name, with the system one holding the root
PARTITIONS = ("system", "vendor", "product", "system_ext", "odm", "vendor_dlkm", "odm_dlkm", "system_dlkm")

# where the file_contexts of each part of the SELinux policy is in the target files, with the path it
# has in a device that doesn't have a partition for it, in the order the build concatenates them in
# (system/sepolicy/Android.bp): those of the platform as they are, and then those of the device sorted
# with fc_sort, which matters since the last of the entries that match a path is the one that counts
PLATFORM_FILE_CONTEXTS = (
    ("SYSTEM/etc/selinux/plat_file_contexts",),
    ("SYSTEM_EXT/etc/selinux/system_ext_file_contexts", "SYSTEM/system_ext/etc/selinux/system_ext_file_contexts"),
    ("PRODUCT/etc/selinux/product_file_contexts", "SYSTEM/product/etc/selinux/product_file_contexts"),
)
DEVICE_FILE_CONTEXTS = (
    ("VENDOR/etc/selinux/vendor_file_contexts", "SYSTEM/vendor/etc/selinux/vendor_file_contexts"),
    ("ODM/etc/selinux/odm_file_contexts", "VENDOR/odm/etc/selinux/odm_file_contexts"),
)

EXT4_MAGIC = 0xEF53
EROFS_MAGIC = 0xE0F5E1E2
EXT4_ROOT_INO = 2

INCOMPAT_FILETYPE = 0x2
INCOMPAT_EXTENTS = 0x40
INCOMPAT_64BIT = 0x80
INCOMPAT_MMP = 0x100
INCOMPAT_FLEX_BG = 0x200
INCOMPAT_CSUM_SEED = 0x2000
INCOMPAT_INLINE_DATA = 0x8000
# the incompatible features that don't change how the metadata read here is laid out
INCOMPAT_SUPPORTED = (INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_MMP | INCOMPAT_FLEX_BG
                      | INCOMPAT_CSUM_SEED | INCOMPAT_INLINE_DATA)

EXTENTS_FL = 0x80000
INLINE_DATA_FL = 0x10000000
EXTENT_MAGIC = 0xF30A
XATTR_MAGIC = 0xEA020000
XATTR_PREFIXES = {1: b"user.", 2: b"system.posix_acl_access", 3: b"system.posix_acl_default", 4: b"trusted.",
                  6: b"security.", 7: b"system.", 8: b"system.richacl"}

XATTR_SELINUX = b"security.selinux"
XATTR_CAPABILITY = b"security.capability"
XATTR_INLINE_DATA = b"system.data"
VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_FLAGS_EFFECTIVE = 0x1


def fail(message):
    sys.exit(f"{sys.argv[0]}: {message}")


class Ext4:
    """The files of an ext4 image, read straight out of the image, which starts at offset in the file."""

    def __init__(self, path, offset=0):
        self.path = path
        self.image = open(path, "rb")
        self.offset = offset
        sb = self.read(1024, 1024)
        if struct.unpack_from("<H", sb, 0x38)[0] != EXT4_MAGIC:
            fail(f"{path} is not an ext4 image")
        self.block_size = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] if struct.unpack_from("<I", sb, 0x4C)[0] else 128
        incompat = struct.unpack_from("<I", sb, 0x60)[0]
        if incompat & ~INCOMPAT_SUPPORTED:
            fail(f"{path} uses the unsupported incompatible ext4 features {incompat & ~INCOMPAT_SUPPORTED:#x}")
        self.filetype = incompat & INCOMPAT_FILETYPE
        self.desc_size = 32
        if incompat & INCOMPAT_64BIT:
            self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0]
        groups = -(-struct.unpack_from("<I", sb, 0x0)[0] // self.inodes_per_group)
        self.descs = self.read((first_data_block + 1) * self.block_size, groups * self.desc_size)

    def read(self, offset, size):
        self.image.seek(self.offset + offset)
        data = self.image.read(size)
        if len(data) != size:
            fail(f"{self.path} is truncated")
        return data

    def inode(self, ino):
        group, index = divmod(ino - 1, self.inodes_per_group)
        desc = self.descs[group * self.desc_size:(group + 1) * self.desc_size]
        table = struct.unpack_from("<I", desc, 0x8)[0]
        if self.desc_size >= 64:
            table |= struct.unpack_from("<I", desc, 0x28)[0] << 32
        return self.read(table * self.block_size + index * self.inode_size, self.inode_size)

    def xattrs(self, ino, raw):
        xattrs = {}
        if self.inode_size > 128:
            start = 128 + struct.unpack_from("<H", raw, 0x80)[0]
            if start + 4 <= len(raw) and struct.unpack_from("<I", raw, start)[0] == XATTR_MAGIC:
                # the values of the attributes in the inode are at offsets from the first entry
                self.xattr_entries(ino, raw, start + 4, start + 4, xattrs)
        block = struct.unpack_from("<I", raw, 0x68)[0] | struct.unpack_from("<H", raw, 0x76)[0] << 32
        if block:
            data = self.read(block * self.block_size, self.block_size)
            if struct.unpack_from("<I", data, 0)[0] != XATTR_MAGIC:
                fail(f"{self.path}: inode {ino} has a corrupt extended attribute block")
            # the entries in a block follow its 32 byte header and their values are at offsets from it
            self.xattr_entries(ino, data, 32, 0, xattrs)
        return xattrs

    def xattr_entries(self, ino, data, offset, values, xattrs):
        while offset + 4 <= len(data) and struct.unpack_from("<I", data, offset)[0]:
            name_len, index, value_offset, value_inum, value_size = struct.unpack_from("<BBHII", data, offset)
            if index not in XATTR_PREFIXES or value_inum:
                fail(f"{self.path}: inode {ino} has an unsupported extended attribute")
            name = XATTR_PREFIXES[index] + data[offset + 16:offset + 16 + name_len]
            xattrs[name] = data[values + value_offset:values + value_offset + value_size]
            offset += (16 + name_len + 3) & ~3

    def extents(self, ino, node):
        magic, entries, _, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != EXTENT_MAGIC:
            fail(f"{self.path}: inode {ino} has a corrupt extent tree")
        for i in range(entries):
            entry = 12 + 12 * i
            if depth:
                leaf = struct.unpack_from("<I", node, entry + 4)[0] | struct.unpack_from("<H", node, entry + 8)[0] << 32
                yield from self.extents(ino, self.read(leaf * self.block_size, self.block_size))
            else:
                logical, length, start_hi, start_lo = struct.unpack_from("<IHHI", node, entry)
                yield logical, length, start_hi << 32 | start_lo

    @staticmethod
    def size(raw):
        """The size of the file whose inode is raw."""
        return struct.unpack_from("<I", raw, 0x4)[0] | struct.unpack_from("<I", raw, 0x6C)[0] << 32

    def data(self, ino, raw, offset=0, size=None):
        """The contents of the file with inode number ino, which must not be stored inline, or the at
        most size bytes of them at offset."""
        flags = struct.unpack_from("<I", raw, 0x20)[0]
        if flags & INLINE_DATA_FL:
            fail(f"{self.path}: the contents of inode {ino} are inline, which is not supported")
        if not flags & EXTENTS_FL:
            fail(f"{self.path}: inode {ino} uses block maps, which are not supported")
        end = self.size(raw) if size is None else min(offset + size, self.size(raw))
        data = bytearray(max(end - offset, 0))
        for logical, length, start in self.extents(ino, raw[0x28:0x28 + 60]):
            # an uninitialized extent, whose length has the top bit set, reads as zeroes
            if length <= 32768:
                low = max(offset, logical * self.block_size)
                high = min(end, (logical + length) * self.block_size)
                if low < high:
                    data[low - offset:high - offset] = self.read(start * self.block_size + low - logical * self.block_size,
                                                                 high - low)
        return bytes(data)

    def dir_entries(self, ino, raw, xattrs):
        """The names and inode numbers of the entries of the directory with inode number ino."""
        if struct.unpack_from("<I", raw, 0x20)[0] & INLINE_DATA_FL:
            # the inode holds the number of the parent directory and then the first entries, and the
            # rest of the entries are in an extended attribute
            regions = [raw[0x28 + 4:0x28 + 60], xattrs.get(XATTR_INLINE_DATA, b"")]
        else:
            data = self.data(ino, raw)
            regions = [data[i:i + self.block_size] for i in range(0, len(data), self.block_size)]
        for region in regions:
            offset = 0
            while offset + 8 <= len(region):
                entry_ino, rec_len = struct.unpack_from("<IH", region, offset)
                name_len = region[offset + 6] if self.filetype else struct.unpack_from("<H", region, offset + 6)[0]
                if rec_len < 8 or offset + rec_len > len(region) or 8 + name_len > rec_len:
                    fail(f"{self.path}: directory inode {ino} is corrupt")
                name = region[offset + 8:offset + 8 + name_len]
                # the entries of the tree of an indexed directory and the checksums of the blocks are
                # hidden in entries with no inode
                if entry_ino and name not in (b".", b".."):
                    yield name, entry_ino
                offset += rec_len

    def metadata(self, ino, raw, xattrs):
        mode = struct.unpack_from("<H", raw, 0x0)[0]
        if stat.S_ISDIR(mode):
            kind = "d"
        elif stat.S_ISREG(mode):
            kind = "f"
        elif stat.S_ISLNK(mode):
            kind = "l"
        else:
            fail(f"{self.path}: inode {ino} is of an unsupported type {mode:#o}")

        caps = 0
        for name, value in xattrs.items():
            if name == XATTR_SELINUX:
                if not value.endswith(b"\0") or b"\0" in value[:-1]:
                    fail(f"{self.path}: inode {ino} has a malformed SELinux label {value!r}")
            elif name == XATTR_CAPABILITY:
                # only the capabilities the build can set can be carried over: effective and
                # permitted ones, with no inheritable ones, as a revision 2 attribute
                if len(value) != 20:
                    fail(f"{self.path}: inode {ino} has unsupported capabilities {value.hex()}")
                magic, permitted_lo, inheritable_lo, permitted_hi, inheritable_hi = struct.unpack("<5I", value)
                caps = permitted_hi << 32 | permitted_lo
                if (magic != VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE or inheritable_lo or inheritable_hi
                        or not caps):
                    fail(f"{self.path}: inode {ino} has unsupported capabilities {value.hex()}")
            elif not (name == XATTR_INLINE_DATA and struct.unpack_from("<I", raw, 0x20)[0] & INLINE_DATA_FL):
                fail(f"{self.path}: inode {ino} has an unsupported extended attribute {name!r}")
        if XATTR_SELINUX not in xattrs:
            fail(f"{self.path}: inode {ino} has no SELinux label")

        return {
            "type": kind,
            "uid": struct.unpack_from("<H", raw, 0x2)[0] | struct.unpack_from("<H", raw, 0x78)[0] << 16,
            "gid": struct.unpack_from("<H", raw, 0x18)[0] | struct.unpack_from("<H", raw, 0x7A)[0] << 16,
            "mode": stat.S_IMODE(mode),
            "caps": caps,
            "label": os.fsdecode(xattrs[XATTR_SELINUX][:-1]),
        }

    def walk(self):
        """The path relative to the root, which is "" itself, the inode number, the inode and the
        metadata of every file."""
        paths = {}
        pending = [("", EXT4_ROOT_INO)]
        while pending:
            path, ino = pending.pop()
            if ino in paths:
                fail(f"{self.path}: /{path} is a hard link to /{paths[ino]}, which target files cannot hold")
            paths[ino] = path
            raw = self.inode(ino)
            xattrs = self.xattrs(ino, raw)
            metadata = self.metadata(ino, raw, xattrs)
            yield path, ino, raw, metadata
            if metadata["type"] == "d":
                for name, entry_ino in self.dir_entries(ino, raw, xattrs):
                    # mke2fs creates lost+found in every image it builds
                    if path == "" and name == b"lost+found":
                        continue
                    pending.append((os.path.join(path, os.fsdecode(name)), entry_ino))

    def files(self):
        """The metadata of every file, by path relative to the root."""
        return {path: metadata for path, _, _, metadata in self.walk()}


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
# the IDs of the blocks of the APK signature schemes v2, v3 and v3.1 in the APK signing block
APK_SIGNATURE_SCHEMES = (0x7109871A, 0xF05368C0, 0x1B93AD61)

# where the keys named in apkcerts.txt and apexkeys.txt are, which the signing maps to the keys it
# signs with
KEY_PATH = "build/make/target/product/security/"

# the tool that signs the files in the payload of an APEX that are signed with its payload key, which
# only those of the virt APEX are: the images of the protected VMs, which pvmfw verifies with the key
PAYLOAD_SIGN_TOOL = "sign_virt_apex"

AVB_MAGIC = b"AVB0"
AVB_HEADER_SIZE = 256
AVB_FOOTER_MAGIC = b"AVBf"
AVB_FOOTER_SIZE = 64


def length_prefixed(data):
    """The items of a sequence of items prefixed by their 32 bit length, as the APK signing block holds."""
    offset = 0
    while offset < len(data):
        size = struct.unpack_from("<I", data, offset)[0]
        if offset + 4 + size > len(data):
            raise ValueError("truncated length-prefixed item")
        yield data[offset + 4:offset + 4 + size]
        offset += 4 + size


def apk_certificates(name, apk):
    """The DER certificate that the APK or APEX whose contents are apk is signed with."""
    eocd = apk.rfind(b"PK\x05\x06", max(0, len(apk) - 65536 - 22))
    if eocd < 0:
        fail(f"{name} is not a zip file")
    central_directory = struct.unpack_from("<I", apk, eocd + 16)[0]
    certificates = set()
    # the signing block of the schemes from v2 on, which ends with its size and its magic right
    # before the central directory
    if central_directory >= 24 and apk[central_directory - 16:central_directory] == APK_SIG_BLOCK_MAGIC:
        block_size = struct.unpack_from("<Q", apk, central_directory - 24)[0]
        pairs = apk[central_directory - block_size:central_directory - 24]
        offset = 0
        while offset < len(pairs):
            size, scheme = struct.unpack_from("<QI", pairs, offset)
            if scheme in APK_SIGNATURE_SCHEMES:
                # a sequence of signers, each starting with the signed data, which holds the digests
                # and then the certificates, the first of which is the one of the signer
                for signers in length_prefixed(pairs[offset + 12:offset + 8 + size]):
                    for signer in length_prefixed(signers):
                        signed_data = length_prefixed(next(length_prefixed(signer)))
                        next(signed_data)
                        certificates.add(next(length_prefixed(next(signed_data))))
            offset += 8 + size
    if not certificates:
        # only signed with the JAR signing of v1, whose signature is a PKCS #7 one
        with zipfile.ZipFile(io.BytesIO(apk)) as z:
            for entry in z.namelist():
                if re.fullmatch(r"META-INF/[^/]*\.(RSA|DSA|EC)", entry):
                    der = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-outform", "DER"],
                                         input=z.read(entry), check=True, stdout=subprocess.PIPE).stdout
                    certificates.add(der)
    if len(certificates) != 1:
        fail(f"{name} is signed with {len(certificates)} certificates rather than one")
    return certificates.pop()


def zip_member(path, member, tmp):
    """The path and the offset in it of the contents of member of the zip file at path, extracted to a
    file in tmp unless stored uncompressed."""
    with zipfile.ZipFile(path) as z:
        info = z.getinfo(member)
        if info.compress_type == zipfile.ZIP_STORED:
            with open(path, "rb") as f:
                f.seek(info.header_offset)
                header = f.read(30)
            name_size, extra_size = struct.unpack_from("<HH", header, 26)
            return path, info.header_offset + 30 + name_size + extra_size
        return z.extract(info, tempfile.mkdtemp(dir=tmp)), 0


def read_file(path, offset=0, size=None):
    """The contents of the file at path, or the at most size bytes of them at offset."""
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def apex_payload(apex, tmp):
    """The public key of the payload of the APEX or compressed APEX apex, the type of its filesystem,
    and the path, the size and a function reading the contents like read_file of every regular file in
    it."""
    with zipfile.ZipFile(apex) as z:
        # a compressed APEX holds the original one as a whole
        if "original_apex" in z.namelist():
            apex = z.extract("original_apex", tempfile.mkdtemp(dir=tmp))
    with zipfile.ZipFile(apex) as z:
        public_key = z.read("apex_pubkey")
    image, offset = zip_member(apex, "apex_payload.img", tmp)
    with open(image, "rb") as f:
        f.seek(offset + 1024)
        superblock = f.read(1024)
    if struct.unpack_from("<H", superblock, 0x38)[0] == EXT4_MAGIC:
        payload = Ext4(image, offset)
        return public_key, "ext4", [(path, payload.size(raw), functools.partial(payload.data, ino, raw))
                                    for path, ino, raw, metadata in payload.walk() if metadata["type"] == "f"]
    if struct.unpack_from("<I", superblock, 0)[0] == EROFS_MAGIC:
        out = tempfile.mkdtemp(dir=tmp)
        if offset:
            with zipfile.ZipFile(apex) as z:
                image = z.extract("apex_payload.img", out)
        subprocess.run(["fsck.erofs", f"--extract={out}/payload", image], check=True, stdout=subprocess.DEVNULL)
        files = []
        for root, _, names in os.walk(out + "/payload"):
            for name in names:
                path = os.path.join(root, name)
                if stat.S_ISREG(os.lstat(path).st_mode):
                    files.append((os.path.relpath(path, out + "/payload"), os.path.getsize(path),
                                  functools.partial(read_file, path)))
        return public_key, "erofs", files
    fail(f"the payload of {apex} is neither an ext4 nor an erofs image")


def avb_public_key(name, size, read):
    """The public key that the file name of size bytes, whose contents are read like read_file, is
    signed with by AVB as a vbmeta image or as an image with an AVB footer, empty if its vbmeta is
    unsigned, or None if it is neither."""
    if size >= len(AVB_MAGIC) and read(0, len(AVB_MAGIC)) == AVB_MAGIC:
        vbmeta = 0
    elif size >= AVB_FOOTER_SIZE and (footer := read(size - AVB_FOOTER_SIZE)).startswith(AVB_FOOTER_MAGIC):
        # after the magic, the version and the size of the image
        vbmeta = struct.unpack_from(">Q", footer, 20)[0]
    else:
        return None
    header = read(vbmeta, AVB_HEADER_SIZE)
    if len(header) != AVB_HEADER_SIZE or not header.startswith(AVB_MAGIC):
        fail(f"{name} has an AVB footer that doesn't point to a vbmeta")
    # the key is in the auxiliary data block, which follows the header and the authentication one
    authentication_size = struct.unpack_from(">Q", header, 12)[0]
    key_offset, key_size = struct.unpack_from(">QQ", header, 64)
    return read(vbmeta + AVB_HEADER_SIZE + authentication_size + key_offset, key_size)


def payload_key_signed(apex, public_key, files):
    """The paths of the files, as apex_payload gives them, in the payload of the APEX apex that are
    signed with its payload key public_key."""
    return sorted(path for path, size, read in files if avb_public_key(f"{apex}:{path}", size, read) == public_key)


def apk_keys(target_files, certs, meta):
    """Write to the directory meta the apkcerts.txt and apexkeys.txt files of the target files
    directory target_files, which name the key that each APK and APEX has been signed with, as found
    by the certificate it is signed with in the certs file, whose lines hold the SHA-256 digest of a
    certificate, the certificate and the name of its key."""
    keys = {}
    with open(certs) as f:
        for line in f:
            digest, _, key = line.split()
            keys[digest] = key

    apks = {}
    apexes = {}
    # the APEXes with files in their payload signed with the payload key, which the signing signs with
    # the payload key it signs the APEX with only if given the tool to
    payload_signed = set()

    def add(found, name, where, apk):
        key = keys.get(hashlib.sha256(apk_certificates(where, apk)).hexdigest())
        if found.setdefault(name, (key, where))[0] != key:
            fail(f"{where} and {found[name][1]} have the same name but are signed with different keys, "
                 "which target files cannot hold")

    with tempfile.TemporaryDirectory() as tmp:
        for root, dirs, names in os.walk(target_files):
            dirs.sort()
            for name in sorted(names):
                path = os.path.join(root, name)
                if name.endswith((".apex", ".capex")):
                    # the signing names a compressed APEX after the APEX it holds
                    apex_name = re.sub(r"\.capex$", ".apex", name)
                    with open(path, "rb") as f:
                        add(apexes, apex_name, path, f.read())
                    public_key, _, files = apex_payload(path, tmp)
                    if payload_key_signed(path, public_key, files):
                        payload_signed.add(apex_name)
                    for inner, _, read in files:
                        if inner.endswith(".apk"):
                            add(apks, os.path.basename(inner), f"{path}:{inner}", read())
                elif name.endswith(".apk"):
                    with open(path, "rb") as f:
                        add(apks, name, path, f.read())

    # an APK or APEX signed with any other key is left signed as it is
    def certificate(prefix, key, presigned_private_key):
        if key is None:
            return f'{prefix}certificate="PRESIGNED" {prefix}private_key="{presigned_private_key}"'
        return f'{prefix}certificate="{KEY_PATH}{key}.x509.pem" {prefix}private_key="{KEY_PATH}{key}.pk8"'

    with text(os.path.join(meta, "apkcerts.txt"), "w") as f:
        for name, (key, _) in sorted(apks.items()):
            f.write(f'name="{name}" {certificate("", key, "")} partition=""\n')
    with text(os.path.join(meta, "apexkeys.txt"), "w") as f:
        for name, (key, _) in sorted(apexes.items()):
            # the payload keys are the ones the release script gives for each APEX
            sign_tool = f' sign_tool="{PAYLOAD_SIGN_TOOL}"' if name in payload_signed else ""
            f.write(f'name="{name}" public_key="apk_dummy_public_key" private_key="apk_dummy_private_key" '
                    f'{certificate("container_", key, "PRESIGNED")} partition=""{sign_tool}\n')


def apex_verify(original, signed):
    """Check that each APEX that apexkeys.txt in the original target files zip gives a sign tool for
    has, in the signed target files zip, a payload with the same type of filesystem and the same files
    in it signed with its payload key as the original one."""
    with (zipfile.ZipFile(original) as before, zipfile.ZipFile(signed) as after,
          tempfile.TemporaryDirectory() as tmp):
        names = set()
        for line in before.read("META/apexkeys.txt").decode("utf-8", "surrogateescape").splitlines():
            if match := re.fullmatch(r'name="(.*?)" .* sign_tool=".*"', line):
                names.add(match[1])
        for member in before.namelist():
            if member.endswith((".apex", ".capex")) and re.sub(r"\.capex$", ".apex", os.path.basename(member)) in names:
                payloads = []
                for z in before, after:
                    public_key, fs_type, files = apex_payload(z.extract(member, tempfile.mkdtemp(dir=tmp)), tmp)
                    payloads.append((fs_type, payload_key_signed(f"{z.filename}:{member}", public_key, files)))
                if payloads[0] != payloads[1]:
                    fail(f"{member} has a signed {payloads[1][0]} payload with {payloads[1][1]} signed with its "
                         f"payload key rather than an {payloads[0][0]} one with {payloads[0][1]}")


def apex_name(apex):
    """The name of the APEX or compressed APEX apex, which its payload is mounted at /apex/ after."""
    with zipfile.ZipFile(apex) as z:
        # a compressed APEX holds the original one as a whole
        if "original_apex" in z.namelist():
            with zipfile.ZipFile(io.BytesIO(z.read("original_apex"))) as original:
                manifest = original.read("apex_manifest.pb")
        else:
            manifest = z.read("apex_manifest.pb")
    name = last_bytes(fields(manifest), 1)
    if not name:
        fail(f"{apex} has no name in its manifest")
    return os.fsdecode(name)


def device_path(target_files, path):
    """The path on the device of the file at path in the target files directory target_files, which
    goes on into the payload of an APEX if a directory in it is an APEX file."""
    parts = path.split("/")
    for i in range(2, len(parts)):
        apex = os.path.join(target_files, *parts[:i])
        if os.path.isfile(apex):
            return "/".join(["/apex", apex_name(apex), *parts[i:]])
    if parts[0].lower() not in PARTITIONS or len(parts) < 2:
        fail(f"{path} is not in the directory of a partition")
    return "/".join(["", parts[0].lower(), *parts[1:]])


# the files that dexpreopt compiles the dex code of an APK or jar into: the compiled code, its dex code
# (unless left in the APK or jar) and verification data, and the app image of its classes
PREOPT_EXTENSIONS = (".odex", ".vdex", ".art")


def stale_preopt(target_files, patched):
    """Remove from the target files directory target_files the files compiled by dexpreopt that the
    dex code of the files at the paths patched in it, which go on into the payload of an APEX as for
    device_path, being changed makes stale, printing each of them, so that the runtime and odrefresh
    compile them again on the device rather than reject them, or worse use them."""
    remove = {}
    locations = []
    for path in patched:
        location = device_path(target_files, path)
        locations.append(location)
        # where ART looks for the files compiled from it: the system server jars of APEXes are
        # compiled into the framework directory of the partition of the APEX, named after their
        # path with the directories flattened
        if location.startswith("/apex/"):
            patterns = [os.path.join(glob.escape(os.path.join(target_files, partition.upper(), "framework", "oat")),
                                     "*", glob.escape(location[1:].replace("/", "@") + "@classes"))
                        for partition in PARTITIONS]
        else:
            directory, name = os.path.split(os.path.join(target_files, path))
            patterns = [os.path.join(glob.escape(directory), "oat", "*", glob.escape(os.path.splitext(name)[0]))]
        for pattern in patterns:
            for extension in PREOPT_EXTENSIONS:
                for artifact in glob.glob(pattern + extension):
                    remove.setdefault(artifact, f"compiled from {location}")

    # compiled code records by their location on the device the dex files it was compiled against (the
    # boot classpath, with the checksums of the boot image, and the class loader context, with the
    # checksums of its dex files) and its own ones, so it is stale if it names a patched file. Its
    # verification data doesn't depend on anything but its own dex code, which the runtime falls back
    # to once the compiled code is gone
    boot_image = []
    for partition in PARTITIONS:
        for root, dirs, names in os.walk(os.path.join(target_files, partition.upper())):
            for name in names:
                path = os.path.join(root, name)
                # the .oat files are those of the boot image, the others being .odex ones
                if not name.endswith((".odex", ".oat")) or os.path.islink(path):
                    continue
                if name.endswith(".oat"):
                    boot_image.append(path)
                data = read_file(path)
                found = next((location for location in locations if os.fsencode(location) in data), None)
                if found:
                    for artifact in path, os.path.splitext(path)[0] + ".art":
                        if os.path.lexists(artifact):
                            remove.setdefault(artifact, f"compiled against {found}")

    # the boot image is loaded, and compiled again by odrefresh, as a whole, and its vdex files are in
    # the directory above that of the files of each instruction set, which link to them
    stale_boot_image = [path for path in boot_image if path in remove]
    if stale_boot_image:
        reason = "in the boot image with " + device_path(target_files, os.path.relpath(stale_boot_image[0], target_files))
        for path in boot_image:
            base = os.path.splitext(path)[0]
            for artifact in path, base + ".art", base + ".vdex":
                if os.path.lexists(artifact):
                    remove.setdefault(artifact, reason)
                    if os.path.islink(artifact):
                        target = os.path.join(os.path.dirname(artifact), os.readlink(artifact))
                        remove.setdefault(os.path.normpath(target), reason)

    for artifact, reason in sorted(remove.items()):
        relative = os.path.relpath(artifact, target_files)
        print(f"Removing stale {device_path(target_files, relative)}, {reason}")
        # along with the fs-verity metadata of it that the build makes
        for path in artifact, artifact + ".fsv_meta":
            if os.path.lexists(path):
                os.unlink(path)
        # and the directories that only held compiled files, as a build that doesn't compile them has
        # none of
        top = os.path.join(target_files, relative.split("/")[0])
        directory = os.path.dirname(artifact)
        while directory != top and not os.listdir(directory):
            os.rmdir(directory)
            directory = os.path.dirname(directory)


def partition_prefix(partition):
    """The path the files of the image of a partition have in the fs_config and file_contexts."""
    return "" if partition == "system" else partition


def join(prefix, path):
    return prefix + "/" + path if prefix and path else prefix or path


def unjoin(prefix, path):
    """The path relative to the root of the image of a file whose path in the fs_config is path."""
    if not prefix:
        return path
    return "" if path == prefix else path[len(prefix) + 1:]


def text(path, mode="r"):
    """Open a text file that holds file names, which can be any bytes."""
    return open(path, mode, encoding="utf-8", errors="surrogateescape")


def fs_dump(image):
    json.dump(Ext4(image).files(), sys.stdout, sort_keys=True)


def avb_args(partition, image):
    """The misc_info.txt entries that make the build add the same AVB footer to partition as image has."""
    info = subprocess.run(["avbtool", "info_image", "--image", image], check=True, stdout=subprocess.PIPE,
                          text=True).stdout
    fields = dict(re.findall(r"^\s*([A-Za-z ]+):\s+(.*)$", info, re.M))
    props = [arg for name, value in re.findall(r"^\s+Prop: (.*?) -> '(.*)'$", info, re.M)
             for arg in ("--prop", f"{name}:{value}")]
    descriptors = re.findall(r"^    (\S.*) descriptor:$", info, re.M)
    if any(value != "0" for value in re.findall(r"^\s*(?:Flags|Rollback Index):\s+(.*)$", info, re.M)):
        fail(f"{image} has an AVB footer with flags or a rollback index, which the build doesn't give it")
    if descriptors == ["Hashtree"]:
        if fields["Data Block Size"] != "4096 bytes" or fields["Hash Block Size"] != "4096 bytes":
            fail(f"{image} has an AVB hashtree with a block size other than 4096")
        args = ["--hash_algorithm", fields["Hash Algorithm"]]
        if fields["FEC num roots"] == "0":
            args.append("--do_not_generate_fec")
        else:
            args += ["--fec_num_roots", fields["FEC num roots"]]
        return [f"avb_{partition}_hashtree_enable=true",
                f"avb_{partition}_add_hashtree_footer_args={shlex.join(args + props)}",
                f"avb_{partition}_salt={fields['Salt']}"]
    if descriptors == ["Hash"]:
        # the build only gives the images with a hash footer a salt of their own through their arguments
        args = ["--hash_algorithm", fields["Hash Algorithm"], "--salt", fields["Salt"]]
        return [f"avb_{partition}_add_hash_footer_args={shlex.join(args + props)}",
                f"{partition}_size={fields['Image size'].split()[0]}"]
    fail(f"{image} has an AVB footer with descriptors {descriptors} rather than a single hash or hashtree one")


def tree_files(target_files, partition):
    """The type of each of the files that are going to be in the image of a partition, by the path
    they have in the fs_config."""
    prefix = partition_prefix(partition)
    trees = [(prefix, os.path.join(target_files, partition.upper()))]
    if partition == "system":
        # the system image of a system-as-root device is the root filesystem, with the system
        # partition in it at /system, which build_image.py builds out of ROOT and then SYSTEM
        trees = [("", os.path.join(target_files, "ROOT")), ("system", os.path.join(target_files, "SYSTEM"))]
    files = {}
    for tree_prefix, tree in trees:
        if not os.path.isdir(tree):
            fail(f"{tree} is missing")
        for top, dirs, names in os.walk(tree):
            rel = os.path.relpath(top, tree)
            base = join(tree_prefix, "" if rel == "." else rel)
            if top == tree:
                # ROOT holds the directory that SYSTEM goes in
                if partition == "system" and tree_prefix == "" and "system" in dirs:
                    dirs.remove("system")
                entries = [(base, top)]
            else:
                entries = []
            if base == prefix and "lost+found" in dirs:
                # mke2fs creates it
                dirs.remove("lost+found")
            entries += [(join(base, name), os.path.join(top, name)) for name in dirs + names]
            for path, host_path in entries:
                if re.search(r"[\x00-\x20\x7f]", path):
                    fail(f"{path!r} cannot be written in a fs_config or file_contexts file")
                mode = os.lstat(host_path).st_mode
                if stat.S_ISDIR(mode):
                    files[path] = "d"
                elif stat.S_ISREG(mode):
                    files[path] = "f"
                elif stat.S_ISLNK(mode):
                    files[path] = "l"
                else:
                    fail(f"{host_path} is of an unsupported type")
    return files


def policy_file_contexts(target_files, parts):
    """The paths of the file_contexts of the parts of the policy in target_files that it has."""
    paths = []
    for candidates in parts:
        found = [p for p in (os.path.join(target_files, c) for c in candidates) if os.path.exists(p)]
        paths += found[:1]
    return paths


def fs_config_name(partition, path):
    if partition != "system":
        return partition + "_filesystem_config.txt"
    if path == "system" or path.startswith("system/"):
        return "filesystem_config.txt"
    return "root_filesystem_config.txt"


def fs_config(target_files, expected_dir, partitions):
    meta = os.path.join(target_files, "META")
    with tempfile.TemporaryDirectory() as tmp:
        parts = policy_file_contexts(target_files, PLATFORM_FILE_CONTEXTS)
        if not parts or not parts[0].endswith("/plat_file_contexts"):
            fail(f"{target_files} has no plat_file_contexts")
        device = policy_file_contexts(target_files, DEVICE_FILE_CONTEXTS)
        if device:
            parts.append(os.path.join(tmp, "device_file_contexts"))
            subprocess.run(["fc_sort", "-i", *device, "-o", parts[-1]], check=True)
        policy = os.path.join(tmp, "file_contexts")
        with open(policy, "wb") as f:
            # with a newline after each file, in case one doesn't end with one, as the build does
            f.writelines(read_file(path) + b"\n" for path in parts)
        subprocess.run(["sefcontext_compile", "-o", os.path.join(meta, "file_contexts.bin"), policy], check=True)

        # fs_config reads the device specific defaults from the etc/fs_config_* files of each
        # partition, which it looks for next to the directory of the system partition it is given
        out = os.path.join(tmp, "out")
        os.mkdir(out)
        for partition in PARTITIONS:
            tree = os.path.abspath(os.path.join(target_files, partition.upper()))
            if os.path.isdir(tree):
                os.symlink(tree, os.path.join(out, partition))

        files = {}
        originals = {}
        for partition, metadata in partitions:
            files[partition] = tree_files(target_files, partition)
            with open(metadata) as f:
                originals.update((join(partition_prefix(partition), path), m) for path, m in json.load(f).items())

        # the metadata that a file the original image doesn't have gets by default, as the build
        # computes it, with a directory told apart by a slash
        paths = [(path, kind) for partition in files for path, kind in sorted(files[partition].items())]
        listing = "".join(path + "/" * (kind == "d") + "\n" for path, kind in paths)
        output = subprocess.run(["fs_config", "-C", "-D", os.path.join(out, "system"), "-R", ""],
                                input=os.fsencode(listing), check=True, stdout=subprocess.PIPE).stdout
        lines = os.fsdecode(output).splitlines()
        if len(lines) != len(paths):
            fail("fs_config did not print a line for each file")
        defaults = {}
        for (path, _), line in zip(paths, lines):
            # the path goes first, and a path has no spaces
            fields = line.split(" ")[1:]
            attrs = dict(f.split("=", 1) for f in fields[3:])
            defaults[path] = {"uid": int(fields[0]), "gid": int(fields[1]), "mode": int(fields[2], 8),
                              "caps": int(attrs["capabilities"], 16)}

        fs_configs = {}
        for partition in files:
            prefix = partition_prefix(partition)
            expected = {}
            for path, kind in files[partition].items():
                original = originals.get(path)
                if original and original["type"] == kind:
                    m = {k: original[k] for k in ("uid", "gid", "mode", "caps", "label")}
                else:
                    m = defaults[path]
                expected[path] = dict(m, type=kind)
                # e2fsdroid looks the root of every image up by an empty path, and every other file by
                # the path it has on the device
                fs_configs.setdefault(fs_config_name(partition, path), []).append(
                    f"{'' if path == prefix else path} {m['uid']} {m['gid']} {m['mode']:o} "
                    f"capabilities={m['caps']:#x}\n")

            with open(os.path.join(expected_dir, partition + ".json"), "w") as f:
                json.dump({unjoin(prefix, path): m for path, m in expected.items()}, f, sort_keys=True)

        for name, lines in fs_configs.items():
            with text(os.path.join(meta, name), "w") as f:
                f.writelines(sorted(lines))


def fs_verify(image, expected_path):
    with open(expected_path) as f:
        expected = json.load(f)
    actual = Ext4(image).files()
    errors = []
    for path in sorted(expected.keys() | actual.keys()):
        if path not in actual:
            errors.append(f"/{path} is missing")
        elif path not in expected:
            errors.append(f"/{path} should not be there")
        # a file with no expected label, which the original image doesn't have, gets the one the
        # policy gives it, as it does in a normal build
        elif {k: v for k, v in actual[path].items() if k in expected[path]} != expected[path]:
            errors.append(f"/{path} is {actual[path]} rather than {expected[path]}")
    if errors:
        fail(f"{image} doesn't hold the expected files:\n" + "\n".join(errors))


# the boot image files that unpack_bootimg writes out, as the options of mkbootimg that take them
BOOT_FILE_OPTIONS = ("--kernel", "--ramdisk", "--dtb", "--vendor_bootconfig", "--vendor_ramdisk",
                     "--vendor_ramdisk_fragment")
RAMDISK_OPTIONS = ("--ramdisk", "--vendor_ramdisk", "--vendor_ramdisk_fragment")
# the options of mkbootimg that describe the ramdisk that follows them in a vendor boot image
FRAGMENT_OPTIONS = re.compile(r"--ramdisk_type|--ramdisk_name|--board_id[0-9]+")
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
CPIO_TRAILER = b"TRAILER!!!"


def unpack_boot_image(image, out):
    """The mkbootimg options that image was made with, as unpack_bootimg writes them out to out."""
    args = subprocess.run(["unpack_bootimg", "--boot_img", image, "--out", out, "--format", "mkbootimg"],
                          check=True, stdout=subprocess.PIPE, text=True).stdout
    info = subprocess.run(["unpack_bootimg", "--boot_img", image, "--out", out + ".info"], check=True,
                          stdout=subprocess.PIPE, text=True).stdout
    # a GKI boot image is certified by a signature that only a prebuilt image can carry
    if re.search(r"^boot\.img signature size: (?!0$)", info, re.M):
        fail(f"{image} has a boot signature, which target files can only hold in a prebuilt image")
    tokens = shlex.split(args)
    return list(zip(tokens[::2], tokens[1::2]))


def cpio_entries(ramdisk):
    """The entries of the newc cpio archive in the lz4 compressed ramdisk, as the name, mode, uid, gid,
    device major and minor numbers and contents of each."""
    with open(ramdisk, "rb") as f:
        if f.read(4) != LZ4_LEGACY_MAGIC:
            fail(f"{ramdisk} is not a ramdisk compressed with lz4 as the build compresses them")
    data = subprocess.run(["lz4", "-d", "-c", ramdisk], check=True, stdout=subprocess.PIPE).stdout
    entries = []
    offset = 0
    while True:
        header = data[offset:offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            fail(f"{ramdisk} is not a newc cpio archive")
        ino, mode, uid, gid, nlink, mtime, size, dev_major, dev_minor, rdev_major, rdev_minor, name_size, _ = (
            int(header[6 + 8 * i:14 + 8 * i], 16) for i in range(13))
        name = data[offset + 110:offset + 110 + name_size - 1]
        offset = (offset + 110 + name_size + 3) & ~3
        contents = data[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == CPIO_TRAILER:
            return entries
        entries.append((name, mode, uid, gid, rdev_major, rdev_minor, contents))


def ramdisk_metadata(ramdisk):
    return [[os.fsdecode(name), mode, uid, gid, rdev_major, rdev_minor]
            for name, mode, uid, gid, rdev_major, rdev_minor, _ in cpio_entries(ramdisk)]


def describe_boot_image(image, tmp):
    """What a built boot image must be the same as the original in: its header, the contents of its
    files and the names and metadata of the files in its ramdisks, whose contents may have changed."""
    out = os.path.join(tmp, "unpacked")
    description = []
    for option, value in unpack_boot_image(image, out):
        if option in RAMDISK_OPTIONS:
            value = ramdisk_metadata(value)
        elif option in BOOT_FILE_OPTIONS:
            with open(value, "rb") as f:
                value = hashlib.sha256(f.read()).hexdigest()
        description.append([option, value])
    return description


def extract_ramdisk(ramdisk, tree, nodes_allowed):
    """Extract the files of the ramdisk to tree, as the directory that mkbootfs is given, and return
    the lines of the fs_config that mkbootfs takes the metadata of the files from and of the node list
    of the entries that it adds of its own."""
    entries = cpio_entries(ramdisk)
    # mkbootfs writes out the entries of the node list first, and then the files in the directory it
    # is given, sorted as it walks the directory, so the files are the longest run of entries at the end
    # in that order that follows every device node
    key = [tuple(name.split(b"/")) for name, *_ in entries]
    first_file = len(entries)
    while first_file > 0 and (first_file == len(entries) or key[first_file - 1] < key[first_file]):
        first_file -= 1
    for i, (_, mode, *_) in enumerate(entries):
        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            first_file = max(first_file, i + 1)
    if first_file and not nodes_allowed:
        fail(f"{ramdisk} has device nodes, which target files can only hold in an init_boot ramdisk")

    os.makedirs(tree)
    fs_config = {}
    nodes = []
    for i, (name, mode, uid, gid, rdev_major, rdev_minor, contents) in enumerate(entries):
        parts = name.split(b"/")
        if not name or any(part in (b"", b".", b"..") for part in parts):
            fail(f"{ramdisk} holds a file named {name!r}")
        if re.search(rb"[\x00-\x20\x7f]", name):
            fail(f"{ramdisk} holds {name!r}, which cannot be written in a fs_config file")
        path = os.fsdecode(name)
        line = f"{path} {uid} {gid} {stat.S_IMODE(mode):o}\n"
        if fs_config.setdefault(path, line) != line:
            fail(f"{ramdisk} holds /{path} twice with different metadata")
        host_path = os.path.join(tree, *map(os.fsdecode, parts))
        if i < first_file:
            if stat.S_ISDIR(mode):
                nodes.append(f"dir {path} {stat.S_IMODE(mode):04o} {uid} {gid}\n")
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                kind = "c" if stat.S_ISCHR(mode) else "b"
                nodes.append(f"nod {path} {stat.S_IMODE(mode):04o} {uid} {gid} {kind} {rdev_major} {rdev_minor}\n")
            else:
                fail(f"{ramdisk} holds /{path} among the entries of the node list")
        elif os.path.lexists(host_path):
            fail(f"{ramdisk} holds /{path} twice")
        elif stat.S_ISDIR(mode):
            os.mkdir(host_path)
        elif stat.S_ISREG(mode):
            with open(host_path, "wb") as f:
                f.write(contents)
        elif stat.S_ISLNK(mode):
            os.symlink(contents, host_path)
        else:
            fail(f"{ramdisk} holds /{path}, which is of an unsupported type {mode:#o}")
    # mkbootfs looks the root up too, although it doesn't write it out
    return [" 0 0 755\n"] + sorted(fs_config.values()), nodes


def boot_inputs(out, partitions):
    target_files = os.path.join(out, "target_files")
    meta = os.path.join(target_files, "META")
    expected = os.path.join(out, "expected")
    os.makedirs(meta)
    os.makedirs(expected)
    misc_info = []
    shared = {}

    def share(key, value, image):
        """Set a misc_info.txt entry that more than one image is built with."""
        if shared.setdefault(key, (value, image))[0] != value:
            fail(f"{image} and {shared[key][1]} would need different {key}: {value} and {shared[key][0]}")

    with tempfile.TemporaryDirectory() as tmp:
        for partition, image in partitions:
            unpacked = os.path.join(tmp, partition)
            options = unpack_boot_image(image, unpacked)
            values = dict(options)
            tree = os.path.join(target_files, partition.upper())
            misc_info += avb_args(partition, image)

            if partition in ("boot", "init_boot"):
                known = ("--header_version", "--os_version", "--os_patch_level", "--kernel", "--ramdisk", "--cmdline")
                unknown = [option for option, _ in options if option not in known]
                if unknown:
                    fail(f"{image} is made with {' '.join(unknown)}, which target files cannot hold")
                if os.path.getsize(values["--ramdisk"]) == 0:
                    if partition == "init_boot":
                        fail(f"{image} has no ramdisk")
                    # like a GKI boot image, which a normal build takes as a prebuilt one
                    continue
                if partition == "init_boot" and (os.path.getsize(values["--kernel"]) or values["--cmdline"]):
                    fail(f"{image} has a kernel or a command line, which the build doesn't give an init_boot image")
                fs_config, nodes = extract_ramdisk(values["--ramdisk"], os.path.join(tree, "RAMDISK"),
                                                   partition == "init_boot")
                with text(os.path.join(meta, partition + "_filesystem_config.txt"), "w") as f:
                    f.writelines(fs_config)
                if nodes:
                    with text(os.path.join(meta, "ramdisk_node_list"), "w") as f:
                        f.writelines(nodes)
                if os.path.getsize(values["--kernel"]):
                    shutil.copyfile(values["--kernel"], os.path.join(tree, "kernel"))
                if values["--cmdline"]:
                    with open(os.path.join(tree, "cmdline"), "w") as f:
                        f.write(values["--cmdline"])
                header = ["--header_version", values["--header_version"]]
                if partition == "init_boot":
                    misc_info.append(f"mkbootimg_init_args={shlex.join(header)}")
                else:
                    share("mkbootimg header version", values["--header_version"], image)
                share("mkbootimg_version_args", shlex.join(
                    ["--os_version", values["--os_version"], "--os_patch_level", values["--os_patch_level"]]), image)

            elif partition == "vendor_boot":
                # what goes in a file of its own in VENDOR_BOOT, as the name of the file
                files = {"--dtb": "dtb", "--vendor_bootconfig": "vendor_bootconfig", "--vendor_cmdline": "vendor_cmdline",
                         "--pagesize": "pagesize", "--base": "base"}
                known = ("--header_version", "--kernel_offset", "--ramdisk_offset", "--tags_offset", "--dtb_offset",
                         "--board", "--vendor_ramdisk", "--vendor_ramdisk_fragment", *files)
                args = []
                ramdisks = []
                fragment = []
                os.makedirs(tree)
                for option, value in options:
                    if FRAGMENT_OPTIONS.fullmatch(option):
                        fragment += [option, value]
                    elif option in ("--vendor_ramdisk", "--vendor_ramdisk_fragment"):
                        ramdisks.append((fragment, value))
                        fragment = []
                    elif option not in known:
                        fail(f"{image} is made with {option}, which target files cannot hold")
                    elif option in files and option in BOOT_FILE_OPTIONS:
                        shutil.copyfile(value, os.path.join(tree, files[option]))
                    elif option in files:
                        if value:
                            with open(os.path.join(tree, files[option]), "w") as f:
                                f.write(value)
                    else:
                        args += [option, value]
                # the build makes the ramdisk in VENDOR_BOOT/RAMDISK the first one, of the platform type
                # and with no name, and then adds the others as fragments
                if not ramdisks or ramdisks[0][0] not in ([], ["--ramdisk_type", "1", "--ramdisk_name", ""]):
                    fail(f"{image} doesn't start with the unnamed platform ramdisk that the build makes first")
                extract_ramdisk(ramdisks[0][1], os.path.join(tree, "RAMDISK"), False)
                names = []
                for fragment, ramdisk in ramdisks[1:]:
                    name = dict(zip(fragment[::2], fragment[1::2])).get("--ramdisk_name", "")
                    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in (".", "..") or name in names:
                        fail(f"{image} has a ramdisk named {name!r}, which cannot be a fragment in target files")
                    names.append(name)
                    fragment_dir = os.path.join(tree, "RAMDISK_FRAGMENTS", name)
                    os.makedirs(fragment_dir)
                    with open(os.path.join(fragment_dir, "mkbootimg_args"), "w") as f:
                        f.write(shlex.join(fragment))
                    shutil.copyfile(ramdisk, os.path.join(fragment_dir, "prebuilt_ramdisk"))
                if names:
                    with open(os.path.join(tree, "vendor_ramdisk_fragments"), "w") as f:
                        f.write(shlex.join(names))
                share("mkbootimg header version", values["--header_version"], image)
                misc_info.append(f"mkbootimg_args={shlex.join(args)}")
                misc_info.append("vendor_boot=true")

            else:
                fail(f"{partition} is not a boot image partition")

            with open(os.path.join(expected, partition + ".json"), "w") as f:
                json.dump(describe_boot_image(image, os.path.join(tmp, partition + ".expected")), f)

        if "mkbootimg header version" in shared and "vendor_boot" not in dict(partitions):
            misc_info.append(f"mkbootimg_args={shlex.join(['--header_version', shared['mkbootimg header version'][0]])}")
        if "mkbootimg_version_args" in shared:
            misc_info.append(f"mkbootimg_version_args={shared['mkbootimg_version_args'][0]}")
    with open(os.path.join(out, "misc_info.txt"), "w") as f:
        f.writelines(line + "\n" for line in misc_info)


def boot_verify(image, expected_path):
    with open(expected_path) as f:
        expected = json.load(f)
    with tempfile.TemporaryDirectory() as tmp:
        actual = describe_boot_image(image, tmp)
    if actual != expected:
        errors = [f"{a} rather than {e}" for a, e in zip(actual, expected) if a != e]
        if len(actual) != len(expected):
            errors.append(f"{len(actual)} options rather than {len(expected)}")
        fail(f"{image} is not made like the original one:\n" + "\n".join(errors))


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "fs-dump":
        fs_dump(args[1])
    elif len(args) >= 5 and len(args) % 2 == 1 and args[0] == "fs-config":
        partitions = list(zip(args[3::2], args[4::2]))
        unknown = [p for p, _ in partitions if p not in PARTITIONS]
        if unknown:
            fail(f"unknown partitions {' '.join(unknown)}")
        fs_config(args[1], args[2], partitions)
    elif len(args) == 3 and args[0] == "fs-verify":
        fs_verify(args[1], args[2])
    elif len(args) >= 4 and len(args) % 2 == 0 and args[0] == "boot-inputs":
        boot_inputs(args[1], list(zip(args[2::2], args[3::2])))
    elif len(args) == 3 and args[0] == "boot-verify":
        boot_verify(args[1], args[2])
    elif len(args) == 3 and args[0] == "avb-args":
        print("\n".join(avb_args(args[1], args[2])))
    elif len(args) == 4 and args[0] == "apk-keys":
        apk_keys(args[1], args[2], args[3])
    elif len(args) == 3 and args[0] == "apex-verify":
        apex_verify(args[1], args[2])
    elif len(args) >= 3 and args[0] == "stale-preopt":
        stale_preopt(args[1], args[2:])
    else:
        fail("usage: fs-dump IMAGE | fs-config TARGET_FILES EXPECTED PARTITION METADATA... | fs-verify IMAGE EXPECTED | "
             "boot-inputs OUT PARTITION IMAGE... | boot-verify IMAGE EXPECTED | avb-args PARTITION IMAGE | "
             "apk-keys TARGET_FILES CERTS META | stale-preopt TARGET_FILES PATCHED... | apex-verify ORIGINAL SIGNED")


if __name__ == "__main__":
    main()
