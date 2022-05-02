#!/usr/bin/env python

import hashlib
import os
import os.path
import shutil
import struct
import subprocess
import sys
import zipfile

# from https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/scripts/update_payload/
import update_metadata_pb2

BRILLO_MAJOR_PAYLOAD_VERSION = 2

class PayloadError(Exception):
  pass

class Payload(object):
  class _PayloadHeader(object):
    _MAGIC = b'CrAU'

    def __init__(self):
      self.version = None
      self.manifest_len = None
      self.metadata_signature_len = None
      self.size = None

    def ReadFromPayload(self, payload_file):
      magic = payload_file.read(4)
      if magic != self._MAGIC:
        raise PayloadError('Invalid payload magic: %s' % magic)
      self.version = struct.unpack('>Q', payload_file.read(8))[0]
      self.manifest_len = struct.unpack('>Q', payload_file.read(8))[0]
      self.size = 20
      self.metadata_signature_len = 0
      if self.version != BRILLO_MAJOR_PAYLOAD_VERSION:
        raise PayloadError('Unsupported payload version (%d)' % self.version)
      self.size += 4
      self.metadata_signature_len = struct.unpack('>I', payload_file.read(4))[0]

  def __init__(self, payload_file):
    self.payload_file = payload_file
    self.header = None
    self.manifest = None
    self.data_offset = None
    self.metadata_signature = None
    self.metadata_size = None

  def _ReadManifest(self):
    return self.payload_file.read(self.header.manifest_len)

  def _ReadMetadataSignature(self):
    self.payload_file.seek(self.header.size + self.header.manifest_len)
    return self.payload_file.read(self.header.metadata_signature_len);

  def ReadDataBlob(self, offset, length):
    self.payload_file.seek(self.data_offset + offset)
    return self.payload_file.read(length)

  def Init(self):
    self.header = self._PayloadHeader()
    self.header.ReadFromPayload(self.payload_file)
    manifest_raw = self._ReadManifest()
    self.manifest = update_metadata_pb2.DeltaArchiveManifest()
    self.manifest.ParseFromString(manifest_raw)
    metadata_signature_raw = self._ReadMetadataSignature()
    if metadata_signature_raw:
      self.metadata_signature = update_metadata_pb2.Signatures()
      self.metadata_signature.ParseFromString(metadata_signature_raw)
    self.metadata_size = self.header.size + self.header.manifest_len
    self.data_offset = self.metadata_size + self.header.metadata_signature_len

def main(filename, output_dir):
  if filename.endswith('.zip'):
    print("Extracting 'payload.bin' from OTA file...")
    ota_zf = zipfile.ZipFile(filename)
    payload_file = open(ota_zf.extract('payload.bin', output_dir), 'rb')
  else:
    payload_file = open(filename, 'rb')

  payload = Payload(payload_file)
  payload.Init()

  with open(os.path.join(output_dir, "ab_partitions.txt"), "w") as abf:
    for p in payload.manifest.partitions:
      print(p.partition_name, file = abf)

  with open(os.path.join(output_dir, "dynamic_partitions_info.txt"), "w") as df:
    if payload.manifest.HasField("dynamic_partition_metadata"):
      d = payload.manifest.dynamic_partition_metadata
      print("use_dynamic_partitions=true", file = df)
      if d.HasField("snapshot_enabled") and d.snapshot_enabled:
        print("virtual_ab=true", file = df)
#     if d.HasField("vabc_enabled") and d.vabc_enabled:
#      	print("virtual_ab_compression=true")
      print("super_partition_groups=" + " ".join([g.name for g in d.groups]), file = df)
      for g in d.groups:
        print("super_" + g.name + "_group_size=" + str(g.size), file = df)
        print("super_" + g.name + "_partition_list=" + " ".join(g.partition_names), file = df)
    else:
      print("use_dynamic_partitions=false")

if __name__ == '__main__':
  try:
    filename = sys.argv[1]
  except:
    print('Usage: %s payload.bin' % sys.argv[0])
    sys.exit()

  try:
    output_dir = sys.argv[2]
  except IndexError:
    output_dir = os.getcwd()

  if not os.path.exists(output_dir):
    os.makedirs(output_dir)

  main(filename, output_dir)
