#!/usr/bin/env python3
import sys

# Ensure proper usage
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <all_files_output.txt> <dev_nodes_output.txt>", file=sys.stderr)
    sys.exit(1)

file_all_path = sys.argv[1]
file_dev_path = sys.argv[2]

with open(file_all_path, 'w') as f_all, open(file_dev_path, 'w') as f_dev:
    f_all.write(" 0 0 0755\n")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 8:
            continue

        mode_str = parts[0]
        ftype = mode_str[0]
        perms = mode_str[1:]

        # Convert standard rwxrwxrwx string to 4-digit octal (e.g., 0755)
        octal = 0
        for i, char in enumerate(perms):
            if char != '-':
                octal |= 1 << (8 - i)
        octal_str = f"0{oct(octal)[2:]}"

        uid, gid = parts[2], parts[3]

        # Extract file name appropriately based on the ls -l column structure
        if ftype in ('c', 'b'):
            # Device nodes have major/minor numbers, pushing the name column over
            name = " ".join(parts[9:])
        else:
            name = " ".join(parts[8:])
            # If it's a symlink, isolate just the file name and drop the '-> target'
            if ftype == 'l' and ' -> ' in name:
                name = name.split(' -> ')[0]

        # 1. Write to the first file (All files: <name> <uid> <gid> <mode>)
        f_all.write(f"{name} {uid} {gid} {octal_str}\n")

        # 2. Write to the second file (Dev nodes & Dirs only)
        if ftype in ('c', 'b'):
            major = parts[4].rstrip(',')
            minor = parts[5]
            f_dev.write(f"nod {name} {octal_str} {uid} {gid} {ftype} {major} {minor}\n")
        elif ftype == 'd':
            f_dev.write(f"dir {name} {octal_str} {uid} {gid}\n")
