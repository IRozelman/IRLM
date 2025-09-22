#!/bin/bash

# This script builds all components of the project.

# Directory definitions
SRC_DIR="lsm/ebpf_monitor/tracepoints"
BUILD_DIR="lsm/ebpf_monitor/build"
INCLUDE_DIRS="-I./lsm/ebpf_monitor/maps -I./lsm/ebpf_monitor/include -I/home/itamar/linux/tools/bpf/bpftool"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Compiler flags
CLANG_FLAGS="-g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall"

echo "[*] Building eBPF programs..."

# Loop throw all .bpf.c files in tracepoints/
for src_file in "$SRC_DIR"/*.bpf.c; do
    fname=$(basename "$src_file")
    out_file="$BUILD_DIR/${fname%.bpf.c}.o"

    echo "[+] Compiling $fname -> $out_file"
    clang $CLANG_FLAGS $INCLUDE_DIRS -c $src_file -o $out_file

    if [[ $? -ne 0 ]]; then
        echo "[!] Compilation failed for $src_file"
        exit 1
    fi
done

echo "[v] All eBPF programs built successfully."
