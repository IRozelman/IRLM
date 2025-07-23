# Developer Setup Guide for IRLM

This guide assumes you are running a real Ubuntu machine, not WSL.

## Python Environment

Create a virtual environment and install required Python packages.

cd ~/git-projects/IRLM
python3 -m venv .venv
source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Contents of requirements.txt:

rich==13.5.2
click==8.1.3
psutil==5.9.4
bcc==0.28.0

## System Dependencies

Install required system packages:

sudo apt update
sudo apt install -y \
  clang llvm make gcc \
  libelf-dev libbpf-dev \
  flex bison libz-dev libssl-dev \
  linux-headers-$(uname -r)

If bpftool is not available through apt, build it manually:

git clone --depth=1 https://github.com/torvalds/linux.git ~/bpftool-src
cd ~/bpftool-src/tools/bpf/bpftool
make
sudo cp bpftool /usr/local/bin/

Test with:

sudo bpftool prog show

## VS Code Task Configuration

To compile .bpf.c files automatically:

Create .vscode/tasks.json with the following content:

{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build BPF Program",
      "type": "shell",
      "command": "clang",
      "args": [
        "-O2",
        "-g",
        "-target", "bpf",
        "-D__TARGET_ARCH_x86",
        "-Wall",
        "-Wno-unused-value",
        "-Wno-pointer-sign",
        "-Wno-compare-distinct-pointer-types",
        "-I./lsm/ebpf_monitor/maps",
        "-I./vmlinux",
        "-c",
        "${file}",
        "-o",
        "${fileDirname}/${fileBasenameNoExtension}.o"
      ],
      "group": "build",
      "problemMatcher": [],
      "detail": "Compiles a single BPF program file using Clang"
    }
  ]
}

To build a BPF file, open it in VS Code and press Ctrl+Shift+B.

## No Testing Required Yet

Testing is deferred until later checklist stages. Do not run test cases unless explicitly stated.
