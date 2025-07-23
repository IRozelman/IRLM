# IRLM – Intelligent Runtime Library Monitor

IRLM is a Linux-based security system that uses eBPF and BPF-LSM to detect, trace, and respond to suspicious system activity. It provides full visibility into runtime behavior, including file operations, process executions, memory execution, and network activity. It is designed to detect fileless malware, stealthy evasion techniques, and persistent threats.

## Features

- System call tracing (file, network, process, memory, config)
- Runtime anomaly detection (memfd execution, LD_PRELOAD, ptrace, etc.)
- Syscall allowlist/blocklist enforcement using LSM hooks
- Multi-language runtime agents (Python, C#, C++, Bash, PHP, Java, JS)
- Behavior correlation and scoring in C++
- Tools for simulation, visualization, and attack replay

## Project Structure

IRLM/ \n
├── lsm/ -> eBPF and LSM modules \n
├── runtime_hardening/ -> Runtime protection modules \n
├── kernel_integrity/ -> Kernel structure integrity checks \n
├── network_guard/ -> Network-level protection (XDP, firewall) \n
├── core/ -> C++ engine for scoring and correlation \n
├── detection/ -> Python-based detection logic \n
├── agent/ -> Agents in Python, C#, JS, and others \n
├── interfaces/ -> CLI and GUI interfaces \n
├── proto/ -> gRPC definitions \n
├── tools/ -> Simulation and visualization tools \n
├── tests/ -> Testing infrastructure \n
├── scripts/ -> Install scripts, launchers \n
└── docs/ -> Documentation \n

## Setup Instructions

See docs/DEV_SETUP.md for full setup and build instructions.

To compile a BPF program, open a .bpf.c file in VS Code and press Ctrl+Shift+B.
