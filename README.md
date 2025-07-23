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

IRLM/  
├── lsm/ -> eBPF and LSM modules  
├── runtime_hardening/ -> Runtime protection modules  
├── kernel_integrity/ -> Kernel structure integrity checks  
├── network_guard/ -> Network-level protection (XDP, firewall)  
├── core/ -> C++ engine for scoring and correlation  
├── detection/ -> Python-based detection logic  
├── agent/ -> Agents in Python, C#, JS, and others  
├── interfaces/ -> CLI and GUI interfaces  
├── proto/ -> gRPC definitions  
├── tools/ -> Simulation and visualization tools  
├── tests/ -> Testing infrastructure  
├── scripts/ -> Install scripts, launchers  
└── docs/ -> Documentation  

## Setup Instructions

See docs/DEV_SETUP.md for full setup and build instructions.

To compile a BPF program, open a .bpf.c file in VS Code and press Ctrl+Shift+B.
