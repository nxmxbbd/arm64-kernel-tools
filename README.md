# arm64-kernel-tools

ARM64 kernel runtime diagnostics and hotpatching toolkit for embedded Linux.

## What This Is

Tools for reading and modifying running ARM64 Linux kernels via `/dev/mem` when traditional debugging interfaces (`debugfs`, `kprobes`, `ftrace`, `livepatch`) are unavailable. Designed for locked-down embedded systems where `/dev/mem` is the only way in.

## Why It Exists

A WD Purple Pro 26TB drive appeared broken on an embedded system (Ubiquiti UDM SE). The system had no `debugfs`, no `kprobes`, no loadable modules (`MODULE_SIG_FORCE=y`), no `kexec`. `/dev/mem` was the only kernel introspection path available. Over the course of the investigation, three hypotheses were tested and disproved — requiring kernel data structure patching, kernel text hotpatching, and systematic ATA command testing — before the drive was proven dead on arrival. The tools and techniques developed during that investigation are useful for any locked-down embedded Linux system with `/dev/mem` access.

## Tools

| Tool | Purpose | Risk Level |
|------|---------|------------|
| `mem-struct-scan.py` | Find kernel data structures by scanning physical memory | Read-only |
| `mem-data-patch.py` | Patch kernel data structures via /dev/mem | High — modifies kernel data |
| `text-hotpatch.py` | Patch ARM64 kernel instructions (Python, with JIT cache maint) | Critical — modifies kernel code |
| `text-hotpatch.c` | Patch ARM64 kernel instructions (C, proper `__builtin___clear_cache`) | Critical — modifies kernel code |
| `pte-walk.py` | Walk ARM64 page tables, inspect permissions | Read-only |

## Quick Start

```bash
# Find a kernel struct by scanning for a known field value
sudo python3 tools/mem-struct-scan.py --preset ata-device --anchor-value 50782535680

# Walk ARM64 page tables
sudo python3 tools/pte-walk.py --pgd-pa 0x04ca6000 --va 0xffffff8008081000

# Check kernel text patch sites (read-only)
sudo python3 tools/text-hotpatch.py --preset ata-device-obs --stext-pa 0x04081000 --status

# Cross-compile the C hotpatcher
aarch64-linux-gnu-gcc -static -O2 -o text-hotpatch tools/text-hotpatch.c
```

## Requirements

- Python 3.6+
- Root access
- `/dev/mem` accessible (`CONFIG_STRICT_DEVMEM=n` or appropriate permissions)
- `/proc/kallsyms` readable (for text patching tools)
- ARM64 (aarch64) system
- For `text-hotpatch.c`: aarch64 C compiler (cross-compile or native)

## Safety Philosophy

Every tool is built around a multi-layer safety model:

- **Read-only tools never write to `/dev/mem`** — `mem-struct-scan.py` and `pte-walk.py` only read.
- **Data patching tools verify before and after writing** — `mem-data-patch.py` checks the current value before overwriting and reads back after writing. Auto-rollback on verification failure.
- **Text patching tools verify instruction encoding** — `text-hotpatch.py` and `text-hotpatch.c` confirm the instruction at the target address matches the expected old encoding before writing.
- **All patches are volatile** — modifications are to the running kernel's memory only, never to disk. A reboot always recovers the original state.
- **Dry-run mode is the default** — all write operations require an explicit flag (`--write`, `--apply`) to actually modify memory. Without it, they show what would change and exit.

## Documentation

- [Case Study: UDM SE HDD Investigation](docs/case-study-udm-hdd.md)
- [ATA Command Testing Methodology](docs/ata-command-map.md)
- [ARM64 I-cache Pitfalls](docs/arm64-icache-pitfalls.md)
- [Kernel Text Patching Guide](docs/kernel-text-patching.md)
- [UDM SE Reference](examples/udm-se/README.md)

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

These tools can crash your system. See [DISCLAIMER.md](DISCLAIMER.md).

## Contributing

Issues and PRs welcome. See [SECURITY.md](SECURITY.md) for security-related reports.
