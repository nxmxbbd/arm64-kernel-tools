# UDM SE Reference

Platform-specific notes for the Ubiquiti UniFi Dream Machine Special Edition.

## Hardware

- **SoC**: Annapurna Labs Alpine AL-524 (4x ARM Cortex-A57, ARMv8-A)
- **Kernel**: 4.19.152 (UniFi OS)
- **SATA**: AHCI controller on PCI 0000:00:08.0
  - Port 0: Internal SSD (boot/OS)
  - Port 1: HDD bay (user-accessible)

## Kernel Configuration (relevant bits)

| Config | Value | Impact |
|--------|-------|--------|
| `CONFIG_STRICT_DEVMEM` | `n` | `/dev/mem` gives full physical memory access |
| `CONFIG_MODULE_SIG_FORCE` | `y` | No unsigned module loading — no `insmod` escape hatch |
| `CONFIG_DEVMEM` | `y` | `/dev/mem` exists |

## Key Addresses (kernel 4.19.152)

These are reference values for a specific firmware version. **They will change with firmware updates.** Always verify against `/proc/kallsyms` on your device.

| Symbol / Region | Physical Address | Notes |
|-----------------|-----------------|-------|
| `_stext` | `0x04081000` | Kernel text start |
| VA-to-PA offset | `0xffffff8004000000` | `VA = PA + 0xffffff8004000000` |
| `swapper_pg_dir` | `0x04ca6000` | Level 0 page table base |

## Example Commands

### Scan for an ATA device struct by anchor value

```bash
sudo python3 tools/mem-struct-scan.py \
    --preset ata-device \
    --anchor-value 50782535680
```

The anchor value is the drive's sector count (from `IDENTIFY DEVICE` word 100-103). For a 26TB drive: 50782535680 sectors.

### Walk page tables

```bash
sudo python3 tools/pte-walk.py \
    --pgd-pa 0x04ca6000 \
    --va 0xffffff8008081000
```

### Check text patch status (read-only)

```bash
sudo python3 tools/text-hotpatch.py \
    --preset ata-device-obs \
    --stext-pa 0x04081000 \
    --status
```

### Patch kernel data structure

```bash
# Dry run (default) — shows what would change
sudo python3 tools/mem-data-patch.py \
    --pa 0x3e8d3280 \
    --offset 324 \
    --width 2 \
    --value 0x0040

# Live write
sudo python3 tools/mem-data-patch.py \
    --pa 0x3e8d3280 \
    --offset 324 \
    --width 2 \
    --value 0x0040 \
    --write
```

### Cross-compile and run C hotpatcher

```bash
# On build machine
aarch64-linux-gnu-gcc -static -O2 -o text-hotpatch tools/text-hotpatch.c

# Copy to UDM SE, then:
sudo ./text-hotpatch \
    --preset ata-device-obs \
    --stext-pa 0x04081000 \
    --apply
```

## Notes

- The UDM SE has no `debugfs`, no `kprobes`, no `ftrace`, and `MODULE_SIG_FORCE` prevents loading custom modules. `/dev/mem` is the only kernel introspection path available.
- The AHCI controller is a standard Linux `libahci` device. Port 1 (the HDD bay) uses the same driver as Port 0 (the SSD).
- All patches are volatile. A reboot restores the original kernel state.
