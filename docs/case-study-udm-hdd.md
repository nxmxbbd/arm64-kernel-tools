# Case Study: UDM SE HDD Investigation

**From "drive doesn't work" to "drive is dead"**

This is the story of diagnosing a WD Purple Pro 26TB (WD261PURP) HDD on a Ubiquiti UDM SE. The drive turned out to be dead on arrival, but proving that required building an entire kernel instrumentation toolkit from scratch — because the platform gave us nothing else to work with.

## The Platform Constraints

The UDM SE runs a locked-down Linux 4.19.152 kernel on an Alpine AL-524 (Cortex-A57):

- No `debugfs`
- No `kprobes` or `ftrace`
- `CONFIG_MODULE_SIG_FORCE=y` — cannot load unsigned modules
- No `kexec`
- But: `CONFIG_STRICT_DEVMEM=n` — `/dev/mem` is wide open

This meant `/dev/mem` was the only kernel introspection path available.

## Timeline

### Phase 1: The Symptom

The drive was installed in the UDM SE's HDD bay (AHCI Port 1). `dmesg` showed immediate I/O errors on every command the kernel issued. The drive was detected (IDENTIFY DEVICE succeeded), but all subsequent I/O failed. `smartctl` returned all zeros. The drive appeared fundamentally broken.

### Phase 2: Hypothesis 1 — LBA Addressing Mismatch

**Theory**: The 26TB drive requires 48-bit LBA, but the kernel might be sending 28-bit commands (which cap out at 128GB).

**Investigation**: Used `mem-struct-scan.py` to locate the kernel's `ata_device` structure in physical memory by scanning for the drive's sector count (50782535680) as an anchor value. Examined the `horkage`, `flags`, and `class` fields to determine what addressing mode the kernel was using.

**Result**: Disproved. The kernel was already using 48-bit LBA. The `ata_device` flags showed LBA48 correctly enabled. 28-bit vs 48-bit was not the issue.

### Phase 3: Hypothesis 2 — DMA Channel Failure

**Theory**: The DMA path between the AHCI controller and the drive is broken, but PIO mode (CPU-driven transfers) might work.

**Investigation**: Used `mem-data-patch.py` to modify the `ata_device` structure's transfer mode fields in live kernel memory, forcing the driver to use PIO instead of DMA. This required locating the `pio_mask`, `mwdma_mask`, and `udma_mask` fields and patching them to force PIO-only operation.

**Result**: Disproved. PIO mode also failed with the same I/O errors. The problem was not DMA-specific.

### Phase 4: Hypothesis 3 — Obsolete Device Register Bits

**Theory**: ACS-5 made the DEV bit (0xA0 in the device register) obsolete, but the kernel's `libata` still sets it on every command. Some modern drives might reject commands with this legacy bit set.

**Investigation**: This required patching kernel *text*, not data. The `ata_tf_to_fis()` function and its callers had 16 inline sites where `0xA0` was OR'd into the device register byte. Each site was a MOVZ instruction with the immediate `0xA0` that needed to become `0x40` (keeping the LBA bit, dropping the obsolete DEV bit).

This is where the project took a turn.

**The I-cache crash**: The first attempt used a Python script that wrote the patched instructions via `/dev/mem`. The write succeeded (verified by read-back), but the kernel crashed immediately when execution hit the patched code. The D-cache had the new instructions, but the I-cache still had the old ones. On ARM64, the I-cache and D-cache are not coherent — unlike x86, writing to memory does not automatically invalidate the I-cache. See [ARM64 I-cache Pitfalls](arm64-icache-pitfalls.md) for the full technical explanation.

**The fix**: Built `text-hotpatch.c`, a C program that uses `__builtin___clear_cache()` after writing to the mmap'd `/dev/mem` page. This issues the correct `DC CVAU` + `DSB ISH` + `IC IVAU` + `DSB ISH` + `ISB` sequence. All 16 sites were patched successfully without crashing.

**Result**: Disproved. Even with the device register fixed to `0x40`, the drive still returned errors on all I/O commands. The obsolete bit was not the problem.

### Phase 5: Verifying the I/O Path

**Key insight**: The `DEADBEEF` test. Before accepting that all ATA commands truly failed, we needed to verify that data was actually being transferred. Filled a buffer with `0xDEADBEEF` and issued a READ SECTOR via `SG_IO` passthrough. The buffer came back still full of `DEADBEEF`. The `SG_IO` path was reporting success on some operations, but no data was ever transferred. This eliminated SG_IO as a reliable test path and confirmed the drive was genuinely not responding to data transfer commands.

### Phase 6: Systematic ATA Command Testing

With individual hypotheses exhausted, we moved to a systematic approach: test every relevant ATA command individually and classify the results. See [ATA Command Testing Methodology](ata-command-map.md) for the full framework.

**22 commands tested via SG_IO**. The results fell into a clear pattern:

- **Commands that worked** (0ms response): IDENTIFY DEVICE, CHECK POWER MODE, READ BUFFER, WRITE BUFFER — all operations that only touch the controller's ROM/SRAM.
- **Commands that were immediately rejected** (0ms, error): SMART operations, WRITE SECTOR, various feature sets — firmware dispatch table entries that depend on loaded Service Area data.
- **Commands that timed out** (50-110ms, then error): READ SECTOR, READ DMA, SEEK — commands that attempt media access and hang waiting for the platters.

**Diagnosis**: The drive's Service Area (firmware stored on the platters) failed to load. The controller was alive and responsive, but it had no working firmware to execute media-dependent commands. This is consistent with either a head crash during manufacturing or a defective platter surface in the SA zone.

### Phase 7: Final Confirmation

The drive was removed from the UDM SE and connected to a desktop PC via SATA. On power-up, it produced an audible click-of-death pattern: repeated head seek-reset cycles. The drive was dead on arrival.

## What the Tools Did

| Phase | Tool | Purpose |
|-------|------|---------|
| 2 | `mem-struct-scan.py` | Located `ata_device` struct in physical memory |
| 3 | `mem-data-patch.py` | Forced PIO mode by patching transfer mask fields |
| 4 | `text-hotpatch.py` | First attempt at kernel text patching (crashed — I-cache) |
| 4 | `text-hotpatch.c` | Successful kernel text patching with proper cache maintenance |
| 5-6 | SG_IO scripts | Direct ATA command injection for systematic testing |

## Methodology Lessons

**Test your assumptions about working paths.** SG_IO appeared to be working (no error return) but was not actually transferring data. The `DEADBEEF` buffer test caught this. Never assume a path works just because it does not return an error.

**Systematic testing beats hypothesis chasing.** After three disproved hypotheses, the 22-command systematic test immediately revealed the failure pattern. Start broad when individual theories fail.

**Tool development driven by investigation needs.** Every tool in this repository exists because a specific diagnostic step required it. `mem-struct-scan.py` was built to test Hypothesis 1. `mem-data-patch.py` was built for Hypothesis 2. `text-hotpatch.c` was built after `text-hotpatch.py` crashed the kernel. The tools are practical artifacts of a real investigation.

**Platform constraints force creativity.** On a system with `kprobes` or loadable modules, this investigation would have taken hours, not days. But the locked-down UDM SE left only `/dev/mem`, and that constraint produced tools that work on *any* similarly locked-down embedded Linux system.

**The drive was dead all along.** Sometimes the answer is the simplest one. But you cannot know that until you have eliminated the alternatives — and on this platform, eliminating them required building the tools to look.
