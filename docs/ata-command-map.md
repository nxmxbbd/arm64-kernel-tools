# ATA Command Testing Methodology

Systematic determination of which ATA commands a SATA drive can execute, for use in diagnosing drive failures.

## Purpose

When a drive is detected but not functioning, individual hypothesis testing can take days. A systematic approach — testing every relevant ATA command and classifying the results — reveals the failure pattern immediately.

This methodology uses Linux `SG_IO` passthrough to send raw ATA commands via the SAT (SCSI/ATA Translation) layer, bypassing the kernel's normal I/O path.

## Command Categories

### Controller-Only Commands

These commands are handled entirely by the drive's controller (MCU + ROM/SRAM). They do not require media access or loaded firmware from the Service Area.

| Command | ATA Opcode | What It Does |
|---------|-----------|--------------|
| IDENTIFY DEVICE | `0xEC` | Returns 512 bytes of device info from controller ROM |
| CHECK POWER MODE | `0xE5` | Returns current power state from controller register |
| READ BUFFER | `0xE4` | Reads the controller's internal sector buffer (SRAM) |
| WRITE BUFFER | `0xE8` | Writes to the controller's internal sector buffer |
| DEVICE RESET | `0x08` | Hardware reset via controller |

If these work but everything else fails, the controller is alive but has no firmware.

### Media-Dependent Commands

These commands require functional heads, platters, and/or loaded Service Area firmware.

| Command | ATA Opcode | What It Does |
|---------|-----------|--------------|
| READ SECTOR(S) | `0x20` | 28-bit PIO read from media |
| READ SECTOR(S) EXT | `0x24` | 48-bit PIO read from media |
| READ DMA | `0xC8` | 28-bit DMA read from media |
| READ DMA EXT | `0x25` | 48-bit DMA read from media |
| WRITE SECTOR(S) | `0x30` | 28-bit PIO write to media |
| WRITE SECTOR(S) EXT | `0x34` | 48-bit PIO write to media |
| WRITE DMA | `0xCA` | 28-bit DMA write to media |
| WRITE DMA EXT | `0x35` | 48-bit DMA write to media |
| SEEK | `0x70` | Move heads to specified cylinder |
| RECALIBRATE | `0x10` | Move heads to track 0 |

### Firmware-Dependent Commands

These commands require the Service Area to be loaded into controller RAM, but may not require media access for every invocation.

| Command | ATA Opcode | What It Does |
|---------|-----------|--------------|
| SMART READ DATA | `0xB0/D0` | Returns SMART attribute table |
| SMART READ THRESHOLDS | `0xB0/D1` | Returns SMART threshold table |
| SMART ENABLE OPERATIONS | `0xB0/D8` | Enables SMART monitoring |
| SMART RETURN STATUS | `0xB0/DA` | Returns SMART health status |
| SET FEATURES | `0xEF` | Configures transfer modes, caches, etc. |
| FLUSH CACHE | `0xE7` | Flushes write cache to media |
| READ NATIVE MAX ADDRESS | `0xF8` | Returns max addressable LBA |

## Three-Tier Failure Classification

The response timing is as important as the pass/fail result. Classify each command response into one of three tiers:

### Tier A: Success (response time ~0ms)

The command completed successfully and returned data. For controller-only commands, this means the controller MCU and ROM/SRAM are functional.

### Tier B: Immediate Reject (response time ~0ms, error status)

The command was dispatched to the firmware handler and rejected immediately. This typically means the firmware dispatch table is partially loaded or the command's handler function is not available. The controller received the command and actively refused it — it did not attempt to execute.

### Tier C: Timeout (response time 50ms-110ms+, then error)

The command was dispatched and the controller attempted to execute it, but the operation timed out waiting for a response from the media subsystem (heads, servo, spindle motor). This indicates the firmware *tried* to access the platters and failed.

## Timing Analysis

Timing is critical for classification. Use `clock_gettime(CLOCK_MONOTONIC)` or equivalent around each `SG_IO` call.

- **0ms**: Controller handled it entirely in ROM/SRAM (Tier A) or rejected it from the dispatch table (Tier B). Distinguish by checking the error status.
- **~50ms**: One servo timeout. The controller attempted a head seek and gave up.
- **~110ms**: Multiple retry/timeout cycles. The controller retried the media access.
- **>1s**: Command-level timeout. The entire command was abandoned.

## Using SG_IO for Direct Command Injection

Commands are sent via the Linux `SG_IO` ioctl using the ATA PASS-THROUGH (12) or ATA PASS-THROUGH (16) SCSI CDBs (opcodes `0xA1` and `0x85`).

```
ATA PASS-THROUGH (12) CDB layout:
Byte 0:    0xA1 (opcode)
Byte 1:    Protocol << 1 | EXTEND
Byte 2:    T_DIR | BYT_BLOK | T_LENGTH
Byte 3:    Features
Byte 4:    Sector Count
Byte 5:    LBA Low
Byte 6:    LBA Mid
Byte 7:    LBA High
Byte 8:    Device
Byte 9:    Command opcode
Byte 10:   Reserved
Byte 11:   Control
```

Protocol values:
- `3` (0x06 shifted): Non-data
- `4` (0x08 shifted): PIO Data-In
- `5` (0x0A shifted): PIO Data-Out
- `6` (0x0C shifted): DMA

### Data Buffer Verification

**Do not trust SG_IO return codes alone.** Fill your data buffer with a known pattern (e.g., `0xDEADBEEF`) before each read command. After the command completes, check if the buffer contents changed. If SG_IO reports success but the buffer is still `DEADBEEF`, no data was actually transferred. This catches cases where the SAT layer reports success even though the underlying ATA command failed.

## Diagnosis Decision Tree

### Pattern: Controller-only commands pass, everything else fails

**Diagnosis**: Service Area load failure. The drive's firmware (stored on reserved platter tracks) did not load into controller RAM at spinup. The controller is functional but has no firmware to execute media commands.

**Common causes**: Head crash in the SA zone, defective platter surface, failed head pre-amp.

**Prognosis**: Drive is dead. Professional data recovery (clean room, head swap) is the only option if data existed on the drive.

### Pattern: All reads fail, all writes fail, SMART fails

**Diagnosis**: Complete media failure. Same as above but potentially worse — the controller may not even have enough firmware to properly reject commands.

### Pattern: PIO works, DMA fails

**Diagnosis**: DMA controller or channel failure. The CPU-driven transfer path works but the DMA engine does not. Could be a controller defect, a cable issue (marginal signal integrity affects DMA more than PIO), or a driver/configuration problem.

### Pattern: Reads work, writes fail

**Diagnosis**: Write-protect condition or write head failure. Check IDENTIFY DEVICE word 0 for removable media bit, word 85 for write cache status.

### Pattern: Small LBA reads work, large LBA reads fail

**Diagnosis**: Partial media failure. The inner or outer tracks are damaged. Could also indicate a 28-bit vs 48-bit LBA addressing issue in the host controller or driver.

### Pattern: Everything works via SG_IO but fails through the filesystem

**Diagnosis**: Driver or kernel issue. The hardware path is fine but the kernel's I/O stack has a bug or misconfiguration. This is where kernel data/text patching tools become relevant.

### Pattern: Commands succeed but return wrong data

**Diagnosis**: Translation or ordering issue. Check byte-swap, sector size assumptions (512 vs 4K native), and command queuing behavior.

## Full Command Table

The following table shows all 22 commands used in a comprehensive diagnostic pass, organized by expected behavior on a functional drive:

| # | Command | Opcode | Protocol | Sector Count | Expected Response | Failure Indicates |
|---|---------|--------|----------|-------------|-------------------|-------------------|
| 1 | IDENTIFY DEVICE | `0xEC` | PIO-In | 1 | 512B device info | Controller dead |
| 2 | CHECK POWER MODE | `0xE5` | Non-data | 0 | Power state in SC | Controller dead |
| 3 | READ BUFFER | `0xE4` | PIO-In | 1 | 512B buffer data | Controller SRAM issue |
| 4 | WRITE BUFFER | `0xE8` | PIO-Out | 1 | Success | Controller SRAM issue |
| 5 | READ BUFFER (verify) | `0xE4` | PIO-In | 1 | Written data back | Controller SRAM issue |
| 6 | SMART ENABLE | `0xB0` | Non-data | 0 | Success | SA not loaded |
| 7 | SMART READ DATA | `0xB0` | PIO-In | 1 | 512B SMART data | SA not loaded |
| 8 | SMART READ THRESHOLDS | `0xB0` | PIO-In | 1 | 512B threshold data | SA not loaded |
| 9 | SMART RETURN STATUS | `0xB0` | Non-data | 0 | Health status | SA not loaded |
| 10 | READ NATIVE MAX | `0xF8` | Non-data | 0 | Max LBA | SA not loaded |
| 11 | SET FEATURES (PIO4) | `0xEF` | Non-data | 0 | Success | SA not loaded |
| 12 | SET FEATURES (UDMA6) | `0xEF` | Non-data | 0 | Success | SA not loaded |
| 13 | READ SECTOR (LBA 0) | `0x20` | PIO-In | 1 | 512B from LBA 0 | Media failure |
| 14 | READ SECTOR EXT (LBA 0) | `0x24` | PIO-In | 1 | 512B from LBA 0 | Media failure |
| 15 | READ DMA (LBA 0) | `0xC8` | DMA | 1 | 512B from LBA 0 | DMA or media failure |
| 16 | READ DMA EXT (LBA 0) | `0x25` | DMA | 1 | 512B from LBA 0 | DMA or media failure |
| 17 | WRITE SECTOR (LBA max) | `0x30` | PIO-Out | 1 | Success | Media failure |
| 18 | WRITE DMA (LBA max) | `0xCA` | DMA | 1 | Success | DMA or media failure |
| 19 | SEEK (LBA 0) | `0x70` | Non-data | 0 | Success | Head/servo failure |
| 20 | SEEK (LBA max) | `0x70` | Non-data | 0 | Success | Head/servo failure |
| 21 | RECALIBRATE | `0x10` | Non-data | 0 | Success | Head/servo failure |
| 22 | FLUSH CACHE | `0xE7` | Non-data | 0 | Success | SA not loaded |

## Using the Results

Run all 22 commands, record pass/fail and response time for each, then match against the diagnosis decision tree above. The pattern of which tiers each command falls into tells you exactly where the failure boundary is: controller, firmware, or media.
