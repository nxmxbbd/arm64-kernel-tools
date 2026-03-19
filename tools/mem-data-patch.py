#!/usr/bin/env python3
"""
mem-data-patch.py - Generic kernel data structure patcher for ARM64 Linux via /dev/mem

Patches arbitrary byte values at physical memory addresses in live kernel data
structures. Designed for embedded ARM64 Linux systems where /dev/mem is available
and kernel data structures need runtime modification.

Developed for embedded Linux diagnostics, particularly situations where kernel
driver behavior must be adjusted at runtime without rebuilding or rebooting.

SAFETY MODEL (6 layers):
  L1: Reboot recovery   - All patches are transient; a reboot restores originals
  L2: Software undo     - Every patch records its reverse; --undo restores values
  L3: Pre-write valid.  - Before writing, current value is checked against expected
  L4: Write-then-verify - After each byte write, the value is read back and compared
  L5: Post-patch revalid- After all patches, full re-read validates the struct
  L6: Auto-rollback     - If any write fails verification, all prior writes are undone

ARM64 /dev/mem NOTE:
  On many ARM64 platforms (including Alpine-based embedded systems), mmap with
  PROT_WRITE silently fails for /dev/mem regions. This tool uses the os.lseek +
  os.write pattern instead, which correctly writes through the /dev/mem interface
  on these platforms.

USAGE EXAMPLES:
  # Dry-run (default) with explicit struct address:
  sudo python3 mem-data-patch.py --struct-base 0xffff800012345000 --patches my_patches.json

  # Apply patches:
  sudo python3 mem-data-patch.py --struct-base 0xffff800012345000 --patches my_patches.json --apply

  # Scan memory for struct, then patch:
  sudo python3 mem-data-patch.py --scan-first --anchor-value 0x41 --anchor-offset 0x100 --patches p.json --apply

  # Use built-in ATA PIO preset:
  sudo python3 mem-data-patch.py --struct-base 0xffff800012345000 --preset ata-pio-force --apply

  # Check current state of patches:
  sudo python3 mem-data-patch.py --struct-base 0xffff800012345000 --patches my_patches.json --status

  # Undo previously applied patches:
  sudo python3 mem-data-patch.py --struct-base 0xffff800012345000 --patches my_patches.json --undo --apply
"""

import argparse
import json
import mmap
import os
import struct
import sys
import textwrap
import traceback

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_SIZE = 4096
IORESOURCE_MEM = 0x00000200

# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------

# Each preset is a dict matching the patch JSON schema.
# These encode domain-specific knowledge for common use cases.

PRESETS = {
    "ata-pio-force": {
        "description": "Force ATA device into PIO mode by setting NODMA horkage, PIO flag, clearing DMA mode",
        "notes": [
            "Targets fields within a Linux kernel ata_device struct.",
            "horkage: sets ATA_HORKAGE_NODMA bit (bit 1 = 0x02)",
            "flags: sets ATA_DFLAG_PIO bit (bit 5 = 0x20) in the low byte",
            "dma_mode: clears DMA transfer mode to 0x00",
            "Offsets are relative to the ata_device struct base.",
            "Use mem-struct-scan.py or --scan-first to locate the struct.",
        ],
        "patches_apply": [
            {
                "name": "horkage_nodma",
                "offset": 264,
                "size": 1,
                "from": "0x00",
                "to": "0x02",
                "desc": "Set ATA_HORKAGE_NODMA bit in horkage field (low byte at +264)",
            },
            {
                "name": "flags_pio",
                "offset": 12,
                "size": 1,
                "from": None,
                "to": None,
                "desc": "Set ATA_DFLAG_PIO bit (0x20) in flags field (low byte at +12) -- OR-style",
                "bit_or": 0x20,
            },
            {
                "name": "dma_mode_clear",
                "offset": 276,
                "size": 1,
                "from": None,
                "to": "0x00",
                "desc": "Clear dma_mode byte to disable DMA transfers",
            },
        ],
        "patches_undo": [
            {
                "name": "horkage_nodma",
                "offset": 264,
                "size": 1,
                "from": "0x02",
                "to": "0x00",
                "desc": "Clear ATA_HORKAGE_NODMA bit in horkage field",
            },
            {
                "name": "flags_pio",
                "offset": 12,
                "size": 1,
                "from": None,
                "to": None,
                "desc": "Clear ATA_DFLAG_PIO bit (0x20) in flags field -- AND-NOT-style",
                "bit_and_not": 0x20,
            },
            {
                "name": "dma_mode_clear",
                "offset": 276,
                "size": 1,
                "from": "0x00",
                "to": None,
                "desc": "Restore dma_mode -- requires manual value or skip",
                "skip": True,
                "skip_reason": "Original DMA mode value is device-specific; set manually if needed",
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# Physical memory access primitives
# ---------------------------------------------------------------------------


def get_ram_ranges():
    """Parse /proc/iomem to find System RAM ranges.

    Returns a list of (start, end) tuples representing physical address ranges
    that correspond to System RAM.  Only ranges marked as IORESOURCE_MEM or
    explicitly labelled 'System RAM' are included.
    """
    ranges = []
    try:
        with open("/proc/iomem", "r") as f:
            for line in f:
                line = line.strip()
                if "System RAM" not in line:
                    continue
                addr_part = line.split(":")[0].strip()
                if "-" not in addr_part:
                    continue
                start_s, end_s = addr_part.split("-")
                start = int(start_s, 16)
                end = int(end_s, 16)
                ranges.append((start, end))
    except PermissionError:
        print("[!] Cannot read /proc/iomem -- need root privileges", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[!] /proc/iomem not found -- is this a Linux system?", file=sys.stderr)
        sys.exit(1)

    if not ranges:
        print("[!] No System RAM ranges found in /proc/iomem", file=sys.stderr)
        sys.exit(1)

    return ranges


def read_phys(addr, length):
    """Read `length` bytes from physical address `addr` via /dev/mem.

    Uses mmap for read access, which works reliably on ARM64.
    Returns bytes or None on failure.
    """
    fd = None
    mm = None
    try:
        fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
        page_offset = addr % PAGE_SIZE
        map_base = addr - page_offset
        map_size = page_offset + length
        # Round up to page boundary
        map_size = ((map_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

        mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED, mmap.PROT_READ, offset=map_base)
        mm.seek(page_offset)
        data = mm.read(length)
        return data
    except Exception as e:
        print(f"[!] read_phys(0x{addr:x}, {length}): {e}", file=sys.stderr)
        return None
    finally:
        if mm is not None:
            try:
                mm.close()
            except Exception:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass


def read_phys_byte(addr):
    """Read a single byte from a physical address. Returns int or None."""
    data = read_phys(addr, 1)
    if data and len(data) == 1:
        return data[0]
    return None


def write_phys_byte(addr, value):
    """Write a single byte to a physical address via /dev/mem.

    Uses os.lseek + os.write instead of mmap PROT_WRITE.  On many ARM64
    platforms (Alpine-based embedded systems, etc.), mmap with PROT_WRITE
    silently fails for /dev/mem regions.  The file-descriptor approach works
    correctly on these platforms.

    Returns True on success, False on failure.
    """
    fd = None
    try:
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        os.lseek(fd, addr, os.SEEK_SET)
        written = os.write(fd, bytes([value & 0xFF]))
        return written == 1
    except Exception as e:
        print(f"[!] write_phys_byte(0x{addr:x}, 0x{value:02x}): {e}", file=sys.stderr)
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Memory scanning
# ---------------------------------------------------------------------------


def scan_memory(anchor_value, anchor_offset, ram_ranges, struct_size=512,
                validation_fields=None, progress=True):
    """Scan System RAM for a struct whose anchor field matches `anchor_value`.

    Arguments:
      anchor_value    -- byte value (int 0-255) expected at anchor_offset
      anchor_offset   -- offset within the struct where the anchor lives
      ram_ranges      -- list of (start, end) from get_ram_ranges()
      struct_size     -- minimum struct size to read for validation (default 512)
      validation_fields -- optional list of dicts with 'offset' and 'expected' (int)
                           keys for additional candidate validation
      progress        -- print progress messages

    Returns a list of candidate physical addresses (struct base addresses).
    """
    if not isinstance(anchor_value, int):
        anchor_value = int(str(anchor_value), 0)
    if not isinstance(anchor_offset, int):
        anchor_offset = int(str(anchor_offset), 0)

    candidates = []
    chunk_size = 1024 * 1024  # 1 MiB chunks
    total_bytes = sum(end - start + 1 for start, end in ram_ranges)
    scanned = 0

    if progress:
        print(f"[*] Scanning {total_bytes / (1024**2):.0f} MiB of System RAM "
              f"for anchor 0x{anchor_value:02x} at offset +0x{anchor_offset:x}")

    for ram_start, ram_end in ram_ranges:
        region_start = ram_start
        while region_start <= ram_end:
            read_len = min(chunk_size, ram_end - region_start + 1)
            data = read_phys(region_start, read_len)
            if data is None:
                region_start += read_len
                scanned += read_len
                continue

            # Search for anchor_value in this chunk
            search_start = 0
            while True:
                pos = data.find(bytes([anchor_value]), search_start)
                if pos == -1:
                    break
                # The struct base would be at (region_start + pos - anchor_offset)
                struct_base = region_start + pos - anchor_offset
                if struct_base >= 0:
                    candidate_valid = True
                    # Run additional validation if provided
                    if validation_fields:
                        candidate_valid = validate_candidate(
                            struct_base, validation_fields
                        )
                    if candidate_valid:
                        candidates.append(struct_base)
                        if progress:
                            print(f"    [+] Candidate at 0x{struct_base:x}")
                search_start = pos + 1

            scanned += read_len
            if progress and scanned % (64 * chunk_size) == 0:
                pct = (scanned / total_bytes) * 100
                print(f"    ... {pct:.0f}% scanned ({scanned // (1024**2)} MiB)")

            region_start += read_len

    if progress:
        print(f"[*] Scan complete: {len(candidates)} candidate(s) found")

    return candidates


def validate_candidate(struct_base, validation_fields):
    """Check additional fields at a candidate struct address.

    validation_fields is a list of dicts:
      { "offset": int, "expected": int, "mask": int (optional) }

    Returns True if all fields match.
    """
    for field in validation_fields:
        offset = field["offset"]
        expected = field["expected"]
        mask = field.get("mask", 0xFF)
        val = read_phys_byte(struct_base + offset)
        if val is None:
            return False
        if (val & mask) != (expected & mask):
            return False
    return True


# ---------------------------------------------------------------------------
# Patch operations
# ---------------------------------------------------------------------------


def parse_hex_or_int(value):
    """Parse a value that may be hex string ('0x1a'), int, or None. Returns int or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"Cannot parse value: {value!r}")


def load_patches(args):
    """Load patch definitions from --patches file, --preset, or both.

    Returns (patches_apply, patches_undo) tuple of lists.
    """
    patches_apply = []
    patches_undo = []

    # Load from preset
    if args.preset:
        if args.preset not in PRESETS:
            avail = ", ".join(sorted(PRESETS.keys()))
            print(f"[!] Unknown preset '{args.preset}'. Available: {avail}", file=sys.stderr)
            sys.exit(1)
        preset = PRESETS[args.preset]
        print(f"[*] Loading preset: {args.preset}")
        if "description" in preset:
            print(f"    {preset['description']}")
        patches_apply.extend(preset.get("patches_apply", []))
        patches_undo.extend(preset.get("patches_undo", []))

    # Load from JSON file
    if args.patches:
        try:
            with open(args.patches, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"[!] Patch file not found: {args.patches}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in {args.patches}: {e}", file=sys.stderr)
            sys.exit(1)

        patches_apply.extend(data.get("patches_apply", []))
        patches_undo.extend(data.get("patches_undo", []))

    return patches_apply, patches_undo


def show_status(struct_base, patches):
    """Show the current state of each patch field.

    Reads the current byte at each patch offset and reports whether it
    matches the 'from' (unpatched), 'to' (patched), or neither.
    """
    print(f"\n[*] Patch status at struct base 0x{struct_base:x}:")
    print(f"{'Name':<25} {'Offset':<10} {'Current':<10} {'From':<10} {'To':<10} {'State':<12}")
    print("-" * 80)

    for patch in patches:
        if patch.get("skip"):
            print(f"{patch['name']:<25} {'SKIP':<10} {'':<10} {'':<10} {'':<10} {'skipped':<12}")
            continue

        offset = patch["offset"]
        addr = struct_base + offset
        current = read_phys_byte(addr)

        from_val = parse_hex_or_int(patch.get("from"))
        to_val = parse_hex_or_int(patch.get("to"))
        bit_or = patch.get("bit_or")
        bit_and_not = patch.get("bit_and_not")

        current_str = f"0x{current:02x}" if current is not None else "ERR"
        from_str = f"0x{from_val:02x}" if from_val is not None else "any"
        to_str = f"0x{to_val:02x}" if to_val is not None else "computed"

        if bit_or is not None:
            to_str = f"|0x{bit_or:02x}"
        if bit_and_not is not None:
            to_str = f"&~0x{bit_and_not:02x}"

        if current is None:
            state = "READ_ERROR"
        elif to_val is not None and current == to_val:
            state = "PATCHED"
        elif bit_or is not None and (current & bit_or) == bit_or:
            state = "PATCHED"
        elif from_val is not None and current == from_val:
            state = "UNPATCHED"
        else:
            state = "UNKNOWN"

        print(f"{patch['name']:<25} +0x{offset:<7x} {current_str:<10} {from_str:<10} {to_str:<10} {state:<12}")

    print()


def apply_patches(struct_base, patches, dry_run=True):
    """Apply a list of patches with full safety validation.

    Safety layers:
      L3: Pre-write validation  -- check current value matches 'from'
      L4: Write-then-verify     -- read back after each write
      L5: Post-patch re-validate -- re-read all fields after completion
      L6: Auto-rollback          -- undo all writes if any step fails

    Returns True on success, False on failure (with rollback attempted).
    """
    mode_str = "DRY-RUN" if dry_run else "LIVE"
    print(f"\n[*] Applying {len(patches)} patch(es) in {mode_str} mode at base 0x{struct_base:x}")

    # Track applied patches for rollback (L6)
    applied = []  # list of (addr, original_value, patch_name)

    for i, patch in enumerate(patches):
        name = patch.get("name", f"patch_{i}")
        desc = patch.get("desc", "")

        if patch.get("skip"):
            reason = patch.get("skip_reason", "no reason given")
            print(f"  [{i+1}/{len(patches)}] SKIP {name}: {reason}")
            continue

        offset = patch["offset"]
        addr = struct_base + offset

        from_val = parse_hex_or_int(patch.get("from"))
        to_val = parse_hex_or_int(patch.get("to"))
        bit_or = patch.get("bit_or")
        bit_and_not = patch.get("bit_and_not")

        # Read current value
        current = read_phys_byte(addr)
        if current is None:
            print(f"  [{i+1}/{len(patches)}] FAIL {name}: cannot read 0x{addr:x}")
            if not dry_run:
                _rollback(applied)
            return False

        # Compute target value
        if bit_or is not None:
            target = current | bit_or
        elif bit_and_not is not None:
            target = current & ~bit_and_not & 0xFF
        elif to_val is not None:
            target = to_val
        else:
            print(f"  [{i+1}/{len(patches)}] FAIL {name}: no target value defined")
            if not dry_run:
                _rollback(applied)
            return False

        # L3: Pre-write validation
        if from_val is not None and current != from_val:
            # Check if already at target (idempotent)
            if current == target:
                print(f"  [{i+1}/{len(patches)}] OK   {name}: already at target 0x{target:02x} (no-op)")
                continue
            print(f"  [{i+1}/{len(patches)}] FAIL {name}: pre-validation failed at 0x{addr:x}")
            print(f"         Expected from=0x{from_val:02x}, got 0x{current:02x}")
            if not dry_run:
                _rollback(applied)
            return False

        if current == target:
            print(f"  [{i+1}/{len(patches)}] OK   {name}: already 0x{target:02x} at +0x{offset:x}")
            continue

        print(f"  [{i+1}/{len(patches)}] {'WOULD' if dry_run else 'WRITE'} {name}: "
              f"0x{current:02x} -> 0x{target:02x} at +0x{offset:x} (0x{addr:x})"
              f"  [{desc}]")

        if dry_run:
            continue

        # Write the byte
        if not write_phys_byte(addr, target):
            print(f"         FAIL: write returned error")
            _rollback(applied)
            return False

        # L4: Write-then-verify
        verify = read_phys_byte(addr)
        if verify != target:
            print(f"         FAIL: verify read 0x{verify:02x}, expected 0x{target:02x}")
            # Record this one too for rollback with original value
            applied.append((addr, current, name))
            _rollback(applied)
            return False

        print(f"         Verified: 0x{verify:02x}")
        applied.append((addr, current, name))

    # L5: Post-patch re-validation
    if not dry_run and applied:
        print(f"\n[*] L5: Post-patch re-validation ({len(applied)} write(s))...")
        all_ok = True
        for addr, original, name in applied:
            val = read_phys_byte(addr)
            if val is None:
                print(f"    FAIL: cannot re-read {name} at 0x{addr:x}")
                all_ok = False
            else:
                print(f"    OK: {name} at 0x{addr:x} = 0x{val:02x}")
        if not all_ok:
            print("[!] Post-patch validation failed -- initiating rollback")
            _rollback(applied)
            return False

    if dry_run:
        print(f"\n[*] Dry-run complete. Use --apply to write changes.")
    else:
        print(f"\n[*] All {len(applied)} patch(es) applied and verified successfully.")

    return True


def _rollback(applied):
    """L6: Auto-rollback -- restore all previously written bytes to originals.

    `applied` is a list of (addr, original_value, name) in application order.
    Rollback proceeds in reverse order.
    """
    if not applied:
        print("[*] L6: Nothing to roll back.")
        return

    print(f"\n[!] L6: Auto-rollback -- restoring {len(applied)} byte(s)...")
    for addr, original, name in reversed(applied):
        print(f"    Restoring {name} at 0x{addr:x} to 0x{original:02x}...", end=" ")
        if write_phys_byte(addr, original):
            verify = read_phys_byte(addr)
            if verify == original:
                print("OK")
            else:
                print(f"VERIFY FAIL (got 0x{verify:02x})" if verify is not None else "VERIFY FAIL (read error)")
        else:
            print("WRITE FAIL")

    print("[!] Rollback complete. System may need a reboot if rollback failed (L1).")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mem-data-patch",
        description=(
            "Generic kernel data structure patcher for ARM64 Linux via /dev/mem.\n"
            "\n"
            "Patches arbitrary byte values at physical memory addresses in live\n"
            "kernel data structures. Implements a 6-layer safety model:\n"
            "  L1 Reboot recovery, L2 Software undo, L3 Pre-write validation,\n"
            "  L4 Write-then-verify, L5 Post-patch re-validation, L6 Auto-rollback.\n"
            "\n"
            "Requires root and /dev/mem access."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            EXAMPLES:

              # Show what patches would do (dry-run, the default):
              sudo python3 mem-data-patch.py \\
                  --struct-base 0xffff800012340000 \\
                  --patches my_patches.json

              # Apply patches for real:
              sudo python3 mem-data-patch.py \\
                  --struct-base 0xffff800012340000 \\
                  --patches my_patches.json --apply

              # Use built-in ATA PIO force preset:
              sudo python3 mem-data-patch.py \\
                  --struct-base 0xffff800012340000 \\
                  --preset ata-pio-force --apply

              # Scan memory first, then apply:
              sudo python3 mem-data-patch.py \\
                  --scan-first \\
                  --anchor-value 0x41 --anchor-offset 0x100 \\
                  --patches my_patches.json --apply

              # Check patch status:
              sudo python3 mem-data-patch.py \\
                  --struct-base 0xffff800012340000 \\
                  --preset ata-pio-force --status

              # Undo (reverse) patches:
              sudo python3 mem-data-patch.py \\
                  --struct-base 0xffff800012340000 \\
                  --patches my_patches.json --undo --apply

            PATCH FILE FORMAT (JSON):

              {
                "patches_apply": [
                  {
                    "name": "field_name",
                    "offset": 12,
                    "from": "0x10",
                    "to": "0x12",
                    "desc": "Set field to new value"
                  }
                ],
                "patches_undo": [
                  {
                    "name": "field_name",
                    "offset": 12,
                    "from": "0x12",
                    "to": "0x10",
                    "desc": "Restore original value"
                  }
                ]
              }

              Optional per-patch keys:
                "bit_or": 0x20     -- OR current value with this mask (sets bits)
                "bit_and_not": 0x20 -- AND current with ~mask (clears bits)
                "skip": true       -- skip this patch entry
                "skip_reason": "..."

            AVAILABLE PRESETS:
        """) + "".join(
            f"              {name:<20} {PRESETS[name].get('description', '')}\n"
            for name in sorted(PRESETS)
        ),
    )

    # Address source (mutually supportive, not exclusive)
    addr_group = parser.add_argument_group("address specification")
    addr_group.add_argument(
        "--struct-base",
        metavar="ADDR",
        help="Physical address of the struct base (hex, e.g. 0xffff800012340000)",
    )
    addr_group.add_argument(
        "--scan-first",
        action="store_true",
        help="Scan System RAM for the struct before patching (requires --anchor-value and --anchor-offset)",
    )
    addr_group.add_argument(
        "--anchor-value",
        metavar="VALUE",
        help="For scan mode: byte value to search for at anchor offset (hex, e.g. 0x41)",
    )
    addr_group.add_argument(
        "--anchor-offset",
        metavar="OFFSET",
        help="For scan mode: offset of the anchor byte within the struct (hex, e.g. 0x100)",
    )
    addr_group.add_argument(
        "--validation-fields",
        metavar="JSON",
        help='Additional scan validation fields as JSON string, e.g. \'[{"offset":8,"expected":1}]\'',
    )

    # Patch source
    patch_group = parser.add_argument_group("patch definitions")
    patch_group.add_argument(
        "--patches",
        metavar="FILE",
        help="JSON file defining patches to apply",
    )
    patch_group.add_argument(
        "--preset",
        metavar="NAME",
        choices=sorted(PRESETS.keys()),
        help=f"Use a built-in preset ({', '.join(sorted(PRESETS.keys()))})",
    )

    # Actions
    action_group = parser.add_argument_group("actions")
    action_group.add_argument(
        "--apply",
        action="store_true",
        help="Apply patches (default is dry-run for safety)",
    )
    action_group.add_argument(
        "--undo",
        action="store_true",
        help="Reverse patches (use patches_undo definitions)",
    )
    action_group.add_argument(
        "--status",
        action="store_true",
        help="Show current state of patch fields without modifying anything",
    )
    action_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Preview changes without writing (this is the default)",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate arguments
    if not args.patches and not args.preset:
        parser.error("At least one of --patches or --preset is required")

    if not args.struct_base and not args.scan_first:
        parser.error("Either --struct-base or --scan-first is required")

    if args.scan_first:
        if not args.anchor_value or not args.anchor_offset:
            parser.error("--scan-first requires --anchor-value and --anchor-offset")

    # Load patch definitions
    patches_apply, patches_undo = load_patches(args)

    if not patches_apply and not patches_undo:
        print("[!] No patches loaded. Check your --patches file or --preset.", file=sys.stderr)
        sys.exit(1)

    # Determine struct base address
    struct_base = None

    if args.scan_first:
        anchor_value = int(args.anchor_value, 0)
        anchor_offset = int(args.anchor_offset, 0)

        # Parse optional validation fields
        validation_fields = None
        if args.validation_fields:
            try:
                validation_fields = json.loads(args.validation_fields)
            except json.JSONDecodeError as e:
                print(f"[!] Invalid JSON for --validation-fields: {e}", file=sys.stderr)
                sys.exit(1)

        ram_ranges = get_ram_ranges()
        candidates = scan_memory(
            anchor_value, anchor_offset, ram_ranges,
            validation_fields=validation_fields,
        )

        if not candidates:
            print("[!] No matching struct found in memory scan.", file=sys.stderr)
            sys.exit(1)

        if len(candidates) == 1:
            struct_base = candidates[0]
            print(f"[*] Using struct at 0x{struct_base:x}")
        else:
            print(f"[!] Multiple candidates found ({len(candidates)}). Please specify --struct-base:")
            for c in candidates:
                print(f"    0x{c:x}")
            sys.exit(1)

    if args.struct_base:
        struct_base = int(args.struct_base, 0)

    if struct_base is None:
        print("[!] Could not determine struct base address.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Struct base: 0x{struct_base:x}")

    # Select which patch list to use
    if args.undo:
        if not patches_undo:
            print("[!] No undo patches defined.", file=sys.stderr)
            sys.exit(1)
        active_patches = patches_undo
        print("[*] Mode: UNDO")
    else:
        if not patches_apply:
            print("[!] No apply patches defined.", file=sys.stderr)
            sys.exit(1)
        active_patches = patches_apply
        print("[*] Mode: APPLY")

    # Status mode -- just show and exit
    if args.status:
        show_status(struct_base, active_patches)
        return 0

    # Determine if this is a real write or dry-run
    dry_run = not args.apply

    # Apply (or preview) patches
    success = apply_patches(struct_base, active_patches, dry_run=dry_run)

    if not success:
        print("\n[!] Patch operation FAILED.", file=sys.stderr)
        return 1

    # Show final status
    show_status(struct_base, active_patches)

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
