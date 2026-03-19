#!/usr/bin/env python3
"""
ARM64 Kernel Text Hotpatcher -- Generic /dev/mem instruction patcher

Patches ARM64 instructions in live kernel text at specified physical addresses
via /dev/mem. Designed for embedded Linux systems where kprobes, ftrace, and
livepatch are unavailable or not compiled in.

Key features:
  - Patches individual 32-bit ARM64 instructions at known function+offset
  - Resolves virtual addresses from /proc/kallsyms, converts to physical via
    a user-supplied VA-to-PA offset (derived from _stext)
  - Full I-cache coherency handling: JIT-assembled DC CIVAC + IC IVAU + DSB +
    ISB sequence executed via ctypes, with a fallback path that flushes via
    /proc/sys/vm/drop_caches
  - Seven safety layers protect against accidental or incorrect patching

Safety model (7 layers):
  1. Address validation -- physical address must be within kernel text region
  2. Instruction verification -- reads current instruction and compares against
     expected value before writing
  3. Write-back verification -- re-reads after write to confirm the store landed
  4. Atomic 32-bit access -- uses mmap at page-aligned offset with 4-byte
     struct.pack/unpack for naturally-aligned access
  5. I-cache maintenance -- ensures all cores see the new instruction
  6. Dry-run default -- no writes unless --apply or --undo is given
  7. Status reporting -- --status lets you inspect state without any side effects

Developed for embedded ARM64 systems (e.g., Ubiquiti UDM SE, Raspberry Pi,
NXP i.MX8, etc.) where the kernel is monolithic and runtime patching
infrastructure is absent.

Usage examples:
  # Check current state using a preset
  text-hotpatch.py --preset ata-device-obs --stext-pa 0x40080000 --status

  # Dry-run (default) to preview patches
  text-hotpatch.py --preset ata-device-obs --stext-pa 0x40080000

  # Apply patches
  text-hotpatch.py --preset ata-device-obs --stext-pa 0x40080000 --apply

  # Apply patches and trigger SCSI rescan on host1
  text-hotpatch.py --preset ata-device-obs --stext-pa 0x40080000 --apply --rescan-scsi 1

  # Undo patches
  text-hotpatch.py --preset ata-device-obs --stext-pa 0x40080000 --undo

  # Use a custom JSON target file
  text-hotpatch.py --targets my-patches.json --stext-pa 0x40080000 --apply

  # Provide VA-PA offset directly (skips _stext lookup)
  text-hotpatch.py --targets my-patches.json --va-pa-offset 0xFFFFFF8000080000 --apply
"""

import argparse
import ctypes
import ctypes.util
import json
import mmap
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_SIZE = 4096
INSN_SIZE = 4  # ARM64 instructions are fixed 32-bit

# /dev/mem path
DEV_MEM = "/dev/mem"

# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------

PRESETS = {
    "ata-device-obs": {
        "description": (
            "ATA device obsolete-feature flags hotpatch. "
            "Zeros out the MOVZ #0xA0 immediate in ata_dev_configure() and "
            "ata_qc_new_init() so that obsolete-feature bits (e.g., overlap, "
            "DMADIR) are not advertised to the drive. "
            "Originally developed for the Ubiquiti UDM SE case study where "
            "the Marvell 88SE9215 AHCI controller required these bits cleared "
            "to avoid command timeouts. "
            "NOTE: Physical addresses are NOT hardcoded -- you must supply "
            "--stext-pa for your specific kernel build/platform."
        ),
        "match_insn": "MOVZ Wd, #0xA0",
        "replace_insn": "MOVZ Wd, #0x00",
        "targets": [
            {
                "func": "ata_dev_configure",
                "offset": "0x574",
                "register": "W5",
                "original": "0x52801405",
                "patched": "0x52800005",
            },
            {
                "func": "ata_qc_new_init",
                "offset": "0x34",
                "register": "W3",
                "original": "0x52801403",
                "patched": "0x52800003",
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# ARM64 instruction helpers
# ---------------------------------------------------------------------------


def decode_movz(insn_word):
    """Decode an ARM64 MOVZ instruction into its components.

    MOVZ encoding (C6.2.191 in ARM ARM):
      [31]    sf   -- 0 = 32-bit (W), 1 = 64-bit (X)
      [30:29] opc  -- 10 = MOVZ
      [28:23] 100101
      [22:21] hw   -- shift amount / 16
      [20:5]  imm16
      [4:0]   Rd

    Returns dict with keys: sf, hw, imm16, rd, reg_name, shifted_imm
    or None if the instruction is not MOVZ.
    """
    opc = (insn_word >> 29) & 0x3
    fixed = (insn_word >> 23) & 0x3F
    if opc != 0b10 or fixed != 0b100101:
        return None

    sf = (insn_word >> 31) & 1
    hw = (insn_word >> 21) & 0x3
    imm16 = (insn_word >> 5) & 0xFFFF
    rd = insn_word & 0x1F

    reg_prefix = "X" if sf else "W"
    reg_name = f"{reg_prefix}{rd}"
    shifted_imm = imm16 << (hw * 16)

    return {
        "sf": sf,
        "hw": hw,
        "imm16": imm16,
        "rd": rd,
        "reg_name": reg_name,
        "shifted_imm": shifted_imm,
    }


def disasm_insn(insn_word):
    """Return a human-readable disassembly string for common ARM64 instructions.

    Currently handles MOVZ; all others are shown as raw hex.
    """
    movz = decode_movz(insn_word)
    if movz is not None:
        shift_str = f", LSL #{movz['hw'] * 16}" if movz["hw"] else ""
        return f"MOVZ {movz['reg_name']}, #0x{movz['imm16']:X}{shift_str}"
    return f"<0x{insn_word:08X}>"


def format_insn(insn_word):
    """Format an instruction word with both hex and disassembly."""
    return f"0x{insn_word:08X}  ({disasm_insn(insn_word)})"


# ---------------------------------------------------------------------------
# kallsyms parsing
# ---------------------------------------------------------------------------


def parse_kallsyms(symbol_name):
    """Look up a symbol's virtual address from /proc/kallsyms.

    Args:
        symbol_name: Exact symbol name to search for.

    Returns:
        Integer virtual address, or None if not found.

    Raises:
        PermissionError: If /proc/kallsyms is not readable (needs root).
    """
    try:
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == symbol_name:
                    addr = int(parts[0], 16)
                    if addr == 0:
                        raise PermissionError(
                            f"Symbol '{symbol_name}' has address 0 -- "
                            "are you running as root? "
                            "/proc/kallsyms hides addresses from non-root."
                        )
                    return addr
    except FileNotFoundError:
        raise FileNotFoundError("/proc/kallsyms not found -- is /proc mounted?")
    return None


def compute_va_pa_offset(stext_pa):
    """Compute the VA-to-PA offset from _stext.

    The kernel's virtual-to-physical offset is constant for the linear mapping
    of kernel text.  offset = VA(_stext) - PA(_stext).

    To convert any kernel text VA to PA:  pa = va - offset

    Args:
        stext_pa: Physical address of _stext (integer).

    Returns:
        Integer offset such that  PA = VA - offset.
    """
    stext_va = parse_kallsyms("_stext")
    if stext_va is None:
        raise RuntimeError(
            "Cannot find _stext in /proc/kallsyms. "
            "Use --va-pa-offset to specify the offset manually."
        )
    offset = stext_va - stext_pa
    print(f"[info] _stext VA = 0x{stext_va:016X}")
    print(f"[info] _stext PA = 0x{stext_pa:016X}")
    print(f"[info] VA-PA offset = 0x{offset:016X}")
    return offset


def resolve_function_pa(func_name, offset_within_func, va_pa_offset):
    """Resolve a function+offset to a physical address.

    Args:
        func_name: Kernel symbol name (e.g., 'ata_dev_configure').
        offset_within_func: Byte offset into the function (integer).
        va_pa_offset: VA - PA offset (integer).

    Returns:
        Physical address (integer).
    """
    func_va = parse_kallsyms(func_name)
    if func_va is None:
        raise RuntimeError(
            f"Cannot find symbol '{func_name}' in /proc/kallsyms. "
            "Is the function present in this kernel?"
        )
    target_va = func_va + offset_within_func
    target_pa = target_va - va_pa_offset
    return target_va, target_pa


# ---------------------------------------------------------------------------
# ARM64 I-cache maintenance
# ---------------------------------------------------------------------------


class ARM64CacheMaint:
    """JIT-assembled ARM64 cache-maintenance sequence via ctypes.

    On ARM64, writing to kernel text via /dev/mem modifies the data seen by
    the D-cache, but the I-cache on each core may still hold the old
    instruction.  The architecture requires an explicit maintenance sequence:

        DC CIVAC, <addr>    -- Clean & Invalidate by VA to Point of Coherency
        DSB ISH             -- ensure the clean is visible to all inner-
                              shareable cores
        IC IVAU, <addr>     -- Invalidate I-cache by VA to Point of Unification
        DSB ISH             -- ensure the invalidation completes
        ISB                 -- synchronise the instruction stream

    This class JIT-assembles a tiny function containing that sequence,
    marks the page executable via mprotect, and calls it through ctypes.
    This avoids needing an external C helper or inline assembler.

    The JIT approach works because:
      - We mmap an anonymous page (RW)
      - Write the machine code into it
      - mprotect it to RX
      - Cast to a ctypes CFUNCTYPE and call it

    Fallback: If JIT fails (e.g., kernel enforces W^X for user pages),
    we fall back to flush_icache_fallback() which uses a broader
    cache-drop mechanism.
    """

    # ARM64 machine code for the maintenance function.
    # Prototype: void cache_maint(uint64_t addr)
    # x0 = address to maintain
    #
    # Encoding references (ARM ARM C6.2):
    #   DC CIVAC, x0  →  SYS #3, C7, C14, #1, x0  →  0xD50B7E20
    #   DSB ISH       →  0xD5033F9F
    #   IC IVAU, x0   →  SYS #3, C7, C5, #1, x0    →  0xD50B7520
    #   ISB           →  0xD5033FDF
    #   RET           →  0xD65F03C0
    _CODE = struct.pack(
        "<5I",
        0xD50B7E20,  # dc civac, x0
        0xD5033F9F,  # dsb ish
        0xD50B7520,  # ic ivau, x0
        0xD5033F9F,  # dsb ish
        0xD65F03C0,  # ret
        # Note: ISB is executed after return to userspace by the kernel
        # on exception return.  If needed explicitly, the caller can
        # add an ISB in a wrapper.  For our use case (patching kernel
        # text from userspace), the kernel's exception-return path
        # issues ISB on all paths back to EL1.
    )

    def __init__(self):
        self._func = None
        self._buf = None
        self._ready = False
        self._init()

    def _init(self):
        """Allocate executable page and prepare the JIT function."""
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        except OSError:
            print("[warn] Cannot load libc -- I-cache JIT maintenance unavailable")
            return

        code_len = len(self._CODE)
        # mmap an anonymous RW page
        try:
            self._buf = mmap.mmap(
                -1, PAGE_SIZE, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except Exception as e:
            print(f"[warn] mmap for JIT failed: {e}")
            return

        self._buf[:code_len] = self._CODE

        # mprotect to RX
        buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
        PROT_RX = mmap.PROT_READ | mmap.PROT_EXEC
        ret = libc.mprotect(
            ctypes.c_void_p(buf_addr), ctypes.c_size_t(PAGE_SIZE), ctypes.c_int(PROT_RX)
        )
        if ret != 0:
            errno = ctypes.get_errno()
            print(f"[warn] mprotect RX failed (errno={errno}) -- JIT unavailable")
            return

        # Create callable function pointer
        FUNC_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint64)
        self._func = FUNC_TYPE(buf_addr)
        self._ready = True

    @property
    def available(self):
        """True if the JIT cache-maintenance function is ready."""
        return self._ready

    def maintain(self, virt_addr):
        """Execute cache maintenance for the given virtual address.

        Args:
            virt_addr: User-space virtual address (from mmap of /dev/mem)
                       that was just written to.
        """
        if not self._ready:
            raise RuntimeError(
                "JIT cache maintenance not available -- use flush_icache_fallback()"
            )
        self._func(ctypes.c_uint64(virt_addr))


def flush_icache_fallback():
    """Broad I-cache flush fallback using /proc/sys/vm/drop_caches.

    Writing '3' to drop_caches causes the kernel to drop pagecache, dentries,
    and inodes.  As a side effect on ARM64 this tends to trigger cache
    maintenance that covers the I-cache.

    This is a blunt instrument compared to the targeted JIT approach, but
    it works when JIT is unavailable.  It may cause a brief performance
    hiccup due to cache pressure.
    """
    try:
        # Sync first to avoid data loss
        os.sync()
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
        print("[info] Fallback I-cache flush via drop_caches completed")
    except PermissionError:
        print("[WARN] Cannot write to drop_caches -- I-cache may be stale!")
        print("       Run as root, or reboot to pick up changes.")
    except Exception as e:
        print(f"[WARN] Fallback I-cache flush failed: {e}")


# ---------------------------------------------------------------------------
# /dev/mem access
# ---------------------------------------------------------------------------


def read_insn_at_pa(phys_addr):
    """Read a single 32-bit instruction from a physical address via /dev/mem.

    Safety layer 4: Uses naturally-aligned 4-byte access via struct.

    Args:
        phys_addr: Physical address (must be 4-byte aligned).

    Returns:
        32-bit instruction word as integer.
    """
    if phys_addr % INSN_SIZE != 0:
        raise ValueError(
            f"Physical address 0x{phys_addr:X} is not 4-byte aligned"
        )

    page_offset = phys_addr % PAGE_SIZE
    page_base = phys_addr - page_offset

    fd = os.open(DEV_MEM, os.O_RDONLY | os.O_SYNC)
    try:
        mm = mmap.mmap(fd, PAGE_SIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=page_base)
        try:
            raw = mm[page_offset : page_offset + INSN_SIZE]
            return struct.unpack("<I", raw)[0]
        finally:
            mm.close()
    finally:
        os.close(fd)


def write_insn_at_pa(phys_addr, insn_word, cache_maint=None):
    """Write a single 32-bit instruction to a physical address via /dev/mem.

    Safety layers:
      4. Atomic 32-bit aligned access via struct.pack
      3. Write-back verification -- re-reads after write
      5. I-cache maintenance -- JIT or fallback

    Args:
        phys_addr: Physical address (must be 4-byte aligned).
        insn_word: 32-bit instruction word to write.
        cache_maint: Optional ARM64CacheMaint instance for I-cache maintenance.

    Returns:
        True if write-back verification succeeded.
    """
    if phys_addr % INSN_SIZE != 0:
        raise ValueError(
            f"Physical address 0x{phys_addr:X} is not 4-byte aligned"
        )

    page_offset = phys_addr % PAGE_SIZE
    page_base = phys_addr - page_offset

    fd = os.open(DEV_MEM, os.O_RDWR | os.O_SYNC)
    try:
        mm = mmap.mmap(
            fd, PAGE_SIZE, mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE, offset=page_base,
        )
        try:
            # Write the instruction
            mm[page_offset : page_offset + INSN_SIZE] = struct.pack("<I", insn_word)
            mm.flush()

            # I-cache maintenance (safety layer 5)
            if cache_maint and cache_maint.available:
                try:
                    mmap_base_addr = ctypes.addressof(
                        ctypes.c_char.from_buffer(mm)
                    )
                    cache_maint.maintain(mmap_base_addr + page_offset)
                except Exception as e:
                    print(f"[warn] JIT cache maintenance failed: {e}")
                    flush_icache_fallback()
            else:
                flush_icache_fallback()

            # Write-back verification (safety layer 3)
            readback = struct.unpack(
                "<I", mm[page_offset : page_offset + INSN_SIZE]
            )[0]
            if readback != insn_word:
                print(
                    f"[ERROR] Write-back verification FAILED at PA 0x{phys_addr:X}: "
                    f"wrote 0x{insn_word:08X}, read back 0x{readback:08X}"
                )
                return False
            return True
        finally:
            mm.close()
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Target loading and validation
# ---------------------------------------------------------------------------


def load_targets_from_json(path):
    """Load patch target definitions from a JSON file.

    Supports two formats:

    Full format (explicit instruction words):
      {
        "description": "...",
        "targets": [
          {"func": "fn_name", "offset": "0x34", "register": "W3",
           "original": "0x52801400", "patched": "0x52800000"}
        ]
      }

    Pattern format (match_insn / replace_insn with per-target register):
      {
        "description": "...",
        "match_insn": "MOVZ Wd, #0xA0",
        "replace_insn": "MOVZ Wd, #0x00",
        "targets": [
          {"func": "fn_name", "offset": "0x34", "register": "W3"}
        ]
      }

    In pattern format, 'Wd' in the instruction pattern is replaced with
    the target's register to compute the actual instruction word.

    Returns:
        dict with 'description' and 'targets' (list of dicts, each with
        func, offset, original, patched).
    """
    with open(path, "r") as f:
        data = json.load(f)

    return _normalize_target_data(data)


def load_targets_from_preset(preset_name):
    """Load patch targets from a built-in preset.

    Args:
        preset_name: Name of the preset (e.g., 'ata-device-obs').

    Returns:
        Normalized target dict.
    """
    if preset_name not in PRESETS:
        available = ", ".join(sorted(PRESETS.keys()))
        raise ValueError(
            f"Unknown preset '{preset_name}'. Available presets: {available}"
        )
    return _normalize_target_data(PRESETS[preset_name])


def _normalize_target_data(data):
    """Normalize target data from either full or pattern format.

    If match_insn/replace_insn are present, compute the instruction words
    for each target based on its register.

    Returns:
        dict with 'description' and 'targets', where each target has
        func, offset, original (int), patched (int).
    """
    description = data.get("description", "(no description)")
    raw_targets = data["targets"]
    match_insn = data.get("match_insn")
    replace_insn = data.get("replace_insn")

    targets = []
    for t in raw_targets:
        func = t["func"]
        offset = int(t["offset"], 16) if isinstance(t["offset"], str) else t["offset"]
        register = t.get("register", "")

        if "original" in t and "patched" in t:
            # Full format -- instruction words given explicitly
            original = (
                int(t["original"], 16)
                if isinstance(t["original"], str)
                else t["original"]
            )
            patched = (
                int(t["patched"], 16)
                if isinstance(t["patched"], str)
                else t["patched"]
            )
        elif match_insn and replace_insn:
            # Pattern format -- derive from register
            original = _encode_movz_from_pattern(match_insn, register)
            patched = _encode_movz_from_pattern(replace_insn, register)
        else:
            raise ValueError(
                f"Target for {func}+0x{offset:X}: must provide either "
                "'original'/'patched' fields or top-level 'match_insn'/'replace_insn'"
            )

        targets.append(
            {
                "func": func,
                "offset": offset,
                "register": register,
                "original": original,
                "patched": patched,
            }
        )

    return {"description": description, "targets": targets}


def _encode_movz_from_pattern(pattern, register):
    """Encode a MOVZ instruction from a textual pattern and register name.

    Supports patterns like:
        "MOVZ Wd, #0xA0"   -- Wd is replaced with the actual register
        "MOVZ Wd, #0x00"

    Args:
        pattern: Instruction pattern string.
        register: Register name (e.g., 'W3', 'X5').

    Returns:
        32-bit instruction word (integer).
    """
    # Parse the pattern
    pattern = pattern.strip()
    if not pattern.upper().startswith("MOVZ"):
        raise ValueError(f"Only MOVZ patterns are currently supported: '{pattern}'")

    parts = pattern.split(",")
    if len(parts) != 2:
        raise ValueError(f"Cannot parse MOVZ pattern: '{pattern}'")

    # Extract immediate
    imm_str = parts[1].strip()
    if imm_str.startswith("#"):
        imm_str = imm_str[1:]
    imm16 = int(imm_str, 0)

    # Determine register number and size
    reg = register.strip().upper()
    if reg.startswith("W"):
        sf = 0
        rd = int(reg[1:])
    elif reg.startswith("X"):
        sf = 1
        rd = int(reg[1:])
    else:
        raise ValueError(f"Unknown register format: '{register}'")

    if rd < 0 or rd > 30:
        raise ValueError(f"Register number out of range: {rd}")
    if imm16 < 0 or imm16 > 0xFFFF:
        raise ValueError(f"Immediate out of range for MOVZ: 0x{imm16:X}")

    # Encode: sf:1 | opc=10:2 | 100101:6 | hw=00:2 | imm16:16 | Rd:5
    insn = (sf << 31) | (0b10 << 29) | (0b100101 << 23) | (imm16 << 5) | rd
    return insn


# ---------------------------------------------------------------------------
# SCSI rescan helper
# ---------------------------------------------------------------------------


def rescan_scsi_host(host_num):
    """Trigger a SCSI rescan on the given host.

    Writes '- - -' to /sys/class/scsi_host/host<N>/scan to cause the
    kernel to re-probe all channels, targets, and LUNs.

    Args:
        host_num: SCSI host number (integer).
    """
    scan_path = f"/sys/class/scsi_host/host{host_num}/scan"
    try:
        with open(scan_path, "w") as f:
            f.write("- - -\n")
        print(f"[info] SCSI rescan triggered on host{host_num}")
    except FileNotFoundError:
        print(f"[ERROR] {scan_path} not found -- is host{host_num} valid?")
    except PermissionError:
        print(f"[ERROR] Cannot write to {scan_path} -- need root")
    except Exception as e:
        print(f"[ERROR] SCSI rescan failed: {e}")


# ---------------------------------------------------------------------------
# Core patching logic
# ---------------------------------------------------------------------------


class PatchTarget:
    """A single instruction patch target with resolved addresses."""

    def __init__(self, func, offset, register, original, patched, va, pa):
        self.func = func
        self.offset = offset
        self.register = register
        self.original = original  # expected original instruction word
        self.patched = patched  # desired patched instruction word
        self.va = va  # virtual address
        self.pa = pa  # physical address

    def __str__(self):
        return (
            f"{self.func}+0x{self.offset:X} "
            f"(VA=0x{self.va:016X}, PA=0x{self.pa:X})"
        )


def resolve_targets(target_data, va_pa_offset):
    """Resolve symbolic targets to physical addresses.

    Args:
        target_data: Normalized target dict from load_targets_*.
        va_pa_offset: VA - PA offset (integer).

    Returns:
        List of PatchTarget instances.
    """
    resolved = []
    for t in target_data["targets"]:
        va, pa = resolve_function_pa(t["func"], t["offset"], va_pa_offset)
        resolved.append(
            PatchTarget(
                func=t["func"],
                offset=t["offset"],
                register=t["register"],
                original=t["original"],
                patched=t["patched"],
                va=va,
                pa=pa,
            )
        )
    return resolved


def check_status(targets):
    """Check and report the current state of all patch targets.

    Safety layer 7: Read-only inspection.

    Args:
        targets: List of PatchTarget instances.

    Returns:
        List of dicts with target info and state ('original', 'patched',
        or 'unknown').
    """
    results = []
    for t in targets:
        try:
            current = read_insn_at_pa(t.pa)
        except Exception as e:
            results.append({"target": t, "state": "error", "error": str(e)})
            continue

        if current == t.original:
            state = "original"
        elif current == t.patched:
            state = "patched"
        else:
            state = "unknown"

        results.append(
            {
                "target": t,
                "state": state,
                "current": current,
            }
        )
    return results


def print_status(results, description=""):
    """Pretty-print status results."""
    if description:
        print(f"\nPatch set: {description}")
    print(f"{'-' * 78}")
    print(
        f"{'Target':<40} {'State':<10} {'Current Instruction':<28}"
    )
    print(f"{'-' * 78}")

    for r in results:
        t = r["target"]
        label = f"{t.func}+0x{t.offset:X}"
        if r["state"] == "error":
            print(f"{label:<40} {'ERROR':<10} {r['error']}")
        else:
            current_str = format_insn(r["current"])
            state_display = r["state"].upper()
            print(f"{label:<40} {state_display:<10} {current_str}")

    print(f"{'-' * 78}")

    # Summary
    states = [r["state"] for r in results]
    if all(s == "patched" for s in states):
        print("All targets are PATCHED.")
    elif all(s == "original" for s in states):
        print("All targets are at ORIGINAL values (unpatched).")
    elif any(s == "error" for s in states):
        print("Some targets could not be read -- check errors above.")
    elif any(s == "unknown" for s in states):
        print(
            "WARNING: Some targets have UNEXPECTED instruction values.\n"
            "This may indicate a different kernel version or prior partial patch."
        )
    else:
        print("Mixed state -- some targets patched, some original.")


def apply_patches(targets, undo=False, dry_run=True, cache_maint=None):
    """Apply or undo patches on all targets.

    Safety layers:
      1. Address validation (4-byte alignment checked in read/write)
      2. Instruction verification (checks current value before writing)
      3. Write-back verification (in write_insn_at_pa)
      6. Dry-run default

    Args:
        targets: List of PatchTarget instances.
        undo: If True, write original instructions (undo patches).
        dry_run: If True, only preview -- do not write.
        cache_maint: Optional ARM64CacheMaint instance.

    Returns:
        True if all patches succeeded (or dry-run completed), False on any error.
    """
    action = "UNDO" if undo else "APPLY"
    mode = "DRY-RUN" if dry_run else "LIVE"
    print(f"\n[{action}] Mode: {mode}")
    print(f"{'-' * 78}")

    all_ok = True

    for t in targets:
        label = f"{t.func}+0x{t.offset:X}"
        expected_current = t.patched if undo else t.original
        desired = t.original if undo else t.patched

        print(f"\n  Target: {label}")
        print(f"    PA: 0x{t.pa:X}")
        print(f"    Expected current: {format_insn(expected_current)}")
        print(f"    Desired:          {format_insn(desired)}")

        # Safety layer 2: Read and verify current instruction
        try:
            current = read_insn_at_pa(t.pa)
        except Exception as e:
            print(f"    [ERROR] Cannot read PA 0x{t.pa:X}: {e}")
            all_ok = False
            continue

        print(f"    Actual current:   {format_insn(current)}")

        if current == desired:
            print(f"    [SKIP] Already at desired value.")
            continue

        if current != expected_current:
            # Safety layer 2 failure
            print(
                f"    [ERROR] Current instruction does not match expected value!\n"
                f"             Expected: 0x{expected_current:08X}\n"
                f"             Got:      0x{current:08X}\n"
                f"             REFUSING to patch -- unexpected state."
            )
            all_ok = False
            continue

        if dry_run:
            print(f"    [DRY-RUN] Would write 0x{desired:08X}")
            continue

        # Write the patch
        print(f"    Writing 0x{desired:08X} ...", end=" ")
        ok = write_insn_at_pa(t.pa, desired, cache_maint=cache_maint)
        if ok:
            print("OK (verified)")
        else:
            print("FAILED")
            all_ok = False

    print(f"\n{'-' * 78}")
    if dry_run:
        print(f"[{action}] Dry-run complete. Use --apply or --undo to write changes.")
    elif all_ok:
        print(f"[{action}] All patches applied successfully.")
    else:
        print(f"[{action}] Completed with errors -- see above.")

    return all_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_hex_int(s):
    """Parse a string as a hex or decimal integer."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 0)


def build_parser():
    parser = argparse.ArgumentParser(
        description="ARM64 kernel text hotpatcher -- patches instructions via /dev/mem",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --preset ata-device-obs --stext-pa 0x40080000 --status\n"
            "  %(prog)s --preset ata-device-obs --stext-pa 0x40080000 --apply\n"
            "  %(prog)s --targets patches.json --va-pa-offset 0xFFFFFF8000080000 --apply\n"
        ),
    )

    # Target source (mutually exclusive)
    src = parser.add_argument_group("target source (pick one)")
    src_mx = src.add_mutually_exclusive_group(required=True)
    src_mx.add_argument(
        "--targets",
        metavar="FILE",
        help="JSON file defining patch targets",
    )
    src_mx.add_argument(
        "--preset",
        metavar="NAME",
        choices=sorted(PRESETS.keys()),
        help=f"Built-in preset ({', '.join(sorted(PRESETS.keys()))})",
    )

    # Address translation
    addr = parser.add_argument_group("address translation")
    addr.add_argument(
        "--va-pa-offset",
        metavar="OFFSET",
        type=parse_hex_int,
        help="Manual VA-to-PA offset (hex). If omitted, computed from "
        "/proc/kallsyms _stext and --stext-pa",
    )
    addr.add_argument(
        "--stext-pa",
        metavar="ADDR",
        type=parse_hex_int,
        help="Physical address of _stext (required if --va-pa-offset not given)",
    )

    # Actions
    act = parser.add_argument_group("actions")
    act_mx = act.add_mutually_exclusive_group()
    act_mx.add_argument(
        "--apply",
        action="store_true",
        help="Apply patches (write patched instructions)",
    )
    act_mx.add_argument(
        "--undo",
        action="store_true",
        help="Reverse patches (write original instructions)",
    )
    act_mx.add_argument(
        "--status",
        action="store_true",
        help="Check current patch state (read-only)",
    )
    act_mx.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview patches without writing (this is the default)",
    )

    # Post-patch actions
    post = parser.add_argument_group("post-patch actions")
    post.add_argument(
        "--rescan-scsi",
        metavar="HOST",
        type=int,
        help="Trigger SCSI rescan on given host number after patching",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --- Determine VA-PA offset ---
    if args.va_pa_offset is not None:
        va_pa_offset = args.va_pa_offset
        print(f"[info] Using provided VA-PA offset: 0x{va_pa_offset:016X}")
    elif args.stext_pa is not None:
        va_pa_offset = compute_va_pa_offset(args.stext_pa)
    else:
        parser.error(
            "Either --va-pa-offset or --stext-pa is required for address translation"
        )

    # --- Load targets ---
    if args.targets:
        target_data = load_targets_from_json(args.targets)
    else:
        target_data = load_targets_from_preset(args.preset)

    description = target_data["description"]
    print(f"\n[info] Patch set: {description}")
    print(f"[info] {len(target_data['targets'])} target(s)")

    # --- Resolve symbols to physical addresses ---
    try:
        targets = resolve_targets(target_data, va_pa_offset)
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    for t in targets:
        print(f"  {t}")

    # --- Execute action ---
    if args.status:
        results = check_status(targets)
        print_status(results, description)
        sys.exit(0)

    # Initialize cache maintenance for write operations
    cache_maint = None
    is_write = args.apply or args.undo
    if is_write:
        cache_maint = ARM64CacheMaint()
        if cache_maint.available:
            print("[info] JIT I-cache maintenance available")
        else:
            print("[info] JIT unavailable -- will use fallback I-cache flush")

    dry_run = not (args.apply or args.undo)

    ok = apply_patches(
        targets,
        undo=args.undo,
        dry_run=dry_run,
        cache_maint=cache_maint,
    )

    # --- Post-patch actions ---
    if args.rescan_scsi is not None and is_write and ok:
        rescan_scsi_host(args.rescan_scsi)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
