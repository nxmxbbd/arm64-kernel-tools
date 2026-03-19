#!/usr/bin/env python3
"""
pte-walk.py -- Generic ARM64 page table walker via /dev/mem.

Walks the kernel's page tables by reading physical memory through /dev/mem,
starting from the PGD (swapper_pg_dir) and descending through PUD, PMD, and
PTE levels to resolve virtual-to-physical address mappings.

Supports:
  - 3-level page tables (VA_BITS=39, 4K granule)
  - 4-level page tables (VA_BITS=48, 4K granule)
  - Multiple granule sizes: 4K, 16K, 64K
  - Auto-detection of swapper_pg_dir from /proc/kallsyms
  - Auto-detection of RAM ranges from /proc/iomem

Useful for kernel memory forensics on embedded ARM64 Linux systems where
debugfs, kprobes, and ftrace are unavailable. Can determine page permissions,
memory types, and identify which physical pages back a given virtual address.

READ-ONLY. This tool never writes to /dev/mem. All memory access is via
mmap with PROT_READ only.

See --help for usage examples.
"""

import argparse
import mmap
import os
import struct
import sys
import textwrap

# ============================================================================
# Constants -- ARM64 page table entry bits
# ============================================================================

PTE_VALID       = 1 << 0
PTE_TABLE       = 1 << 1   # For non-leaf: 1=table descriptor, 0=block
PTE_ATTRINDX    = 0b111 << 2
PTE_NS          = 1 << 5
PTE_AP          = 0b11 << 6
PTE_AP_RW_EL1   = 0b00 << 6
PTE_AP_RW_ALL   = 0b01 << 6
PTE_AP_RO_EL1   = 0b10 << 6
PTE_AP_RO_ALL   = 0b11 << 6
PTE_SH          = 0b11 << 8
PTE_AF          = 1 << 10
PTE_NG          = 1 << 11
PTE_CONT        = 1 << 52
PTE_PXN         = 1 << 53
PTE_UXN         = 1 << 54   # also called XN at EL1

ATTR_DEVICE_nGnRnE = 0b000
ATTR_DEVICE_nGnRE  = 0b001
ATTR_NORMAL_NC     = 0b010
ATTR_NORMAL_WT     = 0b011
ATTR_NORMAL        = 0b100

ATTR_NAMES = {
    0b000: "Device-nGnRnE",
    0b001: "Device-nGnRE",
    0b010: "Normal-NC",
    0b011: "Normal-WT",
    0b100: "Normal",
    0b101: "Normal",
    0b110: "Normal",
    0b111: "Normal",
}

SH_NAMES = {
    0b00: "Non-shareable",
    0b01: "Reserved",
    0b10: "Outer-shareable",
    0b11: "Inner-shareable",
}

PAGE_SIZE = mmap.PAGESIZE


# ============================================================================
# DevMem -- Read-only physical memory access via /dev/mem
# ============================================================================

class DevMem:
    """Read-only interface to /dev/mem via mmap.

    All access is strictly read-only (PROT_READ). This class never writes
    to physical memory.
    """

    def __init__(self, dev_path='/dev/mem'):
        self.fd = os.open(dev_path, os.O_RDONLY | os.O_SYNC)
        self._path = dev_path

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, phys_addr, size):
        """Read `size` bytes from physical address. Returns bytes or None on error."""
        try:
            page_off = phys_addr % PAGE_SIZE
            map_start = phys_addr - page_off
            map_size = size + page_off
            if map_size % PAGE_SIZE:
                map_size = (map_size // PAGE_SIZE + 1) * PAGE_SIZE
            mm = mmap.mmap(self.fd, map_size, mmap.MAP_SHARED, mmap.PROT_READ,
                           offset=map_start)
            data = mm[page_off:page_off + size]
            mm.close()
            return bytes(data)
        except (OSError, ValueError, mmap.error):
            return None

    def read_u64(self, phys_addr):
        """Read a single 64-bit little-endian value from physical address."""
        data = self.read(phys_addr, 8)
        if data is None or len(data) < 8:
            return None
        return struct.unpack('<Q', data)[0]


# ============================================================================
# Page table geometry
# ============================================================================

def compute_pt_params(va_bits, granule):
    """Compute page table parameters for a given VA_BITS and granule size.

    Returns a dict with:
      - levels: number of translation levels (3 or 4)
      - page_shift: log2(granule)
      - entries_per_table: number of entries per table
      - bits_per_level: index bits consumed per level
      - level_names: human-readable names for each level
      - level_shifts: bit shift for each level's index extraction
      - level_masks: mask for each level's index
      - block_sizes: size of the block mapped at each level (or 0 if N/A)
      - addr_mask: mask to extract physical address from descriptor
    """
    import math
    page_shift = int(math.log2(granule))
    bits_per_level = page_shift - 3  # each entry is 8 bytes

    # Number of levels needed
    levels_needed = (va_bits - page_shift + bits_per_level - 1) // bits_per_level
    if levels_needed < 3:
        levels_needed = 3
    if levels_needed > 4:
        levels_needed = 4

    entries_per_table = 1 << bits_per_level

    # For the initial lookup level, the index width may be smaller
    # Total bits covered by page tables: va_bits - page_shift
    # Each subsequent level covers bits_per_level bits
    # The top level covers the remainder
    remaining = va_bits - page_shift
    level_bits = []
    for i in range(levels_needed):
        if i < levels_needed - 1:
            level_bits.insert(0, bits_per_level)
            remaining -= bits_per_level
        else:
            level_bits.insert(0, remaining)

    # Build shift/mask for each level
    level_shifts = []
    level_masks = []
    shift = page_shift
    for i in range(levels_needed - 1, -1, -1):
        level_shifts.insert(0, shift)
        level_masks.insert(0, (1 << level_bits[i]) - 1)
        shift += level_bits[i]

    # Level names (from top to bottom)
    if levels_needed == 4:
        level_names = ['PGD', 'PUD', 'PMD', 'PTE']
    else:
        level_names = ['PGD', 'PMD', 'PTE']

    # Block sizes: blocks can exist at non-leaf levels (except PTE level)
    # At level i (0=top), block size = 1 << level_shifts[i]
    block_sizes = []
    for i in range(levels_needed):
        if i < levels_needed - 1:
            block_sizes.append(1 << level_shifts[i + 1])
        else:
            block_sizes.append(granule)  # PTE level -> page

    # Physical address mask: bits [47:page_shift] for 4K granule, etc.
    # Actually it's bits [47:12] typically, but depends on OA size
    # For standard kernels: bits [47:page_shift]
    addr_mask = ((1 << 48) - 1) & ~((1 << page_shift) - 1)

    return {
        'levels': levels_needed,
        'page_shift': page_shift,
        'granule': granule,
        'entries_per_table': entries_per_table,
        'bits_per_level': bits_per_level,
        'level_names': level_names,
        'level_shifts': level_shifts,
        'level_masks': level_masks,
        'level_bits': level_bits,
        'block_sizes': block_sizes,
        'addr_mask': addr_mask,
        'va_bits': va_bits,
    }


def format_size(n):
    """Format a byte count as a human-readable size."""
    if n >= (1 << 30):
        return f"{n / (1 << 30):.1f}G"
    elif n >= (1 << 20):
        return f"{n / (1 << 20):.1f}M"
    elif n >= (1 << 10):
        return f"{n / (1 << 10):.1f}K"
    return f"{n}B"


# ============================================================================
# PTE decoder
# ============================================================================

def decode_entry(entry, level, pt, is_leaf=False):
    """Decode a page table entry into a human-readable dict.

    Args:
        entry: raw 64-bit descriptor value
        level: current level index (0=PGD)
        pt: page table params dict from compute_pt_params()
        is_leaf: True if this is known to be a leaf entry (block or page)

    Returns dict with decoded attributes.
    """
    if entry == 0:
        return {'type': 'invalid', 'raw': 0}

    valid = bool(entry & PTE_VALID)
    if not valid:
        return {'type': 'invalid', 'raw': entry}

    is_table = bool(entry & PTE_TABLE) and (level < pt['levels'] - 1)
    if not is_leaf and is_table and level < pt['levels'] - 1:
        next_addr = entry & pt['addr_mask']
        return {
            'type': 'table',
            'raw': entry,
            'next_table_pa': next_addr,
        }

    # Block or page descriptor
    output_addr = entry & pt['addr_mask']
    attrindx = (entry >> 2) & 0b111
    ap = (entry >> 6) & 0b11
    sh = (entry >> 8) & 0b11
    af = bool(entry & PTE_AF)
    ng = bool(entry & PTE_NG)
    cont = bool(entry & PTE_CONT)
    pxn = bool(entry & PTE_PXN)
    uxn = bool(entry & PTE_UXN)
    ns = bool(entry & PTE_NS)

    # Interpret AP bits
    if ap == 0b00:
        access = "RW_EL1"
    elif ap == 0b01:
        access = "RW_ALL"
    elif ap == 0b10:
        access = "RO_EL1"
    else:
        access = "RO_ALL"

    block_size = pt['block_sizes'][level]

    result = {
        'type': 'block' if level < pt['levels'] - 1 else 'page',
        'raw': entry,
        'output_addr': output_addr,
        'block_size': block_size,
        'block_size_h': format_size(block_size),
        'attrindx': attrindx,
        'attr_name': ATTR_NAMES.get(attrindx, f"idx{attrindx}"),
        'ap': access,
        'sh': SH_NAMES.get(sh, f"sh{sh}"),
        'af': af,
        'ng': ng,
        'cont': cont,
        'pxn': pxn,
        'uxn': uxn,
        'ns': ns,
    }

    return result


def format_decoded(d, indent=4):
    """Format a decoded entry dict into a multi-line string."""
    pad = ' ' * indent
    if d['type'] == 'invalid':
        if d['raw'] == 0:
            return f"{pad}(empty)"
        return f"{pad}INVALID raw=0x{d['raw']:016x}"

    if d['type'] == 'table':
        return f"{pad}TABLE -> PA 0x{d['next_table_pa']:010x}"

    # Block or page
    lines = []
    lines.append(f"{pad}{d['type'].upper()} PA 0x{d['output_addr']:010x} "
                 f"size={d['block_size_h']}")
    lines.append(f"{pad}  attr={d['attr_name']} AP={d['ap']} "
                 f"SH={d['sh']} AF={d['af']}")
    flags = []
    if d['pxn']:
        flags.append('PXN')
    if d['uxn']:
        flags.append('UXN')
    if d['ng']:
        flags.append('nG')
    if d['cont']:
        flags.append('CONT')
    if d['ns']:
        flags.append('NS')
    if flags:
        lines.append(f"{pad}  flags: {' '.join(flags)}")

    # Permission summary
    writable = 'RW' in d['ap']
    executable = not d['pxn']
    perm_str = ('W' if writable else 'R') + ('X' if executable else '-')
    lines.append(f"{pad}  kernel: {perm_str}")

    return '\n'.join(lines)


# ============================================================================
# Page table walking
# ============================================================================

def walk_va(mem, pgd_pa, va, pt):
    """Walk the page table to translate a virtual address.

    Args:
        mem: DevMem instance
        pgd_pa: physical address of PGD (swapper_pg_dir)
        va: virtual address to translate
        pt: page table params from compute_pt_params()

    Returns list of (level_name, index, entry_pa, entry_raw, decoded) tuples,
    one per level visited. The walk stops when a leaf entry or invalid entry
    is found.
    """
    steps = []
    table_pa = pgd_pa

    for level in range(pt['levels']):
        idx = (va >> pt['level_shifts'][level]) & pt['level_masks'][level]
        entry_pa = table_pa + idx * 8
        entry_raw = mem.read_u64(entry_pa)

        if entry_raw is None:
            steps.append((pt['level_names'][level], idx, entry_pa, None,
                          {'type': 'read_error'}))
            break

        decoded = decode_entry(entry_raw, level, pt)
        steps.append((pt['level_names'][level], idx, entry_pa, entry_raw, decoded))

        if decoded['type'] == 'table':
            table_pa = decoded['next_table_pa']
        else:
            # Leaf entry (block/page) or invalid -- walk is done
            break

    return steps


def print_walk(va, steps, pt):
    """Print the results of a page table walk."""
    print(f"\n{'='*70}")
    print(f"Walking VA 0x{va:016x}")
    print(f"{'='*70}")

    for level_name, idx, entry_pa, entry_raw, decoded in steps:
        if entry_raw is None:
            print(f"\n  [{level_name}] index={idx}")
            print(f"    entry at PA 0x{entry_pa:010x}: READ ERROR")
            continue

        print(f"\n  [{level_name}] index={idx}")
        print(f"    entry at PA 0x{entry_pa:010x} = 0x{entry_raw:016x}")
        print(format_decoded(decoded, indent=4))

    # Final result
    last = steps[-1] if steps else None
    if last:
        _, _, _, _, decoded = last
        if decoded['type'] in ('block', 'page'):
            pa = decoded['output_addr']
            offset_within = va & (decoded['block_size'] - 1)
            final_pa = pa | offset_within
            print(f"\n  RESULT: VA 0x{va:016x} -> PA 0x{final_pa:010x}")
            writable = 'RW' in decoded['ap']
            executable = not decoded['pxn']
            print(f"  Permissions: {'RW' if writable else 'RO'}, "
                  f"{'executable' if executable else 'no-execute'}")
            print(f"  Memory type: {decoded['attr_name']}")

            # Feasibility note for /dev/mem patching
            if writable and decoded['attr_name'].startswith('Normal'):
                print(f"  Note: This page is writable normal memory -- "
                      f"a /dev/mem write to PA 0x{final_pa:010x} could modify it.")
            elif not writable:
                print(f"  Note: This page is read-only in the page tables. "
                      f"A /dev/mem write would bypass MMU permissions but cache "
                      f"coherency depends on memory type.")
        elif decoded['type'] == 'invalid':
            print(f"\n  RESULT: VA 0x{va:016x} -> NOT MAPPED (invalid entry)")
        elif decoded['type'] == 'read_error':
            print(f"\n  RESULT: VA 0x{va:016x} -> WALK FAILED (could not read entry)")


# ============================================================================
# PGD overview
# ============================================================================

def show_pgd_overview(mem, pgd_pa, pt):
    """Print an overview of all valid PGD entries."""
    print(f"\n{'='*70}")
    print(f"PGD Overview  (swapper_pg_dir at PA 0x{pgd_pa:010x})")
    print(f"{'='*70}")

    n_entries = 1 << pt['level_bits'][0]
    valid_count = 0
    block_count = 0

    for i in range(n_entries):
        entry_pa = pgd_pa + i * 8
        entry = mem.read_u64(entry_pa)
        if entry is None:
            continue
        if not (entry & PTE_VALID):
            continue

        valid_count += 1
        decoded = decode_entry(entry, 0, pt)

        # Compute the VA range this entry covers
        va_base = i << pt['level_shifts'][0]
        # Sign-extend for kernel addresses
        if va_base & (1 << (pt['va_bits'] - 1)):
            va_base |= ~((1 << pt['va_bits']) - 1) & ((1 << 64) - 1)
        va_end = va_base + (1 << pt['level_shifts'][0])

        if decoded['type'] == 'table':
            print(f"  PGD[{i:>4}] VA 0x{va_base:016x}..0x{va_end-1:016x} "
                  f"-> TABLE at PA 0x{decoded['next_table_pa']:010x}")
        elif decoded['type'] in ('block', 'page'):
            block_count += 1
            print(f"  PGD[{i:>4}] VA 0x{va_base:016x}..0x{va_end-1:016x} "
                  f"-> BLOCK PA 0x{decoded['output_addr']:010x} "
                  f"{decoded['attr_name']} {decoded['ap']}")
        else:
            print(f"  PGD[{i:>4}] raw=0x{entry:016x} (valid but unrecognized)")

    print(f"\n  {valid_count} valid entries out of {n_entries} "
          f"({block_count} blocks)")


# ============================================================================
# PMD detail
# ============================================================================

def show_pmd_detail(mem, pgd_pa, pt, start_idx, end_idx):
    """Show detailed PMD-level entries for a PGD index range.

    For 3-level tables: PGD -> PMD -> PTE (so PMD is level 1)
    For 4-level tables: PGD -> PUD -> PMD -> PTE (so PMD is level 2)
    """
    pmd_level = pt['levels'] - 2  # PMD is always the second-to-last level
    pmd_name = pt['level_names'][pmd_level]

    print(f"\n{'='*70}")
    print(f"{pmd_name} Detail for PGD indices {start_idx}..{end_idx}")
    print(f"{'='*70}")

    for pgd_idx in range(start_idx, end_idx + 1):
        entry_pa = pgd_pa + pgd_idx * 8
        pgd_entry = mem.read_u64(entry_pa)
        if pgd_entry is None or not (pgd_entry & PTE_VALID):
            continue

        decoded = decode_entry(pgd_entry, 0, pt)
        if decoded['type'] != 'table':
            print(f"\n  PGD[{pgd_idx}] = BLOCK (not descending)")
            continue

        # For 4-level, we need to descend PGD -> PUD -> PMD
        # For 3-level, PGD -> PMD directly
        if pt['levels'] == 4:
            _show_pmd_via_pud(mem, decoded['next_table_pa'], pgd_idx, pt)
        else:
            _show_pmd_entries(mem, decoded['next_table_pa'], pgd_idx, -1, pt)


def _show_pmd_via_pud(mem, pud_table_pa, pgd_idx, pt):
    """For 4-level tables: iterate PUD entries, then show PMD for each."""
    n_entries = pt['entries_per_table']
    for pud_idx in range(n_entries):
        pud_entry = mem.read_u64(pud_table_pa + pud_idx * 8)
        if pud_entry is None or not (pud_entry & PTE_VALID):
            continue
        decoded = decode_entry(pud_entry, 1, pt)
        if decoded['type'] == 'table':
            _show_pmd_entries(mem, decoded['next_table_pa'],
                              pgd_idx, pud_idx, pt)
        elif decoded['type'] in ('block', 'page'):
            print(f"  PGD[{pgd_idx}] PUD[{pud_idx}] = "
                  f"BLOCK PA 0x{decoded['output_addr']:010x} "
                  f"size={decoded['block_size_h']} "
                  f"{decoded['attr_name']} {decoded['ap']}")


def _show_pmd_entries(mem, pmd_table_pa, pgd_idx, pud_idx, pt):
    """Show all valid entries in a single PMD table."""
    pmd_level = pt['levels'] - 2
    n_entries = pt['entries_per_table']
    prefix = f"PGD[{pgd_idx}]"
    if pud_idx >= 0:
        prefix += f" PUD[{pud_idx}]"

    for pmd_idx in range(n_entries):
        pmd_entry = mem.read_u64(pmd_table_pa + pmd_idx * 8)
        if pmd_entry is None or not (pmd_entry & PTE_VALID):
            continue

        decoded = decode_entry(pmd_entry, pmd_level, pt)
        if decoded['type'] == 'table':
            print(f"  {prefix} PMD[{pmd_idx:>3}] -> TABLE PA "
                  f"0x{decoded['next_table_pa']:010x}")
        elif decoded['type'] in ('block', 'page'):
            writable = 'RW' in decoded['ap']
            executable = not decoded['pxn']
            perm = ('W' if writable else 'R') + ('X' if executable else '-')
            print(f"  {prefix} PMD[{pmd_idx:>3}] -> BLOCK PA "
                  f"0x{decoded['output_addr']:010x} "
                  f"size={decoded['block_size_h']} "
                  f"{decoded['attr_name']} {decoded['ap']} [{perm}]")


# ============================================================================
# Feasibility analysis
# ============================================================================

def show_feasibility(mem, pgd_pa, pt, ram_ranges):
    """Show a summary of page table structure and /dev/mem feasibility notes."""
    print(f"\n{'='*70}")
    print(f"Page Table Structure Summary")
    print(f"{'='*70}")
    print(f"  VA_BITS:        {pt['va_bits']}")
    print(f"  Granule:        {format_size(pt['granule'])}")
    print(f"  Levels:         {pt['levels']} ({' -> '.join(pt['level_names'])})")
    print(f"  PGD PA:         0x{pgd_pa:010x}")
    print(f"  Entries/table:  {pt['entries_per_table']}")
    for i, name in enumerate(pt['level_names']):
        shift = pt['level_shifts'][i]
        bits = pt['level_bits'][i]
        bsz = format_size(pt['block_sizes'][i])
        print(f"  {name:>4}: bits [{shift+bits-1}:{shift}] "
              f"({bits} bits, {1 << bits} entries, "
              f"block/page={bsz})")

    if ram_ranges:
        print(f"\n  RAM ranges:")
        for start, end in ram_ranges:
            print(f"    0x{start:010x} - 0x{end-1:010x} "
                  f"({format_size(end - start)})")

    print(f"\n  /dev/mem notes:")
    print(f"    - /dev/mem bypasses the MMU, accessing physical memory directly")
    print(f"    - Page table permissions (RO, XN) do not restrict /dev/mem access")
    print(f"    - However, cache coherency matters: device memory is uncached,")
    print(f"      normal memory may be cached. After writing via /dev/mem, the")
    print(f"      CPU cache may hold stale data for normal-memory mappings.")
    print(f"    - CONFIG_STRICT_DEVMEM may restrict which physical ranges are")
    print(f"      accessible via /dev/mem (typically only allows device MMIO).")


# ============================================================================
# Auto-detection helpers
# ============================================================================

def detect_pgd_from_kallsyms():
    """Try to read swapper_pg_dir physical address from /proc/kallsyms.

    Returns the virtual address (which can be used to find the PGD with
    kimage_voffset), or None on failure.
    """
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == 'swapper_pg_dir':
                    addr = int(parts[0], 16)
                    if addr == 0:
                        # Kernel hides symbols from non-root
                        return None
                    return addr
    except (OSError, ValueError):
        pass
    return None


def detect_ram_ranges():
    """Parse /proc/iomem for 'System RAM' ranges.

    Returns list of (start, end) tuples where end is exclusive.
    """
    ranges = []
    try:
        with open('/proc/iomem', 'r') as f:
            for line in f:
                if 'System RAM' in line:
                    addr_part = line.split(':')[0].strip()
                    start_s, end_s = addr_part.split('-')
                    ranges.append((int(start_s, 16), int(end_s, 16) + 1))
    except (OSError, ValueError):
        pass
    return ranges


def detect_kimage_voffset():
    """Try to detect kimage_voffset from /proc/kallsyms.

    Looks for _text symbol (start of kernel image) and known physical text
    locations. Returns the offset or None.
    """
    try:
        text_va = None
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == '_text':
                    text_va = int(parts[0], 16)
                    break
        if text_va and text_va != 0:
            return text_va
    except (OSError, ValueError):
        pass
    return None


# ============================================================================
# Argument parsing
# ============================================================================

def parse_addr(s):
    """Parse an address string (supports 0x prefix and plain decimal)."""
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def build_parser():
    """Build argument parser with full help text."""
    epilog = textwrap.dedent("""\
    examples:
      # Walk a single virtual address (auto-detect PGD from /proc/kallsyms):
      %(prog)s --va 0xffffff8008080000 --kimage-voffset 0xffffff8007e80000

      # Walk with explicit PGD physical address:
      %(prog)s --pgd-pa 0x63E9C000 --va 0xffffffc000000000

      # Walk multiple addresses:
      %(prog)s --pgd-pa 0x63E9C000 \\
          --va 0xffffff8008080000 --va 0xffffffc000000000

      # Show PGD overview (all valid top-level entries):
      %(prog)s --pgd-pa 0x63E9C000 --overview

      # Show PMD detail for PGD indices 256-260:
      %(prog)s --pgd-pa 0x63E9C000 --pmd-range 256 260

      # 48-bit VA space with 4K granule:
      %(prog)s --pgd-pa 0x63E9C000 --va-bits 48 --va 0xffff800000000000

      # Full analysis (overview + feasibility):
      %(prog)s --pgd-pa 0x63E9C000 --all

      # On a UDM SE (Alpine v2 SoC, example values):
      %(prog)s --pgd-pa 0x63E9C000 --va-bits 39 --granule 4096 \\
          --va 0xffffff8008080000 --ram-ranges 0x00000000-0x7fffffff

    notes:
      - Requires root access for /dev/mem and /proc/kallsyms.
      - If --pgd-pa is not specified, the tool tries to auto-detect it
        from /proc/kallsyms (requires --kimage-voffset to convert VA->PA).
      - This tool is strictly read-only. It never writes to /dev/mem.
    """)

    parser = argparse.ArgumentParser(
        prog='pte-walk.py',
        description=(
            'ARM64 page table walker via /dev/mem. Reads the kernel\'s page '
            'tables from physical memory to translate virtual addresses, '
            'inspect page permissions, and analyze the memory map. Supports '
            '3-level (VA_BITS=39) and 4-level (VA_BITS=48) page tables with '
            '4K/16K/64K granule sizes. Strictly read-only.'
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--pgd-pa', type=str, default=None,
        help='Physical address of swapper_pg_dir (hex). Auto-detected from '
             '/proc/kallsyms if not specified (requires --kimage-voffset).'
    )
    parser.add_argument(
        '--va', type=str, action='append', default=None,
        help='Virtual address to walk (hex). Can be specified multiple times.'
    )
    parser.add_argument(
        '--va-bits', type=int, default=39, choices=[39, 48],
        help='VA_BITS -- virtual address width (default: 39).'
    )
    parser.add_argument(
        '--granule', type=int, default=4096, choices=[4096, 16384, 65536],
        help='Page granule size in bytes (default: 4096).'
    )
    parser.add_argument(
        '--kimage-voffset', type=str, default=None,
        help='Kernel image VA-to-PA offset (hex). Used to convert '
             'swapper_pg_dir VA from /proc/kallsyms to a physical address. '
             'Formula: PA = VA - kimage_voffset.'
    )
    parser.add_argument(
        '--ram-ranges', type=str, default=None,
        help='Physical RAM ranges as "start-end,start-end" (hex). '
             'Auto-detected from /proc/iomem if not specified.'
    )
    parser.add_argument(
        '--overview', action='store_true',
        help='Show PGD overview (all valid top-level entries).'
    )
    parser.add_argument(
        '--pmd-range', type=int, nargs=2, metavar=('START', 'END'),
        help='Show PMD detail for the given PGD index range (inclusive).'
    )
    parser.add_argument(
        '--all', action='store_true',
        help='Full analysis: overview + feasibility summary.'
    )
    parser.add_argument(
        '--dev-mem', type=str, default='/dev/mem',
        help='Path to memory device (default: /dev/mem).'
    )

    return parser


# ============================================================================
# Main
# ============================================================================

def main():
    parser = build_parser()
    args = parser.parse_args()

    # --- Resolve PGD physical address ---
    pgd_pa = None
    kimage_voffset = None

    if args.kimage_voffset is not None:
        kimage_voffset = parse_addr(args.kimage_voffset)

    if args.pgd_pa is not None:
        pgd_pa = parse_addr(args.pgd_pa)
    else:
        # Try auto-detection from /proc/kallsyms
        swapper_va = detect_pgd_from_kallsyms()
        if swapper_va is not None:
            print(f"Auto-detected swapper_pg_dir VA: 0x{swapper_va:016x}",
                  file=sys.stderr)
            if kimage_voffset is not None:
                pgd_pa = swapper_va - kimage_voffset
                print(f"  -> PA: 0x{pgd_pa:010x} "
                      f"(using kimage_voffset=0x{kimage_voffset:x})",
                      file=sys.stderr)
            else:
                print("ERROR: Found swapper_pg_dir VA but --kimage-voffset is "
                      "needed to convert to PA.", file=sys.stderr)
                print("  Provide --pgd-pa directly or add --kimage-voffset.",
                      file=sys.stderr)
                return 1
        else:
            print("ERROR: Could not auto-detect swapper_pg_dir. "
                  "Specify --pgd-pa.", file=sys.stderr)
            return 1

    # --- Validate we have something to do ---
    has_action = (args.va or args.overview or args.pmd_range or args.all)
    if not has_action:
        parser.error("No action specified. Use --va, --overview, --pmd-range, "
                     "or --all.")

    # --- Compute page table parameters ---
    pt = compute_pt_params(args.va_bits, args.granule)

    # --- Parse RAM ranges ---
    ram_ranges = []
    if args.ram_ranges:
        for part in args.ram_ranges.split(','):
            part = part.strip()
            if '-' in part:
                s, e = part.split('-', 1)
                ram_ranges.append((parse_addr(s), parse_addr(e) + 1))
    else:
        ram_ranges = detect_ram_ranges()

    # --- Print configuration ---
    print(f"Configuration:", file=sys.stderr)
    print(f"  PGD PA:    0x{pgd_pa:010x}", file=sys.stderr)
    print(f"  VA_BITS:   {args.va_bits}", file=sys.stderr)
    print(f"  Granule:   {format_size(args.granule)}", file=sys.stderr)
    print(f"  Levels:    {pt['levels']} ({' -> '.join(pt['level_names'])})",
          file=sys.stderr)
    if ram_ranges:
        total_ram = sum(e - s for s, e in ram_ranges)
        print(f"  RAM:       {format_size(total_ram)} in "
              f"{len(ram_ranges)} range(s)", file=sys.stderr)
    print(file=sys.stderr)

    # --- Open /dev/mem read-only ---
    with DevMem(args.dev_mem) as mem:

        # Walk requested virtual addresses
        if args.va:
            for va_str in args.va:
                va = parse_addr(va_str)
                steps = walk_va(mem, pgd_pa, va, pt)
                print_walk(va, steps, pt)

        # PGD overview
        if args.overview or args.all:
            show_pgd_overview(mem, pgd_pa, pt)

        # PMD detail
        if args.pmd_range:
            show_pmd_detail(mem, pgd_pa, pt,
                            args.pmd_range[0], args.pmd_range[1])

        # Feasibility summary
        if args.all:
            show_feasibility(mem, pgd_pa, pt, ram_ranges)

    return 0


if __name__ == '__main__':
    sys.exit(main())
