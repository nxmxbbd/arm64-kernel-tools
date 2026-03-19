#!/usr/bin/env python3
"""
mem-struct-scan.py -- Generic /dev/mem kernel struct scanner.

Scans physical memory via /dev/mem to locate kernel data structures by
searching for a known anchor value at a fixed offset, then validating
multiple fields at other offsets within the candidate struct.

Developed for kernel diagnostics on embedded ARM64 Linux systems where
debugfs, kprobes, and ftrace are unavailable. Useful for locating structs
in memory when symbol resolution or pointer chasing is unreliable due to
DMA/cache coherency issues.

Strategy:
  1. Parse /proc/iomem for System RAM ranges.
  2. Scan each range for the anchor value (a unique multi-byte pattern).
  3. For each match, read the surrounding struct and validate fields at
     known offsets against expected values, pointer ranges, or patterns.
  4. Report candidates that pass a configurable minimum number of checks.

READ-ONLY. This tool never writes to /dev/mem. All memory access is via
mmap with PROT_READ only.

Modes of operation:
  --anchor-value + --anchor-offset : Quick scan with minimal config.
  --config <file.json>             : Full field validation from a JSON file.
  --preset <name>                  : Built-in struct definitions (e.g. ata-device).

See --help for examples and JSON config format.
"""

import argparse
import json
import mmap
import os
import struct
import sys
import textwrap
import time

# === Defaults ===

PAGE_SIZE = mmap.PAGESIZE
SCAN_CHUNK = 4 * 1024 * 1024       # 4 MB chunks for mmap
PROGRESS_INTERVAL = 256 * 1024 * 1024  # print every 256 MB

# Default kernel pointer ranges (aarch64 Linux)
DEFAULT_KPTR_RANGES = [
    [0xFFFFFF8000000000, 0xFFFFFF9000000000],  # kimage
    [0xFFFFFFC000000000, 0xFFFFFFD000000000],  # linear map
]

# === Built-in presets ===

PRESETS = {
    "ata-device": {
        "description": "Linux ata_device struct (aarch64, kernel 4.19.x)",
        "anchor": {
            "offset": 760,
            "size": 8,
            "format": "<Q",
            "description": "n_sectors -- set --anchor-value to your drive's sector count"
        },
        "struct_size": 1408,
        "fields": [
            {
                "name": "link",
                "offset": 0,
                "size": 8,
                "format": "<Q",
                "check": "kernel_ptr",
                "description": "Pointer to parent ata_link"
            },
            {
                "name": "devno",
                "offset": 8,
                "size": 4,
                "format": "<I",
                "expect": 0,
                "description": "Device number (0 for master)"
            },
            {
                "name": "horkage",
                "offset": 12,
                "size": 4,
                "format": "<I",
                "check": "info_only",
                "description": "Device horkage flags"
            },
            {
                "name": "flags",
                "offset": 16,
                "size": 8,
                "format": "<Q",
                "check": "bitmask",
                "expect": 8,
                "description": "ATA device flags (check ATA_DFLAG_LBA bit 3)"
            },
            {
                "name": "sdev",
                "offset": 24,
                "size": 8,
                "format": "<Q",
                "check": "kernel_ptr_or_null",
                "description": "Pointer to scsi_device"
            },
            {
                "name": "private_data",
                "offset": 32,
                "size": 8,
                "format": "<Q",
                "check": "info_only",
                "description": "Private data pointer"
            },
            {
                "name": "class",
                "offset": 776,
                "size": 4,
                "format": "<I",
                "expect": 1,
                "description": "ATA_DEV_ATA = 1"
            },
            {
                "name": "pio_mode",
                "offset": 792,
                "size": 1,
                "format": "B",
                "expect": 12,
                "description": "XFER_PIO_4 = 0x0c"
            },
            {
                "name": "dma_mode",
                "offset": 793,
                "size": 1,
                "format": "B",
                "expect": 70,
                "description": "XFER_UDMA_6 = 0x46"
            },
            {
                "name": "xfer_mode",
                "offset": 794,
                "size": 1,
                "format": "B",
                "expect": 70,
                "description": "XFER_UDMA_6 = 0x46"
            },
            {
                "name": "cbl",
                "offset": 808,
                "size": 4,
                "format": "<I",
                "expect": 32,
                "description": "ATA_CBL_SATA = 32"
            },
            {
                "name": "identify",
                "offset": 896,
                "size": 512,
                "format": "raw",
                "check": "ata_identify",
                "description": "512-byte ATA IDENTIFY data block"
            }
        ]
    }
}


def is_kernel_ptr(val, kptr_ranges):
    """Check if value looks like a valid kernel pointer."""
    for lo, hi in kptr_ranges:
        if lo <= val <= hi:
            return True
    return False


def get_ram_ranges():
    """Parse /proc/iomem for 'System RAM' ranges. Returns list of (start, end) tuples."""
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
    if not ranges:
        # Fallback: assume 0 to MemTotal
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        ranges = [(0, kb * 1024)]
                        break
        except (OSError, ValueError):
            ranges = [(0, 4 * 1024 * 1024 * 1024)]
    return ranges


def decode_ata_model(identify_data, word_start=27, word_end=46):
    """Decode ATA IDENTIFY model string (byte-swapped word pairs)."""
    chars = []
    for w in range(word_start, word_end + 1):
        offset = w * 2
        if offset + 1 < len(identify_data):
            chars.append(chr(identify_data[offset + 1]) if identify_data[offset + 1] >= 0x20 else ' ')
            chars.append(chr(identify_data[offset]) if identify_data[offset] >= 0x20 else ' ')
    return ''.join(chars).strip()


def read_phys(fd, phys_addr, size):
    """Read `size` bytes from physical address via /dev/mem mmap (read-only)."""
    try:
        page_off = phys_addr % PAGE_SIZE
        map_start = phys_addr - page_off
        map_size = size + page_off
        if map_size % PAGE_SIZE:
            map_size = (map_size // PAGE_SIZE + 1) * PAGE_SIZE
        mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED, mmap.PROT_READ,
                       offset=map_start)
        data = mm[page_off:page_off + size]
        mm.close()
        return bytes(data)
    except (OSError, ValueError, mmap.error):
        return None


def format_field_value(value, fmt):
    """Format a field value for JSON output."""
    if isinstance(value, int):
        if fmt in ('<Q', '<q') or value > 0xFFFF:
            return f'0x{value:016x}'
        elif fmt in ('<I', '<i', '<H', '<h'):
            return f'0x{value:x}'
        elif fmt in ('B', 'b'):
            return f'0x{value:02x}'
        return value
    return value


def validate_field(data, field, kptr_ranges):
    """Validate a single field definition against struct data.

    Returns (passed: bool, field_result: dict).
    passed is None for info-only fields (they don't count).
    """
    name = field['name']
    offset = field['offset']
    size = field['size']
    fmt = field.get('format', '<Q')
    check = field.get('check', 'exact')
    expect = field.get('expect')

    result = {'offset': offset}

    if fmt == 'raw':
        raw = data[offset:offset + size]
        if check == 'ata_identify':
            model = decode_ata_model(raw)
            result['value'] = model
            # For ata_identify, valid if model string is non-empty printable text
            valid = len(model.strip()) > 0 and any(c.isalpha() for c in model)
            result['valid'] = valid
            return valid, result
        else:
            result['value'] = f'<{len(raw)} bytes>'
            return None, result

    if check == 'info_only':
        if size == 1:
            value = data[offset]
        else:
            value = struct.unpack_from(fmt, data, offset)[0]
        result['value'] = format_field_value(value, fmt)
        return None, result

    if size == 1:
        value = data[offset]
    else:
        value = struct.unpack_from(fmt, data, offset)[0]

    result['value'] = format_field_value(value, fmt)

    if check == 'kernel_ptr':
        valid = is_kernel_ptr(value, kptr_ranges)
        result['valid'] = valid
        return valid, result

    if check == 'kernel_ptr_or_null':
        valid = value == 0 or is_kernel_ptr(value, kptr_ranges)
        result['valid'] = valid
        return valid, result

    if check == 'nonzero':
        valid = value != 0
        result['valid'] = valid
        return valid, result

    if check == 'bitmask':
        valid = bool(value & expect) if expect is not None else True
        result['valid'] = valid
        return valid, result

    # Default: exact match
    if expect is not None:
        valid = value == expect
        result['valid'] = valid
        return valid, result

    # No expectation set, info only
    return None, result


def validate_candidate(fd, base_phys, anchor_value, anchor_offset, anchor_format,
                       struct_size, fields, kptr_ranges):
    """Validate a candidate struct at the given physical address.

    Returns (match_count, total_checks, fields_dict) or (0, 0, None) on failure.
    """
    data = read_phys(fd, base_phys, struct_size)
    if data is None or len(data) < struct_size:
        return 0, 0, None

    field_results = {}
    checks_passed = 0
    total_checks = 0

    # Verify anchor (must match -- this is our search key)
    if anchor_format == 'raw':
        anchor_data = data[anchor_offset:anchor_offset + len(anchor_value)]
        anchor_valid = anchor_data == anchor_value
    else:
        actual = struct.unpack_from(anchor_format, data, anchor_offset)[0]
        anchor_valid = actual == struct.unpack(anchor_format, anchor_value)[0]
        field_results['_anchor'] = {
            'offset': anchor_offset,
            'value': format_field_value(actual, anchor_format),
            'valid': anchor_valid
        }

    if not anchor_valid:
        return 0, 0, None

    total_checks += 1
    checks_passed += 1

    # Validate each configured field
    for field in fields:
        passed, result = validate_field(data, field, kptr_ranges)
        field_results[field['name']] = result
        if passed is not None:
            total_checks += 1
            if passed:
                checks_passed += 1

    return checks_passed, total_checks, field_results


def scan_memory(fd, ram_ranges, anchor_bytes, anchor_offset, anchor_format,
                struct_size, fields, kptr_ranges, min_checks):
    """Scan physical memory for the anchor pattern and validate candidates."""
    candidates = []
    total_bytes = sum(end - start for start, end in ram_ranges)
    scanned = 0
    matches_found = 0
    start_time = time.time()
    last_progress = 0

    print(f"Scanning {total_bytes // (1024*1024)} MB across {len(ram_ranges)} RAM range(s)...",
          file=sys.stderr)
    for rs, re in ram_ranges:
        print(f"  Range: 0x{rs:010x} - 0x{re:010x} ({(re-rs)//(1024*1024)} MB)", file=sys.stderr)

    anchor_int = struct.unpack(anchor_format, anchor_bytes)[0] if anchor_format != 'raw' else None
    if anchor_int is not None:
        print(f"Looking for anchor value {anchor_int} (0x{anchor_int:016x}) at offset {anchor_offset}",
              file=sys.stderr)
    else:
        print(f"Looking for {len(anchor_bytes)}-byte anchor pattern at offset {anchor_offset}",
              file=sys.stderr)

    for range_start, range_end in ram_ranges:
        offset = range_start
        while offset < range_end:
            chunk_size = min(SCAN_CHUNK, range_end - offset)

            try:
                mm = mmap.mmap(fd, chunk_size, mmap.MAP_SHARED, mmap.PROT_READ,
                               offset=offset)
            except (OSError, ValueError, mmap.error):
                offset += chunk_size
                scanned += chunk_size
                continue

            chunk_data = mm[:]
            mm.close()

            search_pos = 0
            while True:
                idx = chunk_data.find(anchor_bytes, search_pos)
                if idx < 0:
                    break
                search_pos = idx + 1

                anchor_phys = offset + idx
                base_phys = anchor_phys - anchor_offset

                if base_phys < 0:
                    continue

                checks, total, field_results = validate_candidate(
                    fd, base_phys, anchor_bytes, anchor_offset, anchor_format,
                    struct_size, fields, kptr_ranges)

                if checks >= min_checks:
                    matches_found += 1
                    candidates.append({
                        'base_phys': base_phys,
                        'checks_passed': checks,
                        'total_checks': total,
                        'fields': field_results
                    })
                    print(f"  ** MATCH at phys=0x{base_phys:010x} "
                          f"({checks}/{total} checks passed)", file=sys.stderr)

            scanned += chunk_size
            offset += chunk_size

            if scanned - last_progress >= PROGRESS_INTERVAL:
                elapsed = time.time() - start_time
                pct = scanned * 100 / total_bytes if total_bytes else 100
                print(f"  [{pct:5.1f}%] {scanned//(1024*1024):>5} MB scanned, "
                      f"{matches_found} candidates, {elapsed:.0f}s elapsed", file=sys.stderr)
                last_progress = scanned

    elapsed = time.time() - start_time
    print(f"  [100.0%] Scan complete: {scanned//(1024*1024)} MB in {elapsed:.1f}s, "
          f"{matches_found} candidate(s)", file=sys.stderr)

    return candidates, total_bytes


def build_result(candidates, ram_bytes):
    """Build final JSON result."""
    if not candidates:
        return {
            'found': False,
            'error': 'No matching struct found',
            'ram_scanned_mb': ram_bytes // (1024 * 1024)
        }

    if len(candidates) > 1:
        candidates.sort(key=lambda c: c['checks_passed'], reverse=True)
        best = candidates[0]
        result = build_single_result(best, ram_bytes)
        result['warning'] = f'Found {len(candidates)} candidates (expected 1). Using best match.'
        result['all_candidates'] = [
            {'struct_base_phys': f'0x{c["base_phys"]:010x}',
             'checks_passed': c['checks_passed'],
             'total_checks': c['total_checks']}
            for c in candidates
        ]
        return result

    return build_single_result(candidates[0], ram_bytes)


def build_single_result(candidate, ram_bytes):
    """Build result dict for a single confirmed candidate."""
    base = candidate['base_phys']
    return {
        'found': True,
        'struct_base_phys': f'0x{base:010x}',
        'fields': candidate['fields'],
        'checks_passed': candidate['checks_passed'],
        'total_checks': candidate['total_checks'],
        'ram_scanned_mb': ram_bytes // (1024 * 1024)
    }


def load_config(path):
    """Load field definitions from a JSON config file."""
    with open(path, 'r') as f:
        return json.load(f)


def parse_int(s):
    """Parse an integer from string, supporting 0x hex prefix."""
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def build_parser():
    """Build the argument parser with full help text."""
    epilog = textwrap.dedent("""\
    examples:
      # Scan for an ata_device struct using the built-in preset.
      # Provide --anchor-value with the drive's n_sectors value:
      %(prog)s --preset ata-device --anchor-value 50782535680

      # Quick scan with just an anchor (no field validation):
      %(prog)s --anchor-value 0x0BD2E00000 --anchor-offset 760 --struct-size 1408

      # Scan using a JSON config file defining fields to validate:
      %(prog)s --config my-struct.json --anchor-value 50782535680

      # Limit scan to first 2 GB of RAM:
      %(prog)s --preset ata-device --anchor-value 50782535680 --max-ram 2048

    json config format:
      {
        "anchor": {
          "offset": 760,       // offset of anchor within struct
          "size": 8,           // anchor value size in bytes
          "format": "<Q"       // struct.pack format string
        },
        "struct_size": 1408,   // total bytes to read for validation
        "fields": [
          {
            "name": "class",
            "offset": 776,
            "size": 4,
            "format": "<I",
            "expect": 1,           // exact expected value
            "description": "ATA_DEV_ATA = 1"
          },
          {
            "name": "link",
            "offset": 0,
            "size": 8,
            "format": "<Q",
            "check": "kernel_ptr"  // validate as kernel pointer
          }
        ]
      }

    field check types:
      exact             Compare value == expect (default when "expect" is set)
      kernel_ptr        Validate value falls within kernel pointer ranges
      kernel_ptr_or_null  Valid if zero or a kernel pointer
      bitmask           Check that (value & expect) != 0
      nonzero           Check that value != 0
      ata_identify      Decode 512-byte ATA IDENTIFY block, check for model string
      info_only         Record value but do not count as a validation check
      raw               Read raw bytes (no struct unpacking)
    """)

    parser = argparse.ArgumentParser(
        prog='mem-struct-scan.py',
        description=(
            'Scan /dev/mem for kernel structs by anchor value and multi-field validation. '
            'Developed for kernel diagnostics on embedded ARM64 Linux systems. '
            'All memory access is strictly read-only.'
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--anchor-value', type=str, default=None,
        help='The anchor value to search for (decimal or 0x hex). '
             'This is the unique value at a known offset used to locate candidates.'
    )
    parser.add_argument(
        '--anchor-offset', type=int, default=None,
        help='Byte offset of the anchor value within the target struct (default: from config/preset).'
    )
    parser.add_argument(
        '--anchor-format', type=str, default=None,
        help='struct.pack format for the anchor value (default: "<Q" for 8-byte little-endian uint64).'
    )
    parser.add_argument(
        '--struct-size', type=int, default=None,
        help='Total bytes to read from struct base for validation (default: from config/preset).'
    )
    parser.add_argument(
        '--min-checks', type=int, default=None,
        help='Minimum number of validation checks that must pass to report a match (default: 1 or from config).'
    )
    parser.add_argument(
        '--config', type=str, default=None,
        help='Path to a JSON config file defining anchor and field definitions.'
    )
    parser.add_argument(
        '--preset', type=str, default=None, choices=list(PRESETS.keys()),
        help='Use a built-in struct preset. Available: ' + ', '.join(PRESETS.keys()) + '.'
    )
    parser.add_argument(
        '--kptr-ranges', type=str, default=None,
        help='Kernel pointer ranges as JSON array of [lo, hi] pairs. '
             'Default: ARM64 ranges [[0xffffff8000000000, 0xffffff9000000000], '
             '[0xffffffc000000000, 0xffffffd000000000]].'
    )
    parser.add_argument(
        '--max-ram', type=int, default=None,
        help='Limit scan to first N megabytes of RAM.'
    )
    parser.add_argument(
        '--dev-mem', type=str, default='/dev/mem',
        help='Path to memory device (default: /dev/mem).'
    )
    parser.add_argument(
        '--list-presets', action='store_true',
        help='List available built-in presets and exit.'
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Handle --list-presets
    if args.list_presets:
        for name, preset in PRESETS.items():
            print(f"  {name}: {preset.get('description', 'No description')}")
            anchor = preset.get('anchor', {})
            print(f"    anchor offset: {anchor.get('offset')}, "
                  f"format: {anchor.get('format', '<Q')}")
            print(f"    struct size: {preset.get('struct_size')}")
            print(f"    fields: {len(preset.get('fields', []))}")
        return 0

    # Resolve configuration: preset -> config file -> CLI args
    anchor_offset = None
    anchor_format = '<Q'
    anchor_size = 8
    struct_size = None
    fields = []
    min_checks = None

    if args.preset:
        preset = PRESETS[args.preset]
        anchor_cfg = preset['anchor']
        anchor_offset = anchor_cfg['offset']
        anchor_format = anchor_cfg.get('format', '<Q')
        anchor_size = anchor_cfg.get('size', 8)
        struct_size = preset.get('struct_size', 1408)
        fields = preset.get('fields', [])
        min_checks = preset.get('min_checks', 6)

    if args.config:
        config = load_config(args.config)
        anchor_cfg = config.get('anchor', {})
        if 'offset' in anchor_cfg:
            anchor_offset = anchor_cfg['offset']
        if 'format' in anchor_cfg:
            anchor_format = anchor_cfg['format']
        if 'size' in anchor_cfg:
            anchor_size = anchor_cfg['size']
        if 'struct_size' in config:
            struct_size = config['struct_size']
        if 'fields' in config:
            fields = config['fields']
        if 'min_checks' in config:
            min_checks = config['min_checks']

    # CLI args override everything
    if args.anchor_offset is not None:
        anchor_offset = args.anchor_offset
    if args.anchor_format is not None:
        anchor_format = args.anchor_format
    if args.struct_size is not None:
        struct_size = args.struct_size
    if args.min_checks is not None:
        min_checks = args.min_checks

    # Validate required arguments
    if args.anchor_value is None:
        parser.error('--anchor-value is required (the value to search for in memory)')
    if anchor_offset is None:
        parser.error('--anchor-offset is required (or use --preset / --config)')

    # Parse anchor value
    anchor_int = parse_int(args.anchor_value)
    anchor_bytes = struct.pack(anchor_format, anchor_int)

    # Default struct_size: anchor_offset + anchor_size if not specified
    if struct_size is None:
        if fields:
            max_end = max(f['offset'] + f['size'] for f in fields)
            struct_size = max(max_end, anchor_offset + anchor_size)
        else:
            struct_size = anchor_offset + anchor_size

    # Default min_checks
    if min_checks is None:
        min_checks = 1 if not fields else max(1, len(fields) // 2)

    # Kernel pointer ranges
    if args.kptr_ranges:
        kptr_ranges = json.loads(args.kptr_ranges)
    else:
        kptr_ranges = DEFAULT_KPTR_RANGES

    # Get RAM ranges
    ram_ranges = get_ram_ranges()

    # Apply --max-ram limit
    if args.max_ram is not None:
        max_bytes = args.max_ram * 1024 * 1024
        limited = []
        remaining = max_bytes
        for start, end in ram_ranges:
            if remaining <= 0:
                break
            size = end - start
            if size > remaining:
                limited.append((start, start + remaining))
                remaining = 0
            else:
                limited.append((start, end))
                remaining -= size
        ram_ranges = limited

    total_bytes = sum(end - start for start, end in ram_ranges)
    print(f"RAM: {total_bytes // (1024*1024)} MB in {len(ram_ranges)} range(s)", file=sys.stderr)
    print(f"Struct size: {struct_size} bytes, min checks: {min_checks}, "
          f"fields: {len(fields)}", file=sys.stderr)

    # Safety: open read-only
    fd = os.open(args.dev_mem, os.O_RDONLY | os.O_SYNC)

    try:
        candidates, scanned_bytes = scan_memory(
            fd, ram_ranges, anchor_bytes, anchor_offset, anchor_format,
            struct_size, fields, kptr_ranges, min_checks)
    finally:
        os.close(fd)

    result = build_result(candidates, scanned_bytes)

    # JSON to stdout
    print(json.dumps(result, indent=2))

    if result.get('found'):
        base = result['struct_base_phys']
        checks = result['checks_passed']
        total = result['total_checks']
        print(f"\nFound struct at {base} ({checks}/{total} checks passed)", file=sys.stderr)
    else:
        print(f"\n{result.get('error', 'Not found')}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
