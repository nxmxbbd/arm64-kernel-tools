# ARM64 Kernel Text Patching via /dev/mem

Step-by-step methodology for modifying running kernel instructions from userspace on ARM64 Linux.

**Read [ARM64 I-cache Pitfalls](arm64-icache-pitfalls.md) first.** If you skip the cache maintenance step, you will crash the kernel.

## Prerequisites

| Requirement | How to Check |
|-------------|-------------|
| `/dev/mem` accessible | `ls -la /dev/mem` — must exist and be readable/writable by root |
| `CONFIG_STRICT_DEVMEM=n` | `zcat /proc/config.gz \| grep STRICT_DEVMEM` or try reading a kernel address |
| `/proc/kallsyms` readable | `cat /proc/kallsyms \| head` — must show actual addresses, not all zeros |
| Root access | Required for `/dev/mem` and `/proc/kallsyms` |
| ARM64 (aarch64) | `uname -m` should show `aarch64` |

If `/proc/kallsyms` shows all zeros, set `kptr_restrict`: `echo 0 > /proc/sys/kernel/kptr_restrict`

## Step 1: Target Identification

Find the function and offset you want to patch using `/proc/kallsyms`:

```bash
# Find a symbol
grep ' ata_tf_to_fis$' /proc/kallsyms
# Output: ffffff800809c3a0 T ata_tf_to_fis

# Find all symbols in a module/subsystem
grep ' ata_' /proc/kallsyms | head -20
```

Record the virtual address (VA) of the target symbol.

If you need to patch at an offset within a function (not the first instruction), disassemble the function to find the exact offset. On the target system, if `objdump` is available:

```bash
# Disassemble from /proc/kcore if available
# Otherwise, read the raw bytes via /dev/mem and disassemble offline
```

## Step 2: VA-to-PA Translation

The kernel's virtual addresses must be converted to physical addresses to access them via `/dev/mem`.

For the kernel's linear mapping (where kernel text lives), the translation is a fixed offset from `_stext`:

```
PA = VA - VA_of_stext + PA_of_stext
```

Find `_stext`:

```bash
grep ' _stext$' /proc/kallsyms
# Output: ffffff8004081000 T _stext
```

The PA of `_stext` depends on the platform. For the UDM SE (Alpine AL-524), `_stext` PA is `0x04081000`. You can determine this from the device tree, bootloader logs, or by scanning `/dev/mem` for the kernel magic.

**Example calculation:**

```
Target VA:     0xffffff800809c3a0  (ata_tf_to_fis)
_stext VA:     0xffffff8004081000
_stext PA:     0x0000000004081000

PA = 0xffffff800809c3a0 - 0xffffff8004081000 + 0x04081000
PA = 0x000000000489c3a0
```

Alternatively, use `pte-walk.py` to walk the page tables and get the PA directly. This is more reliable if the kernel uses non-linear mappings:

```bash
sudo python3 tools/pte-walk.py --pgd-pa 0x04ca6000 --va 0xffffff800809c3a0
```

## Step 3: Instruction Verification

Before patching, read the instruction at the physical address and verify it matches what you expect:

```bash
# Read 4 bytes at the target PA
sudo python3 -c "
import mmap, struct, os
fd = os.open('/dev/mem', os.O_RDONLY | os.O_SYNC)
pa = 0x0489c3a0
page = pa & ~0xfff
offset = pa & 0xfff
mm = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ, offset=page)
val = struct.unpack('<I', mm[offset:offset+4])[0]
print(f'Instruction at PA 0x{pa:08x}: 0x{val:08x}')
mm.close()
os.close(fd)
"
```

Compare the read value against your expected instruction encoding. If they do not match, **stop**. Either your address calculation is wrong or the kernel binary has changed.

## Step 4: ARM64 Instruction Encoding

ARM64 instructions are 4 bytes, little-endian. Common instruction encodings relevant to patching:

### MOVZ (Move wide with zero)

Sets a register to a 16-bit immediate, zero-extending:

```
31 30 29 28  27 26 25 24 23  22 21 20 19 18 17 16 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
sf  1  0  1   0  0  1  0  1  hw        imm16                                             Rd
```

- `sf`: 0 = 32-bit (W register), 1 = 64-bit (X register)
- `hw`: shift amount (00=0, 01=16, 10=32, 11=48)
- `imm16`: the 16-bit immediate value
- `Rd`: destination register (0-30, or 31 for ZR)

**Example**: `MOVZ W0, #0xA0` encodes as:

```
sf=0, hw=00, imm16=0x00A0, Rd=0 (W0)
= 0 10 100101 00 0000000010100000 00000
= 0x52801400
```

To change the immediate from `0xA0` to `0x40`:

```
New: MOVZ W0, #0x40
imm16=0x0040
= 0x52800800
```

The imm16 field occupies bits 20:5. To patch just the immediate:

```
new_insn = (old_insn & ~(0xFFFF << 5)) | (new_imm16 << 5)
```

### ORR (immediate)

Logical OR with immediate. ARM64 uses a bitmask encoding scheme for logical immediates that is notoriously complex. If your target instruction is an ORR immediate, decode it carefully.

### BL (Branch with Link)

Function calls. The offset is a signed 26-bit immediate, multiplied by 4:

```
31 30 29 28 27 26  25:0
1  0  0  1  0  1   imm26
```

## Step 5: The Patch

### Method A: lseek + write (recommended for kernel 4.19)

```c
int fd = open("/dev/mem", O_RDWR | O_SYNC);
uint32_t new_insn = 0x52800800;  // MOVZ W0, #0x40

lseek(fd, target_pa, SEEK_SET);
write(fd, &new_insn, 4);
// Cache maintenance needed — see Step 6
close(fd);
```

### Method B: mmap (preferred, but has a kernel 4.19 quirk)

```c
int fd = open("/dev/mem", O_RDWR | O_SYNC);
off_t page_base = target_pa & ~0xFFFUL;
size_t page_offset = target_pa & 0xFFF;

void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page_base);
volatile uint32_t *target = (volatile uint32_t *)((char *)map + page_offset);
*target = new_insn;
__builtin___clear_cache((char *)target, (char *)target + 4);  // Step 6
munmap(map, 4096);
close(fd);
```

### The mmap PROT_WRITE Quirk on Kernel 4.19

On some ARM64 kernel 4.19 builds, `mmap` of `/dev/mem` with `PROT_WRITE` returns `EINVAL`. This is due to a restrictive check in the kernel's `/dev/mem` mmap implementation that rejects writable mappings of certain physical address ranges.

Workarounds:

1. **Use `lseek` + `write` instead of mmap for the write.** You can still mmap with `PROT_READ` for verification reads. This is what the Python tools do.
2. **Use `PROT_READ | PROT_WRITE` together** (not `PROT_WRITE` alone) — this sometimes works when `PROT_WRITE` alone does not.
3. **Use the C hotpatcher** (`text-hotpatch.c`), which handles this automatically and falls back to `lseek`+`write` if mmap fails.

## Step 6: I-cache Maintenance

**This step is mandatory. Skip it and the kernel crashes.**

See [ARM64 I-cache Pitfalls](arm64-icache-pitfalls.md) for the full explanation.

If using the mmap approach with C:

```c
__builtin___clear_cache((char *)target, (char *)target + 4);
```

If using `lseek` + `write`, you need to separately mmap the page read-only and perform cache maintenance on the mmap'd address:

```c
// After lseek+write:
void *ro_map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, page_base);
char *maint_addr = (char *)ro_map + page_offset;
__builtin___clear_cache(maint_addr, maint_addr + 4);
munmap(ro_map, 4096);
```

The cache maintenance must be performed on a userspace VA that maps to the same physical page. The mmap provides this VA.

## Step 7: Verification

Always read back the patched instruction to confirm:

```c
lseek(fd, target_pa, SEEK_SET);
uint32_t readback;
read(fd, &readback, 4);
assert(readback == new_insn);
```

If the readback does not match, the write failed silently. Do not proceed.

## Step 8: Safety Layers

A production-quality patching tool implements multiple safety checks:

### Pre-check

Before writing, verify:
- The instruction at the target address matches the expected old value
- The target address is within kernel text (between `_stext` and `_etext`)
- The new instruction is a valid ARM64 encoding (at minimum, check for illegal encodings)

### Write-verify

After writing, verify:
- Read-back matches the written value
- If it does not match, the physical page may be read-only (hardware write-protect) or the address may be wrong

### Post-scan

After all patches are applied:
- Re-read all patch sites and verify they hold the correct new values
- Run a basic sanity test (e.g., trigger the patched code path and verify the system does not crash)

### Reboot Recovery

All patches via `/dev/mem` are volatile — they modify the running kernel's memory, not the kernel image on disk. A reboot restores the original state. This is a critical safety property: you cannot permanently brick a system with these tools (assuming the filesystem is not corrupted by a crash).

## Step 9: Multi-Site Patching

When patching multiple sites (e.g., 16 inline instances of the same pattern):

### Atomicity

ARM64 does not provide cross-site atomicity for instruction patching. Each 4-byte write is atomic (aligned 32-bit writes are architecturally atomic on ARM64), but if the kernel executes a code path that crosses two patch sites while one is patched and the other is not, behavior is undefined.

In practice, for the use cases in this toolkit:
- Patch all sites as quickly as possible (minimize the window)
- Patch call sites before patching the target function
- If the patched code path is not actively executing (e.g., a drive error handler when no I/O is in flight), the atomicity risk is negligible

### Batch Cache Maintenance

For multiple patches on the same page, you can defer cache maintenance until all writes on that page are complete:

```c
// Patch all sites on this page
for (int i = 0; i < n_sites_on_page; i++) {
    target[offsets[i]] = new_insns[i];
}
// One cache maintenance call covering all patched addresses
__builtin___clear_cache(
    (char *)map + min_offset,
    (char *)map + max_offset + 4
);
```

For patches spanning multiple pages, perform cache maintenance per page after completing writes on each page.

## Step 10: Putting It All Together

The complete workflow:

```
1. grep /proc/kallsyms for target symbol → VA
2. Compute PA from VA using _stext offset
3. Read instruction at PA via /dev/mem → verify expected encoding
4. Compute new instruction encoding
5. Write new instruction to PA via /dev/mem
6. Perform I-cache maintenance on the page
7. Read-back verify the write
8. Test the patched code path
9. (After debugging is complete, reboot to restore original state)
```

Use `text-hotpatch.py --status` or `text-hotpatch.c --status` to check the current state of known patch sites without modifying anything.
