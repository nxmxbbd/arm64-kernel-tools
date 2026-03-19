# ARM64 I-cache Pitfalls

How to crash a kernel in one easy step: write new instructions to memory and forget that the I-cache does not know about them.

## The Fundamental Problem

On x86, the instruction cache and data cache are coherent. If you write a new instruction to memory, the CPU will see the new instruction when it executes that address. You can patch kernel text with a simple `memcpy` and it works.

**ARM64 is not x86.** On ARM64, the D-cache (data cache) and I-cache (instruction cache) are **not coherent with each other**. If you write new instructions through the D-cache, the I-cache still has the old instructions cached. When the CPU fetches from that address, it executes the stale I-cache contents — which are the old, unpatched instructions (or worse, partially coherent garbage).

This is defined by the ARM architecture, not a bug. ARMv8-A explicitly states that instruction and data caches are not required to be coherent, and in practice, they never are.

## The Three Crashes

During the development of the kernel text patching tools, three different approaches were tried before getting it right.

### Crash 1: Python ctypes Direct Write

**What happened**: A Python script opened `/dev/mem`, mmap'd the physical page containing the target instruction, and wrote the new instruction bytes via ctypes.

```python
# This crashes the kernel on ARM64
mm = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=page_pa)
struct.pack_into('<I', mm, offset_in_page, new_instruction)
mm.close()
```

The write went through. A read-back confirmed the new instruction was in memory. But when the CPU next executed that address, it fetched the **old instruction from the I-cache** and the kernel crashed — the old instruction was now inconsistent with the surrounding patched code.

**Root cause**: The `struct.pack_into` writes go through the D-cache. The I-cache is never invalidated. ARM64 has no hardware I-cache snooping of D-cache writes.

### Crash 2: The drop_caches Red Herring

**What happened**: After Crash 1, the next attempt tried flushing caches between the write and the execution:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

The kernel still crashed.

**Root cause**: `drop_caches` flushes the **page cache** (the kernel's file/block I/O cache in RAM). It has absolutely nothing to do with CPU caches. The I-cache is a hardware cache inside the CPU core, not a software cache in the kernel. `drop_caches` does not execute any cache maintenance instructions.

### Crash 3: Python ctypes JIT Cache Issues

**What happened**: An attempt to use Python's ctypes to call inline assembly for cache maintenance. The idea was to JIT-compile a small function containing the `DC CVAU` / `IC IVAU` instructions and call it via ctypes.

This had its own problems: ctypes' function pointer mechanism involves writing to memory and executing it, which has the same I-cache coherency issue. The cache maintenance code itself was subject to the same bug it was trying to fix.

**Root cause**: You cannot reliably execute JIT'd ARM64 code from Python without first solving the cache coherency problem — which is the problem you are trying to solve. Circular dependency.

## The Correct Solution

The ARM64 architecture defines a specific instruction sequence for making data writes visible to the instruction stream:

```
DC CVAU, <addr>     // Clean D-cache by VA to Point of Unification
DSB ISH              // Data Synchronization Barrier (Inner Shareable)
IC IVAU, <addr>      // Invalidate I-cache by VA to Point of Unification
DSB ISH              // Ensure I-cache invalidation completes
ISB                  // Instruction Synchronization Barrier — flush pipeline
```

Step by step:

1. **DC CVAU**: Cleans (writes back) the D-cache line containing the address to the Point of Unification — the level of the memory hierarchy where the I-cache and D-cache are guaranteed to see the same data. On most ARM64 implementations, this is the L2 cache or main memory.

2. **DSB ISH**: Ensures the D-cache clean has completed and is visible to all cores in the Inner Shareable domain before proceeding.

3. **IC IVAU**: Invalidates the I-cache line containing the address. The next instruction fetch from this address will miss in the I-cache and fetch from the Point of Unification (where the D-cache clean already placed the new data).

4. **DSB ISH**: Ensures the I-cache invalidation has completed on all cores.

5. **ISB**: Flushes the CPU pipeline. Any instructions fetched before this point are discarded and re-fetched. This ensures the current core sees the new instructions immediately.

## Why `__builtin___clear_cache()` Works

The GCC/Clang built-in `__builtin___clear_cache(begin, end)` emits the correct architecture-specific cache maintenance sequence. On ARM64, it generates the `DC CVAU` + `DSB ISH` + `IC IVAU` + `DSB ISH` + `ISB` sequence (or calls a runtime helper that does).

```c
// Correct approach in C
volatile uint32_t *patch_addr = (uint32_t *)(mmap_base + offset);
*patch_addr = new_instruction;
__builtin___clear_cache((char *)patch_addr, (char *)patch_addr + 4);
```

This is why `text-hotpatch.c` exists as a compiled C program rather than a Python script. The C compiler gives us access to `__builtin___clear_cache()`, which is the simplest reliable way to perform cache maintenance from userspace.

## Cortex-A57 Specifics

The Cortex-A57 (used in the Alpine AL-524 on the UDM SE) has a VIPT (Virtually Indexed, Physically Tagged) I-cache that behaves as PIPT (Physically Indexed, Physically Tagged) because it is smaller than the page size times associativity.

What this means in practice:

- `IC IVAU` invalidates by virtual address, but because the I-cache is effectively PIPT, the physical address determines which line is invalidated.
- If you mmap the same physical page at two different virtual addresses, `IC IVAU` on either VA will invalidate the same I-cache line. This simplifies the mmap trick (below).
- The I-cache is 48KB, 3-way set-associative, 64-byte lines.

## The SCTLR_EL1.UCI Bit

`IC IVAU` is an EL1 (kernel) instruction by default. For it to work from EL0 (userspace), the `SCTLR_EL1.UCI` bit (bit 26) must be set. Linux sets this bit, which is why `__builtin___clear_cache()` works from userspace processes.

If you are on a platform where UCI is not set, `IC IVAU` from userspace will trap to EL1. Linux handles this trap and performs the invalidation on behalf of the process, so it still works — just slower.

## The mmap Trick

To perform I-cache maintenance on kernel text from userspace:

1. Open `/dev/mem` and mmap the physical page containing the target instruction.
2. You now have a **userspace virtual address** that maps to the same physical page as the kernel text.
3. Write the new instruction through this mmap'd VA (goes through D-cache).
4. Call `__builtin___clear_cache()` on this same VA.
5. The `DC CVAU` cleans the D-cache line to the PoU.
6. The `IC IVAU` invalidates the I-cache line. Because the I-cache is effectively PIPT on Cortex-A57, this invalidates the line regardless of which VA (your userspace VA or the kernel's VA) was used to fetch it.
7. `DSB ISH` ensures all cores see the invalidation.
8. The next time any core fetches the kernel instruction at the kernel's VA, the I-cache misses and fetches the new instruction from the PoU.

```c
int fd = open("/dev/mem", O_RDWR | O_SYNC);
size_t page_offset = pa & 0xFFF;
off_t page_base = pa & ~0xFFFUL;

void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page_base);
volatile uint32_t *target = (volatile uint32_t *)((char *)map + page_offset);

// Read-verify before patching
uint32_t old = *target;
assert(old == expected_old_instruction);

// Write new instruction
*target = new_instruction;

// Critical: cache maintenance
__builtin___clear_cache((char *)target, (char *)target + 4);

// Read-verify after patching
assert(*target == new_instruction);

munmap(map, 4096);
close(fd);
```

## Why Python Cannot Reliably Do This

Python has no inline assembly support. The available workarounds all have problems:

- **ctypes with JIT'd machine code**: Requires solving the I-cache problem to execute the I-cache fix. Circular.
- **ctypes calling libc's `cacheflush()`**: Linux on ARM64 does not expose `cacheflush()` as a syscall. The glibc wrapper (where it exists) uses `__builtin___clear_cache()` internally, which is a compiler built-in, not a libc function.
- **`/proc/self/mem` tricks**: Writing to `/proc/self/mem` does not perform cache maintenance either.
- **Calling `sync` or `fsync`**: These flush filesystem buffers, not CPU caches.

The reliable solution is to write the cache-sensitive code in C, compile it (cross-compile if necessary), and call it from the target system. This is a few lines of C. The complexity is in understanding *why* it is needed, not in the implementation.

## Summary

| Approach | Works on x86 | Works on ARM64 | Why |
|----------|-------------|---------------|-----|
| Write via mmap, execute | Yes | **No** | I-cache not coherent with D-cache |
| Write + `drop_caches` | Yes (no-op needed) | **No** | `drop_caches` is page cache, not CPU cache |
| Write + `__builtin___clear_cache()` | Yes (no-op on x86) | **Yes** | Correct cache maintenance sequence |
| Write via kernel's `text_poke()` | Yes | Yes | Kernel handles it internally (but requires kernel module) |

The one-line lesson: **on ARM64, always call `__builtin___clear_cache()` after modifying code in memory.** If you cannot use a C compiler, you cannot safely patch ARM64 code from userspace.
