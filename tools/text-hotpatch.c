/*
 * text-hotpatch.c -- ARM64 kernel text hotpatcher (compiled C, no JIT)
 *
 * A generic tool for patching ARM64 kernel instructions in memory via
 * /dev/mem, with proper I-cache maintenance using compiler-generated
 * cache flush intrinsics.
 *
 * This exists because ARM64 has separate D-cache and I-cache that are
 * NOT coherent with each other.  When you modify an instruction via a
 * store (which goes through the D-cache), the I-cache still holds the
 * old instruction.  You must explicitly clean the D-cache line to the
 * Point of Unification and invalidate the I-cache line.  The GCC/Clang
 * __builtin___clear_cache() intrinsic emits the correct DC CVAU + IC
 * IVAU + DSB + ISB sequence.  Python ctypes cannot reliably do this
 * because the JIT-assembled cache maintenance code itself may have
 * I-cache coherency issues, and mmap semantics in Python do not
 * guarantee the right memory type for instruction modification.
 *
 * Currently handles MOVZ Wd, #imm16 instructions, specifically:
 *   MOVZ Wd, #0xA0  -->  MOVZ Wd, #0x00   (patch)
 *   MOVZ Wd, #0x00  -->  MOVZ Wd, #0xA0   (undo)
 * The register (Rd) is preserved automatically.
 *
 * Cross-compile on x86_64:
 *   aarch64-linux-gnu-gcc -static -O2 -o text-hotpatch text-hotpatch.c
 *
 * Modes:
 *   --test   <PA>        Write same value back + cache maint (safety check)
 *   --status <PA> ...    Read-only check of patch sites
 *   --patch  <PA> ...    Apply patches (MOVZ Wd,#0xA0 -> MOVZ Wd,#0x00)
 *   --undo   <PA> ...    Reverse patches (MOVZ Wd,#0x00 -> MOVZ Wd,#0xA0)
 *   --help               Show detailed usage information
 *
 * Addresses are physical addresses in hex (0x prefix optional).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <sched.h>

#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE - 1))

/*
 * ARM64 MOVZ encoding (sf=0, 32-bit form):
 *
 *  31  30 29 28      23 22 21 20                5 4      0
 * [ 0][ opc ][ 1 0 0 1 0 1][ hw ][     imm16     ][  Rd  ]
 *
 * MOVZ Wd, #0xA0 (hw=0):
 *   0 10 100101 00 0000000010100000 Rd
 *   = 0x52801400 | Rd
 *
 * MOVZ Wd, #0x00 (hw=0):
 *   0 10 100101 00 0000000000000000 Rd
 *   = 0x52800000 | Rd
 *
 * imm16 field occupies bits [20:5], so its mask is 0x001FFFE0.
 */
#define MOVZ_A0_MASK   0xFFFFFFE0   /* mask off Rd (bits 4:0) */
#define MOVZ_A0_VAL    0x52801400   /* MOVZ Wd, #0xA0 template */
#define MOVZ_00_MASK   0xFFFFFFE0
#define MOVZ_00_VAL    0x52800000   /* MOVZ Wd, #0x00 template */
#define IMM16_MASK     0x001FFFE0   /* imm16 field bits [20:5] */
#define MOVZ_CHECK     0xFFE00000   /* top 11 bits identify MOVZ Wd */
#define MOVZ_OPCODE    0x52800000

/*
 * Pin the current process to CPU 0.
 *
 * When patching kernel text, we want deterministic behavior.  Pinning to
 * a single core avoids potential issues with cross-CPU I-cache invalidation
 * timing, since __builtin___clear_cache() issues IC IVAU which broadcasts
 * via the inner-shareable domain, but pinning ensures our subsequent reads
 * happen on the same core whose I-cache we just invalidated.
 */
static void pin_to_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0)
        fprintf(stderr, "WARNING: sched_setaffinity failed: %s\n",
                strerror(errno));
    else
        printf("Pinned to CPU0\n");
}

/* Map one page from /dev/mem containing the target physical address */
static void *map_page(int fd, unsigned long pa, int prot)
{
    unsigned long page_base = pa & PAGE_MASK;
    void *m = mmap(NULL, PAGE_SIZE, prot, MAP_SHARED, fd, page_base);
    if (m == MAP_FAILED) {
        fprintf(stderr, "mmap(PA 0x%lx, page 0x%lx) failed: %s\n",
                pa, page_base, strerror(errno));
        return NULL;
    }
    return m;
}

/* Return a pointer to the 32-bit instruction at the given PA within a mapped page */
static inline volatile uint32_t *ptr_at(void *mapped, unsigned long pa)
{
    return (volatile uint32_t *)((char *)mapped + (pa & ~PAGE_MASK));
}

/*
 * Safety test: read the instruction at PA, write the same value back,
 * perform cache maintenance, and verify the readback matches.
 * This confirms /dev/mem access and cache ops work without modifying anything.
 */
static int do_test(int fd, unsigned long pa)
{
    printf("=== Safety Test ===\n");
    printf("PA: 0x%lx\n", pa);

    void *m = map_page(fd, pa, PROT_READ | PROT_WRITE);
    if (!m) return 1;

    volatile uint32_t *p = ptr_at(m, pa);
    uint32_t val = *p;
    printf("Read:   0x%08x\n", val);

    /* Write back the same value -- no functional change */
    *p = val;
    printf("Wrote:  0x%08x (identical -- no functional change)\n", val);

    /*
     * __builtin___clear_cache() is the whole reason this tool is compiled C
     * rather than Python.  On ARM64, the compiler emits:
     *   DC CVAU, addr   -- clean D-cache to Point of Unification
     *   DSB ISH         -- ensure completion
     *   IC IVAU, addr   -- invalidate I-cache at Point of Unification
     *   DSB ISH         -- ensure completion
     *   ISB             -- synchronize instruction stream
     *
     * Python/ctypes cannot reliably emit this sequence because the
     * dynamically generated code itself would need I-cache maintenance.
     */
    __builtin___clear_cache((char *)p, (char *)p + 4);
    printf("Cache:  __builtin___clear_cache() completed\n");

    uint32_t rb = *p;
    printf("Verify: 0x%08x\n", rb);

    munmap(m, PAGE_SIZE);

    if (rb == val) {
        printf("\nPASSED -- write + cache maintenance works on this PA\n");
        return 0;
    } else {
        printf("\nFAILED -- readback mismatch (0x%08x != 0x%08x)\n", rb, val);
        return 1;
    }
}

/* Read-only status check of patch sites */
static int do_status(int fd, unsigned long *addrs, int n)
{
    printf("=== Status (%d sites) ===\n", n);
    int orig = 0, patched = 0, unk = 0;

    for (int i = 0; i < n; i++) {
        void *m = map_page(fd, addrs[i], PROT_READ);
        if (!m) { unk++; continue; }

        uint32_t insn = *ptr_at(m, addrs[i]);
        munmap(m, PAGE_SIZE);

        const char *st;
        if ((insn & MOVZ_A0_MASK) == MOVZ_A0_VAL) {
            st = "original"; orig++;
        } else if ((insn & MOVZ_CHECK) == MOVZ_OPCODE &&
                   (insn & IMM16_MASK) == 0) {
            st = "patched "; patched++;
        } else {
            st = "UNKNOWN "; unk++;
        }

        int rd  = insn & 0x1F;
        int imm = (insn >> 5) & 0xFFFF;
        printf("  [%s] PA 0x%08lx  MOVZ W%d, #0x%x  (raw 0x%08x)\n",
               st, addrs[i], rd, imm, insn);
    }

    printf("\nSummary: %d original, %d patched, %d unknown\n",
           orig, patched, unk);
    return unk > 0 ? 2 : 0;
}

/*
 * Apply or undo patches.
 *
 * Safety logic:
 *   1. Pre-check: verify instruction matches expected "before" value
 *   2. Skip:      if already in desired state, skip silently
 *   3. Write:     store new instruction value
 *   4. Cache:     __builtin___clear_cache() for D-cache/I-cache coherency
 *   5. Verify:    read back and confirm the write took effect
 *   6. Rollback:  on verify failure, restore original value + re-flush
 */
static int do_patch(int fd, unsigned long *addrs, int n, int undo)
{
    const char *action = undo ? "UNDO" : "PATCH";
    printf("=== %s (%d sites) ===\n", action, n);

    int ok = 0, skip = 0, fail = 0;

    for (int i = 0; i < n; i++) {
        void *m = map_page(fd, addrs[i], PROT_READ | PROT_WRITE);
        if (!m) { fail++; continue; }

        volatile uint32_t *p = ptr_at(m, addrs[i]);
        uint32_t old = *p;
        int rd = old & 0x1F;

        uint32_t expect_before, write_val;
        if (undo) {
            expect_before = MOVZ_00_VAL | rd;
            write_val     = MOVZ_A0_VAL | rd;
        } else {
            expect_before = MOVZ_A0_VAL | rd;
            write_val     = MOVZ_00_VAL | rd;
        }

        /* Already in desired state -- skip */
        if (old == write_val) {
            printf("  [SKIP] PA 0x%08lx  already %s\n", addrs[i],
                   undo ? "original" : "patched");
            skip++;
            munmap(m, PAGE_SIZE);
            continue;
        }

        /* Pre-check: instruction must match expected "before" pattern */
        if ((old & MOVZ_A0_MASK) != (expect_before & MOVZ_A0_MASK)) {
            printf("  [FAIL] PA 0x%08lx  unexpected: 0x%08x "
                   "(expect 0x%08x)\n", addrs[i], old, expect_before);
            fail++;
            munmap(m, PAGE_SIZE);
            continue;
        }

        /* Write the new instruction */
        *p = write_val;

        /* D-cache clean + I-cache invalidate -- the critical step */
        __builtin___clear_cache((char *)p, (char *)p + 4);

        /* Verify the write took effect */
        uint32_t rb = *p;
        if (rb == write_val) {
            printf("  [ OK ] PA 0x%08lx  W%d: 0x%08x -> 0x%08x\n",
                   addrs[i], rd, old, write_val);
            ok++;
        } else {
            /* Rollback on failure: restore original + re-flush */
            printf("  [FAIL] PA 0x%08lx  verify: wrote 0x%08x "
                   "got 0x%08x\n", addrs[i], write_val, rb);
            *p = old;
            __builtin___clear_cache((char *)p, (char *)p + 4);
            fail++;
        }

        munmap(m, PAGE_SIZE);
    }

    printf("\nResult: %d %s, %d skipped, %d failed\n",
           ok, undo ? "undone" : "patched", skip, fail);
    return fail > 0 ? 1 : 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "text-hotpatch -- ARM64 kernel text patcher with I-cache maintenance\n"
        "\n"
        "Patches MOVZ Wd, #0xA0 instructions to MOVZ Wd, #0x00 in kernel\n"
        "text via /dev/mem, with proper D-cache/I-cache coherency handling.\n"
        "\n"
        "Usage:\n"
        "  %s --test   <PA>          Safety test (write-back, no change)\n"
        "  %s --status <PA> ...      Read-only check\n"
        "  %s --patch  <PA> ...      Apply patches\n"
        "  %s --undo   <PA> ...      Reverse patches\n"
        "  %s --help                 Show this help\n"
        "\n"
        "PA = physical address in hex (0x prefix optional)\n",
        prog, prog, prog, prog, prog);
}

static void help(const char *prog)
{
    usage(prog);
    fprintf(stderr,
        "\n"
        "WHAT THIS TOOL DOES\n"
        "  Modifies ARM64 kernel instructions in physical memory via /dev/mem.\n"
        "  Specifically, it patches MOVZ Wd, #0xA0 instructions to MOVZ Wd, #0x00\n"
        "  (and can undo the change).  The register operand (Rd) is preserved.\n"
        "  Addresses are physical addresses obtained from /proc/kallsyms,\n"
        "  System.map, or similar kernel symbol sources.\n"
        "\n"
        "WHY THIS TOOL EXISTS\n"
        "  ARM64 has separate data and instruction caches that are not coherent.\n"
        "  When you modify an instruction via a normal store, the new value lands\n"
        "  in the D-cache but the I-cache still holds the stale instruction.\n"
        "  Correct patching requires: DC CVAU (clean D-cache to PoU), DSB,\n"
        "  IC IVAU (invalidate I-cache at PoU), DSB, ISB.\n"
        "\n"
        "  Python + ctypes cannot reliably handle this because:\n"
        "    - JIT-assembled cache maintenance code has its own I-cache issues\n"
        "    - Python mmap may not provide the right memory attributes\n"
        "    - No guaranteed way to emit the DSB/ISB barriers from Python\n"
        "\n"
        "  This compiled C tool uses __builtin___clear_cache(), which the compiler\n"
        "  expands to the correct architecture-specific cache maintenance sequence.\n"
        "\n"
        "CROSS-COMPILATION\n"
        "  Build a static binary on x86_64 for deployment to ARM64 targets:\n"
        "    aarch64-linux-gnu-gcc -static -O2 -o text-hotpatch text-hotpatch.c\n"
        "\n"
        "EXAMPLES\n"
        "  # Test that /dev/mem access and cache ops work at a known address:\n"
        "  ./text-hotpatch --test 0x40B04E78\n"
        "\n"
        "  # Check the current state of multiple patch sites:\n"
        "  ./text-hotpatch --status 0x40B04E78 0x40B05A3C 0x40B06210\n"
        "\n"
        "  # Apply patches (MOVZ Wd,#0xA0 -> MOVZ Wd,#0x00):\n"
        "  ./text-hotpatch --patch 0x40B04E78 0x40B05A3C 0x40B06210\n"
        "\n"
        "  # Undo patches (MOVZ Wd,#0x00 -> MOVZ Wd,#0xA0):\n"
        "  ./text-hotpatch --undo 0x40B04E78 0x40B05A3C 0x40B06210\n"
        "\n"
        "NOTES\n"
        "  - Requires root (or CAP_SYS_RAWIO) for /dev/mem access\n"
        "  - Kernel must be booted with iomem=relaxed or have CONFIG_STRICT_DEVMEM=n\n"
        "  - Patch and undo modes pin to CPU0 for deterministic cache behavior\n"
        "  - All writes are verified with a readback; failures trigger rollback\n"
    );
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--help") == 0) {
        help(argv[0]);
        return 0;
    }

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    int is_test   = (strcmp(mode, "--test") == 0);
    int is_status = (strcmp(mode, "--status") == 0);
    int is_patch  = (strcmp(mode, "--patch") == 0);
    int is_undo   = (strcmp(mode, "--undo") == 0);

    if (!is_test && !is_status && !is_patch && !is_undo) {
        usage(argv[0]);
        return 1;
    }

    /* Parse physical addresses from command line */
    int n = argc - 2;
    unsigned long *addrs = calloc(n, sizeof(unsigned long));
    if (!addrs) { perror("calloc"); return 1; }

    for (int i = 0; i < n; i++) {
        char *end;
        addrs[i] = strtoul(argv[i + 2], &end, 16);
        if (*end != '\0' && *end != '\n') {
            fprintf(stderr, "Bad address: '%s'\n", argv[i + 2]);
            free(addrs);
            return 1;
        }
        if (addrs[i] == 0) {
            fprintf(stderr, "Zero address not allowed\n");
            free(addrs);
            return 1;
        }
    }

    /* Pin to CPU0 for write operations to ensure cache coherency */
    if (is_patch || is_undo)
        pin_to_cpu0();

    int flags = is_status ? (O_RDONLY | O_SYNC) : (O_RDWR | O_SYNC);
    int fd = open("/dev/mem", flags);
    if (fd < 0) {
        perror("open(/dev/mem)");
        free(addrs);
        return 1;
    }

    int ret;
    if (is_test)
        ret = do_test(fd, addrs[0]);
    else if (is_status)
        ret = do_status(fd, addrs, n);
    else
        ret = do_patch(fd, addrs, n, is_undo);

    close(fd);
    free(addrs);
    return ret;
}
