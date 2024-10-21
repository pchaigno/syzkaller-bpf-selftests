#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <linux/bpf_perf_event.h>
#include <linux/bpf.h>
#include <bpf/btf.h>
#include "bpf_rand.h"
#include "filter.h"
#include "test_btf.h"

#define MAX_INSNS 4096
#define MAX_EXPECTED_INSNS  32
#define MAX_UNEXPECTED_INSNS    32
#define MAX_TEST_INSNS  1000000
#define MAX_FIXUPS 8
#define MAX_TEST_RUNS   8
#define TEST_DATA_LEN   64
#define MAX_FUNC_INFOS  8
#define MAX_BTF_STRINGS 256
#define MAX_BTF_TYPES   256

#define INSN_OFF_MASK   ((__s16)0xFFFF)
#define INSN_IMM_MASK   ((__s32)0xFFFFFFFF)
#define SKIP_INSNS()    BPF_RAW_INSN(0xde, 0xa, 0xd, 0xbeef, 0xdeadbeef)

#define POINTER_VALUE      0xcafe4all

#define ETH_HLEN  14

#define F_NEEDS_EFFICIENT_UNALIGNED_ACCESS  (1 << 0)
#define F_LOAD_WITH_STRICT_ALIGNMENT        (1 << 1)
#define F_NEEDS_JIT_ENABLED         (1 << 2)

/**
 * sizeof_field() - Report the size of a struct field in bytes
 *
 * @TYPE: The structure containing the field of interest
 * @MEMBER: The field to return the size of
 */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

/**
 * offsetofend() - Report the offset of a struct field within the struct
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 */
#define offsetofend(TYPE, MEMBER) \
    (offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))

struct kfunc_btf_id_pair {
    const char *kfunc;
    int insn_idx;
    struct bpf_stack_build_id test;
};

struct bpf_test {
    const char *descr;
    struct bpf_insn insns[MAX_INSNS];
    struct bpf_insn *fill_insns;
    /* If specified, test engine looks for this sequence of
     * instructions in the BPF program after loading. Allows to
     * test rewrites applied by verifier.  Use values
     * INSN_OFF_MASK and INSN_IMM_MASK to mask `off` and `imm`
     * fields if content does not matter.  The test case fails if
     * specified instructions are not found.
     *
     * The sequence could be split into sub-sequences by adding
     * SKIP_INSNS instruction at the end of each sub-sequence. In
     * such case sub-sequences are searched for one after another.
     */
    struct bpf_insn expected_insns[MAX_EXPECTED_INSNS];
    /* If specified, test engine applies same pattern matching
     * logic as for `expected_insns`. If the specified pattern is
     * matched test case is marked as failed.
     */
    struct bpf_insn unexpected_insns[MAX_UNEXPECTED_INSNS];
    int fixup_map_hash_8b[MAX_FIXUPS];
    int fixup_map_hash_48b[MAX_FIXUPS];
    int fixup_map_hash_16b[MAX_FIXUPS];
    int fixup_map_array_48b[MAX_FIXUPS];
    int fixup_map_sockmap[MAX_FIXUPS];
    int fixup_map_sockhash[MAX_FIXUPS];
    int fixup_map_xskmap[MAX_FIXUPS];
    int fixup_map_stacktrace[MAX_FIXUPS];
    int fixup_prog1[MAX_FIXUPS];
    int fixup_prog2[MAX_FIXUPS];
    int fixup_map_in_map[MAX_FIXUPS];
    int fixup_cgroup_storage[MAX_FIXUPS];
    int fixup_percpu_cgroup_storage[MAX_FIXUPS];
    int fixup_map_spin_lock[MAX_FIXUPS];
    int fixup_map_array_ro[MAX_FIXUPS];
    int fixup_map_array_wo[MAX_FIXUPS];
    int fixup_map_array_small[MAX_FIXUPS];
    int fixup_sk_storage_map[MAX_FIXUPS];
    int fixup_map_event_output[MAX_FIXUPS];
    int fixup_map_reuseport_array[MAX_FIXUPS];
    int fixup_map_ringbuf[MAX_FIXUPS];
    int fixup_map_timer[MAX_FIXUPS];
    int fixup_map_kptr[MAX_FIXUPS];
    struct kfunc_btf_id_pair fixup_kfunc_btf_id[MAX_FIXUPS];
    /* Expected verifier log output for result REJECT or VERBOSE_ACCEPT.
     * Can be a tab-separated sequence of expected strings. An empty string
     * means no log verification.
     */
    const char *errstr;
    const char *errstr_unpriv;
    uint32_t insn_processed;
    int prog_len;
    enum {
        UNDEF,
        ACCEPT,
        REJECT,
        VERBOSE_ACCEPT,
    } result, result_unpriv;
    enum bpf_prog_type prog_type;
    uint8_t flags;
    void (*fill_helper)(struct bpf_test *self);
    int runs;
#define bpf_testdata_struct_t                   \
    struct {                        \
        uint32_t retval, retval_unpriv;         \
        union {                     \
            __u8 data[TEST_DATA_LEN];       \
            __u64 data64[TEST_DATA_LEN / 8];    \
        };                      \
    }
    union {
        bpf_testdata_struct_t;
        bpf_testdata_struct_t retvals[MAX_TEST_RUNS];
    };
    enum bpf_attach_type expected_attach_type;
    const char *kfunc;
    struct bpf_func_info func_info[MAX_FUNC_INFOS];
    int func_info_cnt;
    char btf_strings[MAX_BTF_STRINGS];
    /* A set of BTF types to load when specified,
     * use macro definitions from test_btf.h,
     * must end with BTF_END_RAW
     */
    __u32 btf_types[MAX_BTF_TYPES];
};

static int probe_filter_length(const struct bpf_insn *fp)
{
    int len;

    for (len = MAX_INSNS - 1; len >= 0; --len)
        if (fp[len].code != 0 || fp[len].imm != 0)
            break;
    return len + 1;
}

/* BPF_DIRECT_PKT_R2 contains 7 instructions, it initializes default return
 * value into 0 and does necessary preparation for direct packet access
 * through r2. The allowed access range is 8 bytes.
 */
#define BPF_DIRECT_PKT_R2                       \
    BPF_MOV64_IMM(BPF_REG_0, 0),                    \
    BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,            \
            offsetof(struct __sk_buff, data)),          \
    BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,            \
            offsetof(struct __sk_buff, data_end)),      \
    BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),                \
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 8),               \
    BPF_JMP_REG(BPF_JLE, BPF_REG_4, BPF_REG_3, 1),          \
    BPF_EXIT_INSN()

/* BPF_RAND_UEXT_R7 contains 4 instructions, it initializes R7 into a random
 * positive u32, and zero-extend it into 64-bit.
 */
#define BPF_RAND_UEXT_R7                        \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,           \
             BPF_FUNC_get_prandom_u32),             \
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),                \
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_7, 33),              \
    BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 33)

/* BPF_RAND_SEXT_R7 contains 5 instructions, it initializes R7 into a random
 * negative u32, and sign-extend it into 64-bit.
 */
#define BPF_RAND_SEXT_R7                        \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,           \
             BPF_FUNC_get_prandom_u32),             \
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),                \
    BPF_ALU64_IMM(BPF_OR, BPF_REG_7, 0x80000000),           \
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_7, 32),              \
    BPF_ALU64_IMM(BPF_ARSH, BPF_REG_7, 32)

static void bpf_fill_ld_abs_vlan_push_pop(struct bpf_test *self)
{
    /* test: {skb->data[0], vlan_push} x 51 + {skb->data[0], vlan_pop} x 51 */
#define PUSH_CNT 51
    /* jump range is limited to 16 bit. PUSH_CNT of ld_abs needs room */
    unsigned int len = (1 << 15) - PUSH_CNT * 2 * 5 * 6;
    struct bpf_insn *insn = self->fill_insns;
    int i = 0, j, k = 0;

    insn[i++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
loop:
    for (j = 0; j < PUSH_CNT; j++) {
        insn[i++] = BPF_LD_ABS(BPF_B, 0);
        /* jump to error label */
        insn[i] = BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0x34, len - i - 3);
        i++;
        insn[i++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
        insn[i++] = BPF_MOV64_IMM(BPF_REG_2, 1);
        insn[i++] = BPF_MOV64_IMM(BPF_REG_3, 2);
        insn[i++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
                     BPF_FUNC_skb_vlan_push);
        insn[i] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, len - i - 3);
        i++;
    }

    for (j = 0; j < PUSH_CNT; j++) {
        insn[i++] = BPF_LD_ABS(BPF_B, 0);
        insn[i] = BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0x34, len - i - 3);
        i++;
        insn[i++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
        insn[i++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
                     BPF_FUNC_skb_vlan_pop);
        insn[i] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, len - i - 3);
        i++;
    }
    if (++k < 5)
        goto loop;

    for (; i < len - 3; i++)
        insn[i] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0xbef);
    insn[len - 3] = BPF_JMP_A(1);
    /* error label */
    insn[len - 2] = BPF_MOV32_IMM(BPF_REG_0, 0);
    insn[len - 1] = BPF_EXIT_INSN();
    self->prog_len = len;
}

static void bpf_fill_jump_around_ld_abs(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    /* jump range is limited to 16 bit. every ld_abs is replaced by 6 insns,
     * but on arches like arm, ppc etc, there will be one BPF_ZEXT inserted
     * to extend the error value of the inlined ld_abs sequence which then
     * contains 7 insns. so, set the dividend to 7 so the testcase could
     * work on all arches.
     */
    unsigned int len = (1 << 15) / 7;
    int i = 0;

    insn[i++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
    insn[i++] = BPF_LD_ABS(BPF_B, 0);
    insn[i] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 10, len - i - 2);
    i++;
    while (i < len - 1)
        insn[i++] = BPF_LD_ABS(BPF_B, 1);
    insn[i] = BPF_EXIT_INSN();
    self->prog_len = i + 1;
}

static void bpf_fill_rand_ld_dw(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    uint64_t res = 0;
    int i = 0;

    insn[i++] = BPF_MOV32_IMM(BPF_REG_0, 0);
    while (i < self->retval) {
        uint64_t val = bpf_semi_rand_get();
        struct bpf_insn tmp[2] = { BPF_LD_IMM64(BPF_REG_1, val) };

        res ^= val;
        insn[i++] = tmp[0];
        insn[i++] = tmp[1];
        insn[i++] = BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1);
    }
    insn[i++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
    insn[i++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32);
    insn[i++] = BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1);
    insn[i] = BPF_EXIT_INSN();
    self->prog_len = i + 1;
    res ^= (res >> 32);
    self->retval = (uint32_t)res;
}

#define MAX_JMP_SEQ 8192

/* test the sequence of 8k jumps */
static void bpf_fill_scale1(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    int i = 0, k = 0;

    insn[i++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
    /* test to check that the long sequence of jumps is acceptable */
    while (k++ < MAX_JMP_SEQ) {
        insn[i++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
                     BPF_FUNC_get_prandom_u32);
        insn[i++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, bpf_semi_rand_get(), 2);
        insn[i++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        insn[i++] = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
                    -8 * (k % 64 + 1));
    }
    /* is_state_visited() doesn't allocate state for pruning for every jump.
     * Hence multiply jmps by 4 to accommodate that heuristic
     */
    while (i < MAX_TEST_INSNS - MAX_JMP_SEQ * 4)
        insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 42);
    insn[i] = BPF_EXIT_INSN();
    self->prog_len = i + 1;
    self->retval = 42;
}

/* test the sequence of 8k jumps in inner most function (function depth 8)*/
static void bpf_fill_scale2(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    int i = 0, k = 0;

#define FUNC_NEST 7
    for (k = 0; k < FUNC_NEST; k++) {
        insn[i++] = BPF_CALL_REL(1);
        insn[i++] = BPF_EXIT_INSN();
    }
    insn[i++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
    /* test to check that the long sequence of jumps is acceptable */
    k = 0;
    while (k++ < MAX_JMP_SEQ) {
        insn[i++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
                     BPF_FUNC_get_prandom_u32);
        insn[i++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, bpf_semi_rand_get(), 2);
        insn[i++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        insn[i++] = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
                    -8 * (k % (64 - 4 * FUNC_NEST) + 1));
    }
    while (i < MAX_TEST_INSNS - MAX_JMP_SEQ * 4)
        insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 42);
    insn[i] = BPF_EXIT_INSN();
    self->prog_len = i + 1;
    self->retval = 42;
}

static void bpf_fill_scale(struct bpf_test *self)
{
    switch (self->retval) {
    case 1:
        return bpf_fill_scale1(self);
    case 2:
        return bpf_fill_scale2(self);
    default:
        self->prog_len = 0;
        break;
    }
}

static int bpf_fill_torturous_jumps_insn_1(struct bpf_insn *insn)
{
    unsigned int len = 259, hlen = 128;
    int i;

    insn[0] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
    for (i = 1; i <= hlen; i++) {
        insn[i]        = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, i, hlen);
        insn[i + hlen] = BPF_JMP_A(hlen - i);
    }
    insn[len - 2] = BPF_MOV64_IMM(BPF_REG_0, 1);
    insn[len - 1] = BPF_EXIT_INSN();

    return len;
}

static int bpf_fill_torturous_jumps_insn_2(struct bpf_insn *insn)
{
    unsigned int len = 4100, jmp_off = 2048;
    int i, j;

    insn[0] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
    for (i = 1; i <= jmp_off; i++) {
        insn[i] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, i, jmp_off);
    }
    insn[i++] = BPF_JMP_A(jmp_off);
    for (; i <= jmp_off * 2 + 1; i+=16) {
        for (j = 0; j < 16; j++) {
            insn[i + j] = BPF_JMP_A(16 - j - 1);
        }
    }

    insn[len - 2] = BPF_MOV64_IMM(BPF_REG_0, 2);
    insn[len - 1] = BPF_EXIT_INSN();

    return len;
}

static void bpf_fill_torturous_jumps(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    int i = 0;

    switch (self->retval) {
    case 1:
        self->prog_len = bpf_fill_torturous_jumps_insn_1(insn);
        return;
    case 2:
        self->prog_len = bpf_fill_torturous_jumps_insn_2(insn);
        return;
    case 3:
        /* main */
        insn[i++] = BPF_RAW_INSN(BPF_JMP|BPF_CALL, 0, 1, 0, 4);
        insn[i++] = BPF_RAW_INSN(BPF_JMP|BPF_CALL, 0, 1, 0, 262);
        insn[i++] = BPF_ST_MEM(BPF_B, BPF_REG_10, -32, 0);
        insn[i++] = BPF_MOV64_IMM(BPF_REG_0, 3);
        insn[i++] = BPF_EXIT_INSN();

        /* subprog 1 */
        i += bpf_fill_torturous_jumps_insn_1(insn + i);

        /* subprog 2 */
        i += bpf_fill_torturous_jumps_insn_2(insn + i);

        self->prog_len = i;
        return;
    default:
        self->prog_len = 0;
        break;
    }
}

static void bpf_fill_big_prog_with_loop_1(struct bpf_test *self)
{
    struct bpf_insn *insn = self->fill_insns;
    /* This test was added to catch a specific use after free
     * error, which happened upon BPF program reallocation.
     * Reallocation is handled by core.c:bpf_prog_realloc, which
     * reuses old memory if page boundary is not crossed. The
     * value of `len` is chosen to cross this boundary on bpf_loop
     * patching.
     */
    const int len = getpagesize() - 25;
    int callback_load_idx;
    int callback_idx;
    int i = 0;

    insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, 1);
    callback_load_idx = i;
    insn[i++] = BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW,
                 BPF_REG_2, BPF_PSEUDO_FUNC, 0,
                 777 /* filled below */);
    insn[i++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
    insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_3, 0);
    insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_4, 0);
    insn[i++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_loop);

    while (i < len - 3)
        insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0);
    insn[i++] = BPF_EXIT_INSN();

    callback_idx = i;
    insn[i++] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0);
    insn[i++] = BPF_EXIT_INSN();

    insn[callback_load_idx].imm = callback_idx - callback_load_idx - 1;
    self->func_info[1].insn_off = callback_idx;
    self->prog_len = i;
    assert(i == len);
}

static struct bpf_test tests[] = {
#include "verifier/atomic_and.c"
#include "verifier/atomic_bounds.c"
#include "verifier/atomic_cmpxchg.c"
#include "verifier/atomic_fetch_add.c"
#include "verifier/atomic_fetch.c"
#include "verifier/atomic_invalid.c"
#include "verifier/atomic_or.c"
#include "verifier/atomic_xchg.c"
#include "verifier/atomic_xor.c"
#include "verifier/basic.c"
#include "verifier/basic_call.c"
#include "verifier/basic_instr.c"
#include "verifier/basic_stx_ldx.c"
#include "verifier/bpf_loop_inline.c"
#include "verifier/bpf_st_mem.c"
#include "verifier/calls.c"
#include "verifier/ctx_skb.c"
#include "verifier/ctx_sk_lookup.c"
#include "verifier/dead_code.c"
#include "verifier/direct_value_access.c"
#include "verifier/event_output.c"
#include "verifier/jit.c"
#include "verifier/jmp32.c"
#include "verifier/jset.c"
#include "verifier/jump.c"
#include "verifier/junk_insn.c"
#include "verifier/ld_abs.c"
#include "verifier/ld_dw.c"
#include "verifier/ld_imm64.c"
#include "verifier/map_kptr.c"
#include "verifier/perf_event_sample_period.c"
#include "verifier/precise.c"
#include "verifier/scale.c"
#include "verifier/sleepable.c"
#include "verifier/wide_access.c"
};

void main() {}
