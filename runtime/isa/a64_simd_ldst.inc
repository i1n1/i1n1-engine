/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SIMD&FP load/store, immediate-addressed families (Arm ARM C7.2 LDP/STP/LDNP/STNP (SIMD&FP),
 * LDR/STR (immediate, SIMD&FP), LDUR/STUR (SIMD&FP)). Textually included by a64.c after
 * a64_more.inc (it uses that file's static helpers and adds no external symbols; the product EFI
 * build lists engine sources explicitly, so a new translation unit would need shared-file edits).
 *
 *   pair   : S/D/Q x { LDNP/STNP, post-index, signed offset, pre-index }
 *   single : B/H/S/D/Q x { unsigned offset, unscaled (LDUR/STUR), post-index, pre-index }
 *
 * Register-offset and literal forms and the structure loads/stores live in a64_simd_ext.c
 * (ocnext_a64_simd_mem_*) and share the FPEN gate and the unknown-source policy below.
 *
 * Contract
 *  - Encodings the architecture leaves unallocated (pair opc 11, Q/B-H-S-D size mixes, bits 11:10
 *    = 10 unprivileged slot, load pair with Rt == Rt2 which is CONSTRAINED UNPREDICTABLE) are a
 *    deterministic stop, never an execution.
 *  - Order: reserved check, sync profile, FPEN (EC 0x07 trap), SP alignment, then ONE memory
 *    transaction of the whole transfer (both halves of a pair). A fault commits nothing: no
 *    register, no writeback, no memory. Pair/single alignment is the element size, so Q is 16
 *    when strict data alignment is in force; LDNP/STNP carry no alignment difference.
 *  - A load writes the whole 128-bit Vt (upper bytes zeroed, all 16 bytes KNOWN). The base
 *    register and Vt are different register files: V31 is an ordinary vector, Xn 31 is SP.
 *  - Store sources must be KNOWN. A source byte the CPU model never wrote is an
 *    architecturally UNKNOWN reset value (not a computed one). Default: deterministic stop.
 *    Research profile (hooks->unknown_vector_store_zero): the bytes that reach MEMORY are the
 *    bank's deterministic unknown storage (always 0); the register itself stays UNKNOWN, so a
 *    later direct read still stops while a reload from memory yields known bytes. Any value is a
 *    legal choice for an UNKNOWN reset value, but memory then holds an assumption, not a
 *    measurement; boot receipts must say so.
 */

#define SIMD_LDST_PAIR 1u
#define SIMD_LDST_SINGLE 2u

struct simd_ldst_plan {
    uint32_t opcode;
    uint8_t form;        /* SIMD_LDST_PAIR / SIMD_LDST_SINGLE; 0 = not this family */
    uint8_t reserved;    /* in the family but unallocated/unpredictable: stop */
    uint8_t load;
    uint8_t rt, rt2, rn;
    uint8_t size;        /* bytes per register: 1,2,4,8,16 */
    uint8_t nregs;       /* 1 or 2 */
    uint8_t wb;          /* pre/post-index writeback */
    uint8_t post;        /* writeback form: address is the unmodified base */
    int64_t offset;      /* byte offset (already scaled and sign-extended) */
};

static unsigned simd_ldst_decode(uint32_t op, struct simd_ldst_plan *p)
{
    int pair, uoff;
    unsigned opc, mode;
    if (!(op & (UINT32_C(1) << 26))) return 0;
    pair = (op & UINT32_C(0x3a000000)) == UINT32_C(0x28000000);
    uoff = !pair && (op & UINT32_C(0x3b000000)) == UINT32_C(0x39000000);
    if (!pair && !uoff && (op & UINT32_C(0x3b200000)) != UINT32_C(0x38000000)) return 0;
    p->opcode = op;
    p->form = pair ? SIMD_LDST_PAIR : SIMD_LDST_SINGLE;
    p->reserved = 0;
    p->rt = (uint8_t)(op & 31u);
    p->rn = (uint8_t)((op >> 5) & 31u);
    p->rt2 = (uint8_t)((op >> 10) & 31u);
    p->nregs = pair ? 2u : 1u;
    if (pair) {
        opc = op >> 30;
        mode = (op >> 23) & 3u;          /* 0 NP, 1 post, 2 offset, 3 pre */
        p->size = (uint8_t)(4u << opc);
        p->load = (uint8_t)((op >> 22) & 1u);
        p->offset = (int64_t)(sign_extend((op >> 15) & 127u, 7) * p->size);
        p->wb = (uint8_t)(mode == 1 || mode == 3);
        p->post = (uint8_t)(mode == 1);
        if (opc == 3 || (p->load && p->rt == p->rt2)) p->reserved = 1;
    } else {
        opc = (op >> 22) & 3u;
        mode = uoff ? 0u : (op >> 10) & 3u;   /* 0 unscaled, 1 post, 2 reserved, 3 pre */
        p->size = (uint8_t)(opc < 2 ? 1u << (op >> 30) : 16u);
        p->load = (uint8_t)(opc & 1u);
        p->offset = uoff ? (int64_t)((uint64_t)((op >> 10) & 4095u) * p->size)
                         : (int64_t)sign_extend((op >> 12) & 511u, 9);
        p->wb = (uint8_t)(!uoff && (mode == 1 || mode == 3));
        p->post = (uint8_t)(!uoff && mode == 1);
        if ((!uoff && mode == 2) || (opc >= 2 && (op >> 30) != 0)) p->reserved = 1;
    }
    return 1;
}

/* Source bytes of a store. `unknown_ok` selects the research profile described above. */
static int simd_ldst_gather(const struct ocnext_a64_vector_registers *bank, const struct simd_ldst_plan *p,
                            int unknown_ok, uint8_t *buf)
{
    uint16_t mask = (uint16_t)(p->size == 16 ? UINT16_MAX : (1u << p->size) - 1u);
    unsigned reg, i;
    for (reg = 0; reg < p->nregs; ++reg) {
        unsigned r = reg ? p->rt2 : p->rt;
        if (!unknown_ok && (bank->known_bytes[r] & mask) != mask) return -1;
        for (i = 0; i < p->size; ++i)
            buf[reg * p->size + i] = (bank->known_bytes[r] >> i) & 1u ? bank->bytes[r][i] : 0;
    }
    return 0;
}

/* Resolve unknown source bytes of a register-offset / structure store under the same policy. */
static int simd_mem_gather_policy(const struct ocnext_a64_cpu *cpu, const struct ocnext_a64_hooks *hooks,
                                  const struct ocnext_a64_simd_mem_plan *plan, uint8_t *buf)
{
    struct ocnext_a64_vector_registers resolved;
    unsigned r, i;
    if (ocnext_a64_simd_mem_gather(&cpu->vector, plan, buf) == OCNEXT_A64_SIMD_EXT_OK) return 0;
    if (!hooks || !hooks->unknown_vector_store_zero) return -1;
    resolved = cpu->vector;
    for (r = 0; r < 32; ++r) {
        for (i = 0; i < 16; ++i)
            if (!((resolved.known_bytes[r] >> i) & 1u)) resolved.bytes[r][i] = 0;
        resolved.known_bytes[r] = OCNEXT_A64_VECTOR_KNOWN_ALL;
    }
    return ocnext_a64_simd_mem_gather(&resolved, plan, buf) == OCNEXT_A64_SIMD_EXT_OK ? 0 : -1;
}

static int simd_ldst_exec(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
                          const struct ocnext_a64_hooks *hooks, const struct simd_ldst_plan *p,
                          struct transaction *tx, enum ocnext_a64_result *res)
{
    uint8_t buf[32];
    uint64_t base, address;
    unsigned total = (unsigned)p->size * p->nregs;
    enum ocnext_a64_fault_code code;
    int st;
    if (p->reserved) return MORE_UNSUPPORTED;
    st = more_fp_access(cpu, memory, p->opcode, res);
    if (st != MORE_OK) return st;
    if (stop_sp_alignment(cpu, memory, p->opcode, p->rn, res)) return MORE_RESULT;
    base = reg_read(cpu, p->rn, 64, 1);
    address = p->post ? base : base + (uint64_t)p->offset;
    if (!p->load && simd_ldst_gather(&cpu->vector, p, hooks && hooks->unknown_vector_store_zero, buf) != 0)
        return MORE_UNSUPPORTED;
    code = memory_transfer(cpu, memory, address, buf, total, p->size, p->load);
    if (code != OCNEXT_A64_FAULT_NONE) {
        *res = fault(cpu, code, p->load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, address, total,
                     p->opcode);
        return MORE_RESULT;
    }
    if (p->load) {
        stage_vector(tx, p->rt, buf, p->size);
        if (p->nregs == 2) stage_vector(tx, p->rt2, buf + p->size, p->size);
    }
    if (p->wb) stage_write(tx, p->rn, base + (uint64_t)p->offset, 64, 1);
    return MORE_OK;
}
