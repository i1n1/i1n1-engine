#include "ocnext/a64_atomic.h"

/* Exclusives, ordered accesses and LSE atomics for the single-core A64 model.
 *
 * Monitor: one local exclusive monitor, Open or Exclusive{address,size}, kept
 * in the idle fault record (fault.address / fault.access_size) while
 * fault.code==NONE. A real fault overwrites the record, which is correct: a
 * faulted CPU never resumes, and abort delivery enters an exception that
 * clears the monitor. Addresses are the VAs handed to the memory callbacks.
 *
 * Ordering: this interpreter retires instructions strictly in program order
 * against one memory view, so acquire/release/RCpc/non-temporal ordering is
 * satisfied by construction. There is no second observer, so atomicity of
 * LSE read-modify-write is also by construction. Neither claim extends to
 * SMP, DMA or MMIO ordering; those stay with the memory provider.
 */

static uint64_t gpr(const struct ocnext_a64_cpu *cpu, unsigned reg)
{
    return reg == 31 ? 0 : cpu->x[reg];
}

static uint64_t size_mask(unsigned bytes)
{
    return bytes >= 8 ? UINT64_MAX : (UINT64_C(1) << (bytes * 8u)) - 1u;
}

static uint64_t le_read(const uint8_t *b, unsigned n)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < n; ++i) v |= (uint64_t)b[i] << (8u * i);
    return v;
}

static void le_write(uint8_t *b, uint64_t v, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i) b[i] = (uint8_t)(v >> (8u * i));
}

static int64_t sext(uint64_t v, unsigned bytes)
{
    unsigned bits = bytes * 8u;
    uint64_t sign;
    if (bits >= 64) return (int64_t)v;
    sign = UINT64_C(1) << (bits - 1u);
    v &= size_mask(bytes);
    return (int64_t)((v ^ sign) - sign);
}

/* ---- local exclusive monitor ---- */

int ocnext_a64_exclusive_state(const struct ocnext_a64_cpu *cpu,
                               uint64_t *address, unsigned *size)
{
    if (!cpu || cpu->fault.code != OCNEXT_A64_FAULT_NONE || !cpu->fault.access_size) return 0;
    if (address) *address = cpu->fault.address;
    if (size) *size = cpu->fault.access_size;
    return 1;
}

void ocnext_a64_exclusive_clear(struct ocnext_a64_cpu *cpu)
{
    if (!cpu || cpu->fault.code != OCNEXT_A64_FAULT_NONE) return;
    cpu->fault.address = 0;
    cpu->fault.access_size = 0;
}

static void monitor_set(struct ocnext_a64_cpu *cpu, uint64_t address, unsigned size)
{
    cpu->fault.address = address;
    cpu->fault.access_size = size;
}

static int monitor_matches(const struct ocnext_a64_cpu *cpu, uint64_t address, unsigned size)
{
    return cpu->fault.code == OCNEXT_A64_FAULT_NONE && cpu->fault.access_size == size &&
           cpu->fault.address == address;
}

void ocnext_a64_exclusive_clear_overlap(struct ocnext_a64_cpu *cpu,
                                        uint64_t address, uint64_t size)
{
    uint64_t base;
    if (!cpu || !size || cpu->fault.code != OCNEXT_A64_FAULT_NONE || !cpu->fault.access_size) return;
    base = cpu->fault.address;
    /* Wrap-safe interval intersection. */
    if (address - base < cpu->fault.access_size || base - address < size)
        ocnext_a64_exclusive_clear(cpu);
}

/* ---- decode ---- */

int ocnext_a64_atomic_is_clrex(uint32_t op)
{
    return (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd503305f);
}

int ocnext_a64_atomic_decode(uint32_t op)
{
    return ocnext_a64_atomic_is_clrex(op) ||
           (op & UINT32_C(0x3f000000)) == UINT32_C(0x08000000) ||  /* exclusive/ordered/CAS */
           (op & UINT32_C(0x3f200c00)) == UINT32_C(0x38200000) ||  /* LSE RMW, SWP, LDAPR */
           (op & UINT32_C(0x3f200c00)) == UINT32_C(0x19000000);    /* LDAPUR/STLUR */
}

/* ---- guest access ---- */

static enum ocnext_a64_atomic_status fail(struct ocnext_a64_atomic_effect *e,
        enum ocnext_a64_fault_code code, enum ocnext_a64_access access,
        uint64_t address, unsigned size)
{
    e->fault_code = code;
    e->fault_access = access;
    e->fault_address = address;
    e->fault_size = size;
    e->count = 0;
    return OCNEXT_A64_ATOMIC_FAULT;
}

/* Natural alignment of the whole access is mandatory for every instruction in
 * this family. FEAT_LSE2 within-granule relaxation is NOT modeled: a
 * misaligned access is a deterministic ALIGNMENT stop, never a silent
 * unaligned success. */
static int check(const struct ocnext_a64_memory *m, uint64_t address, unsigned size,
                 enum ocnext_a64_access access, struct ocnext_a64_atomic_effect *e,
                 enum ocnext_a64_atomic_status *out)
{
    if (address & (size - 1u)) {
        *out = fail(e, OCNEXT_A64_FAULT_ALIGNMENT, access, address, size);
        return 1;
    }
    if (address > UINT64_MAX - (size - 1u)) {
        *out = fail(e, access == OCNEXT_A64_ACCESS_WRITE ? OCNEXT_A64_FAULT_WRITE : OCNEXT_A64_FAULT_READ,
                    access, address, size);
        return 1;
    }
    (void)m;
    return 0;
}

static int load(const struct ocnext_a64_memory *m, uint64_t address, uint8_t *buf,
                unsigned size, struct ocnext_a64_atomic_effect *e,
                enum ocnext_a64_atomic_status *out)
{
    if (!m->read || m->read(m->context, address, buf, size, OCNEXT_A64_ACCESS_READ) != 0) {
        *out = fail(e, OCNEXT_A64_FAULT_READ, OCNEXT_A64_ACCESS_READ, address, size);
        return 1;
    }
    return 0;
}

static int store(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *m, uint64_t address,
                 const uint8_t *buf, unsigned size, struct ocnext_a64_atomic_effect *e,
                 enum ocnext_a64_atomic_status *out)
{
    if (!m->write || m->write(m->context, address, buf, size) != 0) {
        *out = fail(e, OCNEXT_A64_FAULT_WRITE, OCNEXT_A64_ACCESS_WRITE, address, size);
        return 1;
    }
    ocnext_a64_exclusive_clear_overlap(cpu, address, size);
    return 0;
}

static void push(struct ocnext_a64_atomic_effect *e, unsigned reg, uint64_t value, unsigned bytes)
{
    e->reg[e->count] = (uint8_t)reg;
    e->value[e->count] = value & size_mask(bytes);
    e->width[e->count] = (uint8_t)(bytes >= 8 ? 64 : 32);
    ++e->count;
}

/* ---- exclusives, ordered accesses, CAS/CASP ---- */

static enum ocnext_a64_atomic_status exclusive_family(struct ocnext_a64_cpu *cpu,
        const struct ocnext_a64_memory *m, uint32_t op, uint64_t addr,
        struct ocnext_a64_atomic_effect *e)
{
    unsigned size = op >> 30, o2 = (op >> 23) & 1u, l = (op >> 22) & 1u, o1 = (op >> 21) & 1u;
    unsigned rs = (op >> 16) & 31u, o0 = (op >> 15) & 1u, rt2 = (op >> 10) & 31u;
    unsigned rn = (op >> 5) & 31u, rt = op & 31u;
    enum ocnext_a64_atomic_status st = OCNEXT_A64_ATOMIC_OK;
    uint8_t buf[16];

    if (!o2 && !o1) {                       /* LDXR/LDAXR/STXR/STLXR */
        unsigned n = 1u << size;
        if (rt2 != 31) return OCNEXT_A64_ATOMIC_UNSUPPORTED; /* SBO field */
        if (l) {
            if (rs != 31) return OCNEXT_A64_ATOMIC_UNSUPPORTED; /* SBO field */
            if (check(m, addr, n, OCNEXT_A64_ACCESS_READ, e, &st)) return st;
            if (load(m, addr, buf, n, e, &st)) return st;
            monitor_set(cpu, addr, n);
            push(e, rt, le_read(buf, n), n);
            return OCNEXT_A64_ATOMIC_OK;
        }
        if (rs == rt || (rs == rn && rn != 31)) return OCNEXT_A64_ATOMIC_UNSUPPORTED; /* CONSTRAINED UNPREDICTABLE */
        if (check(m, addr, n, OCNEXT_A64_ACCESS_WRITE, e, &st)) return st;
        {
            int pass = monitor_matches(cpu, addr, n);
            ocnext_a64_exclusive_clear(cpu); /* any STXR returns the monitor to Open */
            if (pass) {
                le_write(buf, gpr(cpu, rt), n);
                if (store(cpu, m, addr, buf, n, e, &st)) return st;
            }
            push(e, rs, pass ? 0u : 1u, 4);
        }
        return OCNEXT_A64_ATOMIC_OK;
    }
    if (!o2 && o1 && (size & 2u)) {         /* LDXP/LDAXP/STXP/STLXP */
        unsigned d = (size & 1u) ? 8u : 4u, n = 2u * d;
        if (l) {
            if (rs != 31 || rt == rt2) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
            if (check(m, addr, n, OCNEXT_A64_ACCESS_READ, e, &st)) return st;
            if (load(m, addr, buf, n, e, &st)) return st;
            monitor_set(cpu, addr, n);
            push(e, rt, le_read(buf, d), d);
            push(e, rt2, le_read(buf + d, d), d);
            return OCNEXT_A64_ATOMIC_OK;
        }
        if (rs == rt || rs == rt2 || (rs == rn && rn != 31)) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
        if (check(m, addr, n, OCNEXT_A64_ACCESS_WRITE, e, &st)) return st;
        {
            int pass = monitor_matches(cpu, addr, n);
            ocnext_a64_exclusive_clear(cpu);
            if (pass) {
                le_write(buf, gpr(cpu, rt), d);
                le_write(buf + d, gpr(cpu, rt2), d);
                if (store(cpu, m, addr, buf, n, e, &st)) return st;
            }
            push(e, rs, pass ? 0u : 1u, 4);
        }
        return OCNEXT_A64_ATOMIC_OK;
    }
    if (!o2 && o1) {                        /* CASP/CASPA/CASPL/CASPAL */
        unsigned d = (size & 1u) ? 8u : 4u, n = 2u * d;
        uint64_t old_lo, old_hi;
        int equal;
        if (rt2 != 31 || (rs & 1u) || (rt & 1u)) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
        if (check(m, addr, n, OCNEXT_A64_ACCESS_READ, e, &st)) return st;
        if (load(m, addr, buf, n, e, &st)) return st;
        old_lo = le_read(buf, d);
        old_hi = le_read(buf + d, d);
        equal = old_lo == (gpr(cpu, rs) & size_mask(d)) && old_hi == (gpr(cpu, rs + 1u) & size_mask(d));
        if (equal) {
            le_write(buf, gpr(cpu, rt), d);
            le_write(buf + d, gpr(cpu, rt + 1u), d);
        } /* else buf still holds the old value: written back to take the write permission check */
        if (store(cpu, m, addr, buf, n, e, &st)) return st;
        push(e, rs, old_lo, d);
        push(e, rs + 1u, old_hi, d);
        return OCNEXT_A64_ATOMIC_OK;
    }
    if (o2 && !o1) {                        /* LDAR/STLR; LDLAR/STLLR (FEAT_LOR) unsupported */
        unsigned n = 1u << size;
        if (!o0 || rs != 31 || rt2 != 31) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
        if (check(m, addr, n, l ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, e, &st)) return st;
        if (l) {
            if (load(m, addr, buf, n, e, &st)) return st;
            push(e, rt, le_read(buf, n), n);
        } else {
            le_write(buf, gpr(cpu, rt), n);
            if (store(cpu, m, addr, buf, n, e, &st)) return st;
        }
        return OCNEXT_A64_ATOMIC_OK;
    }
    {                                       /* CAS/CASA/CASL/CASAL */
        unsigned n = 1u << size;
        uint64_t old;
        if (rt2 != 31) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
        if (check(m, addr, n, OCNEXT_A64_ACCESS_READ, e, &st)) return st;
        if (load(m, addr, buf, n, e, &st)) return st;
        old = le_read(buf, n);
        if (old == (gpr(cpu, rs) & size_mask(n))) le_write(buf, gpr(cpu, rt), n);
        if (store(cpu, m, addr, buf, n, e, &st)) return st;
        push(e, rs, old, n);
        return OCNEXT_A64_ATOMIC_OK;
    }
}

/* ---- LSE read-modify-write, SWP, LDAPR ---- */

static enum ocnext_a64_atomic_status rmw_family(struct ocnext_a64_cpu *cpu,
        const struct ocnext_a64_memory *m, uint32_t op, uint64_t addr,
        struct ocnext_a64_atomic_effect *e)
{
    unsigned size = op >> 30, a = (op >> 23) & 1u, r = (op >> 22) & 1u;
    unsigned rs = (op >> 16) & 31u, o3 = (op >> 15) & 1u, opc = (op >> 12) & 7u, rt = op & 31u;
    unsigned n = 1u << size;
    enum ocnext_a64_atomic_status st = OCNEXT_A64_ATOMIC_OK;
    uint8_t buf[8];
    uint64_t old, operand, result, mask = size_mask(n);

    if (o3 && opc == 4) {                   /* LDAPR */
        if (!a || r || rs != 31) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
        if (check(m, addr, n, OCNEXT_A64_ACCESS_READ, e, &st)) return st;
        if (load(m, addr, buf, n, e, &st)) return st;
        push(e, rt, le_read(buf, n), n);
        return OCNEXT_A64_ATOMIC_OK;
    }
    if (o3 && opc != 0) return OCNEXT_A64_ATOMIC_UNSUPPORTED; /* LS64 and unallocated */
    if (check(m, addr, n, OCNEXT_A64_ACCESS_WRITE, e, &st)) return st;
    if (load(m, addr, buf, n, e, &st)) return st;
    old = le_read(buf, n);
    operand = gpr(cpu, rs) & mask;
    if (o3) {
        result = operand;                   /* SWP */
    } else {
        switch (opc) {
        case 0: result = old + operand; break;
        case 1: result = old & ~operand; break;
        case 2: result = old ^ operand; break;
        case 3: result = old | operand; break;
        case 4: result = sext(old, n) >= sext(operand, n) ? old : operand; break;
        case 5: result = sext(old, n) <= sext(operand, n) ? old : operand; break;
        case 6: result = old >= operand ? old : operand; break;
        default: result = old <= operand ? old : operand; break;
        }
    }
    le_write(buf, result & mask, n);
    if (store(cpu, m, addr, buf, n, e, &st)) return st;
    push(e, rt, old, n);
    return OCNEXT_A64_ATOMIC_OK;
}

/* ---- LDAPUR/STLUR (FEAT_LRCPC2) ---- */

static enum ocnext_a64_atomic_status unscaled_family(struct ocnext_a64_cpu *cpu,
        const struct ocnext_a64_memory *m, uint32_t op, uint64_t base,
        struct ocnext_a64_atomic_effect *e)
{
    unsigned size = op >> 30, opc = (op >> 22) & 3u, rt = op & 31u, n = 1u << size;
    uint32_t raw = (op >> 12) & 511u;
    uint64_t addr = base + (uint64_t)((int64_t)raw - ((raw & 256u) ? 512 : 0));
    enum ocnext_a64_atomic_status st = OCNEXT_A64_ATOMIC_OK;
    uint8_t buf[8];
    uint64_t v;
    /* opc 2: LDAPURSB/SH/SW into Xt; opc 3: LDAPURSB/SH into Wt. */
    if ((opc == 2 && size == 3) || (opc == 3 && size >= 2)) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
    if (check(m, addr, n, opc ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, e, &st)) return st;
    if (!opc) {
        le_write(buf, gpr(cpu, rt), n);
        if (store(cpu, m, addr, buf, n, e, &st)) return st;
        return OCNEXT_A64_ATOMIC_OK;
    }
    if (load(m, addr, buf, n, e, &st)) return st;
    v = le_read(buf, n);
    if (opc == 1) push(e, rt, v, n);
    else push(e, rt, (uint64_t)sext(v, n), opc == 2 ? 8u : 4u);
    return OCNEXT_A64_ATOMIC_OK;
}

enum ocnext_a64_atomic_status ocnext_a64_atomic_execute(
    struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
    uint32_t op, struct ocnext_a64_atomic_effect *e)
{
    unsigned rn = (op >> 5) & 31u;
    uint64_t base;
    unsigned i;
    if (!cpu || !memory || !e) return OCNEXT_A64_ATOMIC_UNSUPPORTED;
    e->count = 0;
    e->reserved = 0;
    e->fault_code = OCNEXT_A64_FAULT_NONE;
    e->fault_access = OCNEXT_A64_ACCESS_READ;
    e->fault_address = 0;
    e->fault_size = 0;
    for (i = 0; i < 2; ++i) { e->value[i] = 0; e->reg[i] = 31; e->width[i] = 64; }
    if (ocnext_a64_atomic_is_clrex(op)) {
        ocnext_a64_exclusive_clear(cpu);
        return OCNEXT_A64_ATOMIC_OK;
    }
    base = rn == 31 ? cpu->sp : cpu->x[rn];
    if ((op & UINT32_C(0x3f000000)) == UINT32_C(0x08000000)) return exclusive_family(cpu, memory, op, base, e);
    if ((op & UINT32_C(0x3f200c00)) == UINT32_C(0x38200000)) return rmw_family(cpu, memory, op, base, e);
    if ((op & UINT32_C(0x3f200c00)) == UINT32_C(0x19000000)) return unscaled_family(cpu, memory, op, base, e);
    return OCNEXT_A64_ATOMIC_UNSUPPORTED;
}
