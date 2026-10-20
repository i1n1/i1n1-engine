/* AArch64 system-register model; see ocnext/a64_sysreg.h and
 * docs/findings/sysreg-apple-profile.md. No allocation, no libc. */
#include "ocnext/a64_sysreg.h"

/* ------------------------------------------------------------------ SCTLR */

enum ocnext_a64_sctlr_result ocnext_a64_sctlr_apple_write(uint64_t value, unsigned pac_profile,
        uint64_t *stored, uint64_t *bad_mask, const char **reason)
{
    const uint64_t known = OCNEXT_A64_SCTLR_APPLE_EFFECTIVE | OCNEXT_A64_SCTLR_APPLE_PAC_BITS |
                           OCNEXT_A64_SCTLR_APPLE_STATE_ONLY | OCNEXT_A64_SCTLR_APPLE_UNMODELED |
                           OCNEXT_A64_SCTLR_APPLE_RES1 | OCNEXT_A64_SCTLR_APPLE_WRITE_IGNORED;
    uint64_t bad;
    if ((bad = OCNEXT_A64_SCTLR_APPLE_RES1 & ~value)) {
        if (bad_mask) *bad_mask = bad;
        if (reason) *reason = "SCTLR_EL1: RES1 bit (nTLSMD/LSMAOE) written 0";
        return OCNEXT_A64_SCTLR_RES1_CLEAR;
    }
    if ((bad = value & ~known)) {
        if (bad_mask) *bad_mask = bad;
        if (reason) *reason = "SCTLR_EL1: RES0 bit written 1 outside the observed write-ignored set";
        return OCNEXT_A64_SCTLR_RES0_SET;
    }
    if ((bad = value & OCNEXT_A64_SCTLR_APPLE_UNMODELED)) {
        if (bad_mask) *bad_mask = bad;
        if (reason) *reason = "SCTLR_EL1.A: alignment-fault checking is not modeled";
        return OCNEXT_A64_SCTLR_UNMODELED_SET;
    }
    if (!pac_profile && (bad = value & OCNEXT_A64_SCTLR_APPLE_PAC_BITS)) {
        if (bad_mask) *bad_mask = bad;
        if (reason) *reason = "SCTLR_EL1.EnIA/EnIB/EnDA/EnDB set without a configured PAC pointer profile";
        return OCNEXT_A64_SCTLR_PAC_NOT_CONFIGURED;
    }
    if (stored) *stored = value & ~OCNEXT_A64_SCTLR_APPLE_WRITE_IGNORED;
    return OCNEXT_A64_SCTLR_OK;
}

/* ---------------------------------------------------------------- profile */

/* SYNTHETIC identity: composed from architectural field definitions to match
 * the feature set the interpreter/software MMU can honestly back. Not read
 * from Apple silicon. Field-by-field derivation in
 * docs/findings/sysreg-apple-profile.md. */
const struct ocnext_a64_sysreg_profile ocnext_a64_sysreg_profile_apple_v1 = {
    .name = "i1n1-apple-synthetic-v1",
    .midr = UINT64_C(0x610f0230),  /* implementer 0x61 (Apple), arch 0xf, part 0x023: placeholder */
    .mpidr = UINT64_C(0x80000000), /* bit31 RES1, Aff0..2 = 0 (CPU 0) */
    .id_aa64pfr0 = UINT64_C(0x1201000001000011),
    .id_aa64pfr1 = UINT64_C(0x20),
    .id_aa64dfr0 = UINT64_C(0x101006),
    .id_aa64isar0 = UINT64_C(0x0021100110212120),
    .id_aa64isar1 = UINT64_C(0x1101211032),
    .id_aa64mmfr0 = OCNEXT_A64_MMFR0_S1_PA48_ASID16,
    .id_aa64mmfr1 = UINT64_C(0x300000),
    .id_aa64mmfr2 = UINT64_C(0x100000000),
    .clidr = UINT64_C(0x0a200023),
    .ccsidr = { { 0x000fe03b, 0x001fe02b }, { 0x03ffe05b, 0 } },
    .cntfrq = 24000000,
    .actlr_el1_modeled_mask = 0,
};

/* ------------------------------------------------------------------ names */

struct name_entry { uint16_t key; const char *name; };
#define N(o0, op1, crn, crm, op2, text) { OCNEXT_A64_SYSREG_KEY(o0, op1, crn, crm, op2), text }
static const struct name_entry names[] = {
    N(2,0,0,2,2,"MDSCR_EL1"), N(3,0,0,0,0,"MIDR_EL1"), N(3,0,0,0,5,"MPIDR_EL1"),
    N(3,0,1,0,1,"ACTLR_EL1"), N(3,0,13,0,1,"CONTEXTIDR_EL1"), N(3,0,14,1,0,"CNTKCTL_EL1"),
    N(3,1,0,0,0,"CCSIDR_EL1"), N(3,1,0,0,1,"CLIDR_EL1"), N(3,2,0,0,0,"CSSELR_EL1"),
    N(3,0,0,4,0,"ID_AA64PFR0_EL1"), N(3,0,0,4,1,"ID_AA64PFR1_EL1"),
    N(3,0,0,5,0,"ID_AA64DFR0_EL1"), N(3,0,0,5,1,"ID_AA64DFR1_EL1"),
    N(3,0,0,5,4,"ID_AA64AFR0_EL1"), N(3,0,0,5,5,"ID_AA64AFR1_EL1"),
    N(3,0,0,6,0,"ID_AA64ISAR0_EL1"), N(3,0,0,6,1,"ID_AA64ISAR1_EL1"), N(3,0,0,6,2,"ID_AA64ISAR2_EL1"),
    N(3,0,0,7,0,"ID_AA64MMFR0_EL1"), N(3,0,0,7,1,"ID_AA64MMFR1_EL1"), N(3,0,0,7,2,"ID_AA64MMFR2_EL1"),
    N(3,0,12,1,0,"ISR_EL1"),
    N(3,3,14,0,0,"CNTFRQ_EL0"), N(3,3,14,0,1,"CNTPCT_EL0"), N(3,3,14,0,2,"CNTVCT_EL0"),
    N(3,3,14,2,0,"CNTP_TVAL_EL0"), N(3,3,14,2,1,"CNTP_CTL_EL0"), N(3,3,14,2,2,"CNTP_CVAL_EL0"),
    N(3,3,14,3,0,"CNTV_TVAL_EL0"), N(3,3,14,3,1,"CNTV_CTL_EL0"), N(3,3,14,3,2,"CNTV_CVAL_EL0"),
    N(3,0,4,6,0,"ICC_PMR_EL1"), N(3,0,12,8,0,"ICC_IAR0_EL1"), N(3,0,12,8,1,"ICC_EOIR0_EL1"),
    N(3,0,12,8,2,"ICC_HPPIR0_EL1"), N(3,0,12,8,3,"ICC_BPR0_EL1"),
    N(3,0,12,8,4,"ICC_AP0R0_EL1"), N(3,0,12,8,5,"ICC_AP0R1_EL1"),
    N(3,0,12,8,6,"ICC_AP0R2_EL1"), N(3,0,12,8,7,"ICC_AP0R3_EL1"),
    N(3,0,12,9,0,"ICC_AP1R0_EL1"), N(3,0,12,9,1,"ICC_AP1R1_EL1"),
    N(3,0,12,9,2,"ICC_AP1R2_EL1"), N(3,0,12,9,3,"ICC_AP1R3_EL1"),
    N(3,0,12,11,1,"ICC_DIR_EL1"), N(3,0,12,11,3,"ICC_RPR_EL1"), N(3,0,12,11,5,"ICC_SGI1R_EL1"),
    N(3,0,12,11,6,"ICC_ASGI1R_EL1"), N(3,0,12,11,7,"ICC_SGI0R_EL1"),
    N(3,0,12,12,0,"ICC_IAR1_EL1"), N(3,0,12,12,1,"ICC_EOIR1_EL1"), N(3,0,12,12,2,"ICC_HPPIR1_EL1"),
    N(3,0,12,12,3,"ICC_BPR1_EL1"), N(3,0,12,12,4,"ICC_CTLR_EL1"), N(3,0,12,12,5,"ICC_SRE_EL1"),
    N(3,0,12,12,6,"ICC_IGRPEN0_EL1"), N(3,0,12,12,7,"ICC_IGRPEN1_EL1"),
    N(3,4,15,5,0,"s3_4_c15_c5_0 (Apple IMPDEF)"), N(3,4,15,1,4,"s3_4_c15_c1_4 (Apple IMPDEF)"),
};
#undef N

const char *ocnext_a64_sysreg_name(uint16_t key)
{
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (names[i].key == key) return names[i].name;
    return 0;
}

static size_t put(char *b, size_t n, size_t at, const char *s)
{
    while (*s) { if (at + 1 < n) b[at] = *s; ++at; ++s; }
    return at;
}

static size_t put_num(char *b, size_t n, size_t at, unsigned v)
{
    char t[3] = {0, 0, 0};
    if (v >= 10) { t[0] = '1'; t[1] = (char)('0' + v - 10); } else t[0] = (char)('0' + v);
    return put(b, n, at, t);
}

size_t ocnext_a64_sysreg_stop_describe(const struct ocnext_a64_sysreg_model *m, char *buffer, size_t size)
{
    size_t at = 0;
    const char *name;
    if (!m || !buffer || !size) return 0;
    if (!m->stop_valid) { buffer[0] = 0; return 0; }
    name = ocnext_a64_sysreg_name(m->stop_key);
    if (name) at = put(buffer, size, at, name);
    else {
        unsigned k = m->stop_key;
        at = put(buffer, size, at, k >> 14 & 1u ? "s3_" : "s2_");
        at = put_num(buffer, size, at, (k >> 11) & 7u);
        at = put(buffer, size, at, "_c");
        at = put_num(buffer, size, at, (k >> 7) & 15u);
        at = put(buffer, size, at, "_c");
        at = put_num(buffer, size, at, (k >> 3) & 15u);
        at = put(buffer, size, at, "_");
        at = put_num(buffer, size, at, k & 7u);
    }
    at = put(buffer, size, at, ": ");
    at = put(buffer, size, at, m->stop_reason ? m->stop_reason : "unsupported");
    buffer[at < size ? at : size - 1] = 0;
    return at;
}

/* ------------------------------------------------------------------ model */

static int profile_valid(const struct ocnext_a64_sysreg_profile *p)
{
    unsigned level;
    if (!p->name || !(p->mpidr & UINT64_C(0x80000000)) || (p->mpidr >> 40) ||
        (p->midr >> 32) || p->clidr >> 32) return 0;
    for (level = 0; level < OCNEXT_SYSREG_CACHE_LEVELS; ++level) {
        unsigned ctype = (unsigned)((p->clidr >> (3u * level)) & 7u);
        unsigned has_i = ctype == 1 || ctype == 3, has_d = ctype == 2 || ctype == 3 || ctype == 4;
        if (ctype > 4) return 0;
        /* Every present cache has a table entry, absent ones none. */
        if ((has_i != (p->ccsidr[level][1] != 0)) || (has_d != (p->ccsidr[level][0] != 0))) return 0;
    }
    return 1;
}

int ocnext_a64_sysreg_model_init(struct ocnext_a64_sysreg_model *m,
        const struct ocnext_a64_sysreg_profile *profile,
        const struct ocnext_a64_sysreg_ops *ops, void *ctx)
{
    unsigned i;
    uint8_t *raw;
    if (!m || !profile || !profile_valid(profile)) return -1;
    raw = (uint8_t *)m;
    for (i = 0; i < sizeof(*m); ++i) raw[i] = 0;
    m->profile = *profile;
    m->ops = ops;
    m->ctx = ctx;
    return 0;
}

static enum ocnext_a64_sysreg_result stop(struct ocnext_a64_sysreg_model *m, uint16_t key, const char *reason)
{
    m->stop_key = key; m->stop_valid = 1; m->stop_reason = reason;
    return OCNEXT_A64_SYSREG_UNSUPPORTED;
}

static int counters(struct ocnext_a64_sysreg_model *m, uint64_t *physical, uint64_t *virt)
{
    uint64_t p;
    if (!m->ops || !m->ops->counter || m->ops->counter(m->ctx, &p)) return -1;
    *physical = p;
    *virt = p - m->cntvoff; /* CNTVCT = CNTPCT - CNTVOFF (CNTVOFF = 0: no EL2) */
    return 0;
}

static int timer_condition(const struct ocnext_a64_sysreg_timer *t, uint64_t count)
{
    return (t->ctl & 1u) && t->cval <= count; /* ISTATUS: ENABLE && CVAL <= count (unsigned) */
}

int ocnext_a64_sysreg_poll(struct ocnext_a64_sysreg_model *m)
{
    uint64_t p, v;
    unsigned which;
    if (!m) return -1;
    if (counters(m, &p, &v)) return -1;
    for (which = 0; which < 2; ++which) {
        struct ocnext_a64_sysreg_timer *t = &m->timer[which];
        int level = timer_condition(t, which ? v : p) && !(t->ctl & 2u);
        if (level != t->level) {
            t->level = level;
            if (m->ops && m->ops->timer_irq) m->ops->timer_irq(m->ctx, which, level);
        }
    }
    return 0;
}

int ocnext_a64_sysreg_feature_bank(const struct ocnext_a64_sysreg_model *m,
        struct ocnext_a64_feature_registers *bank)
{
    if (!m || !bank || m->profile.id_aa64mmfr0 != OCNEXT_A64_MMFR0_S1_PA48_ASID16) return -1;
    bank->id_aa64mmfr0_el1 = m->profile.id_aa64mmfr0;
    bank->known_mask = OCNEXT_A64_FEATURE_KNOWN_MMFR0;
    bank->reserved = 0;
    return 0;
}

#define EL1_ONLY() do { if (r->current_el == 0) return OCNEXT_A64_SYSREG_UNDEFINED; } while (0)
#define READ_ONLY() do { if (!r->is_read) return OCNEXT_A64_SYSREG_UNDEFINED; } while (0)
#define SERVE(v) do { *out = (v); return OCNEXT_A64_SYSREG_OK; } while (0)

/* ID_AA64* and similar: read-only, EL1 only (no FEAT_IDST: EL0 is UNDEFINED). */
static enum ocnext_a64_sysreg_result id_read(const struct ocnext_a64_sysreg_request *r, uint64_t v, uint64_t *out)
{
    EL1_ONLY();
    READ_ONLY();
    SERVE(v);
}

static enum ocnext_a64_sysreg_result timer_reg(struct ocnext_a64_sysreg_model *m,
        const struct ocnext_a64_sysreg_request *r, unsigned which, unsigned field, uint64_t *out)
{
    struct ocnext_a64_sysreg_timer *t = &m->timer[which];
    uint64_t p, v, count;
    /* EL0 access: CNTKCTL_EL1.EL0PTEN (bit9) physical / EL0VTEN (bit8) virtual. */
    if (r->current_el == 0 && !((m->cntkctl_el1 >> (which ? 8 : 9)) & 1u)) return OCNEXT_A64_SYSREG_TRAP;
    if (counters(m, &p, &v)) return stop(m, r->key, "no counter source bound (timer registers need a clock)");
    count = which ? v : p;
    if (r->is_read) {
        if (field == 0) SERVE((uint64_t)((uint32_t)(t->cval - count)));        /* TVAL: (CVAL - count)[31:0], bits 63:32 RES0 */
        if (field == 1) SERVE((uint64_t)(t->ctl & 3u) | (timer_condition(t, count) ? 4u : 0u)); /* ENABLE|IMASK|ISTATUS */
        SERVE(t->cval);
    }
    if (field == 1) {
        if (r->value & ~UINT64_C(7)) return stop(m, r->key, "timer CTL bits above ISTATUS are RES0");
        t->ctl = (uint32_t)(r->value & 3u); /* ISTATUS is read-only: write ignored */
    } else if (field == 0) {
        /* TVAL write: CVAL = count + SignExtend(value[31:0]); X[t] bits 63:32 not used. */
        t->cval = count + (uint64_t)(int64_t)(int32_t)(uint32_t)r->value;
    } else {
        t->cval = r->value;
    }
    ocnext_a64_sysreg_poll(m);
    return OCNEXT_A64_SYSREG_OK;
}

static enum ocnext_a64_sysreg_result cache_id(struct ocnext_a64_sysreg_model *m,
        const struct ocnext_a64_sysreg_request *r, uint64_t *out)
{
    unsigned level = (m->csselr_el1 >> 1) & 7u, ind = m->csselr_el1 & 1u;
    unsigned ctype;
    EL1_ONLY();
    READ_ONLY();
    ctype = level < OCNEXT_SYSREG_CACHE_LEVELS ? (unsigned)((m->profile.clidr >> (3u * level)) & 7u) : 0;
    if (!(ind ? (ctype == 1 || ctype == 3) : (ctype == 2 || ctype == 3 || ctype == 4)))
        return stop(m, r->key, "CCSIDR_EL1 of a cache that CSSELR_EL1 selects but CLIDR_EL1 lacks is architecturally UNKNOWN; not invented");
    SERVE(m->profile.ccsidr[level][ind]);
}

static enum ocnext_a64_sysreg_result icc(struct ocnext_a64_sysreg_model *m,
        const struct ocnext_a64_sysreg_request *r, uint64_t *out)
{
    const struct ocnext_a64_sysreg_ops *o = m->ops;
    uint16_t key = r->key;
    EL1_ONLY();
    switch (key) {
    case OCNEXT_A64_SYSREG_KEY(3,0,4,6,0): { /* ICC_PMR_EL1 */
        uint8_t pmr;
        if (!o || !o->icc_get_pmr || !o->icc_set_pmr) return stop(m, key, "no GICv3 CPU interface bound");
        if (r->is_read) { if (o->icc_get_pmr(m->ctx, &pmr)) return stop(m, key, "CPU interface PMR read failed"); SERVE(pmr); }
        if (r->value >> 8) return stop(m, key, "ICC_PMR_EL1 bits 63:8 are RES0");
        if (o->icc_set_pmr(m->ctx, (uint8_t)r->value)) return stop(m, key, "CPU interface PMR write failed");
        return OCNEXT_A64_SYSREG_OK;
    }
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,7): { /* ICC_IGRPEN1_EL1 */
        int en;
        if (!o || !o->icc_get_igrpen1 || !o->icc_set_igrpen1) return stop(m, key, "no GICv3 CPU interface bound");
        if (r->is_read) { if (o->icc_get_igrpen1(m->ctx, &en)) return stop(m, key, "CPU interface IGRPEN1 read failed"); SERVE((uint64_t)(en != 0)); }
        if (r->value >> 1) return stop(m, key, "ICC_IGRPEN1_EL1 bits 63:1 are RES0");
        if (o->icc_set_igrpen1(m->ctx, (int)r->value)) return stop(m, key, "CPU interface IGRPEN1 write failed");
        return OCNEXT_A64_SYSREG_OK;
    }
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,6): /* ICC_IGRPEN0_EL1 */
        /* gicv3_lite is Group-1 only: Group 0 is permanently disabled, so the
         * truthful state is 0 and enabling it is unmodeled. */
        if (r->is_read) SERVE(0);
        if (r->value >> 1) return stop(m, key, "ICC_IGRPEN0_EL1 bits 63:1 are RES0");
        if (r->value) return stop(m, key, "Group 0 interrupts are not modeled by gicv3_lite");
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,5): /* ICC_SRE_EL1 */
        /* Only the system-register interface exists: SRE, DFB, DIB are RAO/WI
         * (IHI0069, ICC_SRE_EL1: implementations without legacy/bypass). */
        if (r->is_read) SERVE(7);
        if (r->value >> 3) return stop(m, key, "ICC_SRE_EL1 bits 63:3 are RES0");
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,4): /* ICC_CTLR_EL1 */
        /* RO: PRIbits=7 (8 bits) [10:8], IDbits=0 (16 bit) [13:11], SEIS=A3V=RSS=ExtRange=0.
         * RW: CBPR[0] (stored, no preemption grouping to affect), EOImode[1] and
         * PMHE[6] must stay 0. */
        if (r->is_read) SERVE((uint64_t)(m->icc_ctlr_cbpr & 1u) | UINT64_C(0x700));
        if (r->value & ~UINT64_C(0xcff43)) return stop(m, key, "ICC_CTLR_EL1 RES0 bits written 1");
        if (r->value & 2u) return stop(m, key, "ICC_CTLR_EL1.EOImode=1 (split priority drop/deactivate) is not modeled");
        if (r->value & 0x40u) return stop(m, key, "ICC_CTLR_EL1.PMHE=1 is not modeled");
        m->icc_ctlr_cbpr = (uint32_t)(r->value & 1u);
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,0): { /* ICC_IAR1_EL1 */
        uint32_t intid;
        READ_ONLY();
        if (!o || !o->icc_ack) return stop(m, key, "no GICv3 CPU interface bound");
        if (ocnext_a64_sysreg_poll(m)) return stop(m, key, "no counter source bound (timer outputs cannot be refreshed before acknowledge)");
        if (o->icc_ack(m->ctx, &intid)) return stop(m, key, "CPU interface acknowledge failed");
        SERVE(intid);
    }
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,1): /* ICC_EOIR1_EL1 */
        if (r->is_read) return OCNEXT_A64_SYSREG_UNDEFINED;
        if (!o || !o->icc_eoi) return stop(m, key, "no GICv3 CPU interface bound");
        if (r->value >> 24) return stop(m, key, "ICC_EOIR1_EL1 bits 63:24 are RES0");
        if (o->icc_eoi(m->ctx, (uint32_t)r->value)) return stop(m, key, "EOI of an interrupt that is not active");
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,12,8,0): case OCNEXT_A64_SYSREG_KEY(3,0,12,8,1):
    case OCNEXT_A64_SYSREG_KEY(3,0,12,8,2):
        return stop(m, key, "Group 0 CPU interface registers are not modeled by gicv3_lite");
    case OCNEXT_A64_SYSREG_KEY(3,0,12,8,3): case OCNEXT_A64_SYSREG_KEY(3,0,12,12,3):
        return stop(m, key, "binary point / priority grouping is not modeled by gicv3_lite (it compares full 8-bit priority)");
    case OCNEXT_A64_SYSREG_KEY(3,0,12,12,2):
        return stop(m, key, "ICC_HPPIR1_EL1: gicv3_lite exposes no highest-pending query without acknowledging");
    case OCNEXT_A64_SYSREG_KEY(3,0,12,11,3):
        return stop(m, key, "ICC_RPR_EL1: gicv3_lite does not export running priority");
    case OCNEXT_A64_SYSREG_KEY(3,0,12,11,1):
        return stop(m, key, "ICC_DIR_EL1 requires EOImode=1, which is not modeled");
    default:
        return stop(m, key, "ICC register (SGI generation / active-priority registers) not modeled by gicv3_lite");
    }
}

enum ocnext_a64_sysreg_result ocnext_a64_sysreg_provide(void *model,
        const struct ocnext_a64_sysreg_request *r, uint64_t *out)
{
    struct ocnext_a64_sysreg_model *m = (struct ocnext_a64_sysreg_model *)model;
    const struct ocnext_a64_sysreg_profile *p;
    uint64_t pc, vc;
    if (!m || !r || !out) return OCNEXT_A64_SYSREG_UNSUPPORTED;
    p = &m->profile;
    switch (r->key) {
    case OCNEXT_A64_SYSREG_KEY(3,0,0,0,0): return id_read(r, p->midr, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,0,5): return id_read(r, p->mpidr, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,4,0): return id_read(r, p->id_aa64pfr0, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,4,1): return id_read(r, p->id_aa64pfr1, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,5,0): return id_read(r, p->id_aa64dfr0, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,5,1): return id_read(r, p->id_aa64dfr1, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,5,4): return id_read(r, p->id_aa64afr0, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,5,5): return id_read(r, p->id_aa64afr1, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,6,0): return id_read(r, p->id_aa64isar0, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,6,1): return id_read(r, p->id_aa64isar1, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,6,2): return id_read(r, p->id_aa64isar2, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,7,1): return id_read(r, p->id_aa64mmfr1, out);
    case OCNEXT_A64_SYSREG_KEY(3,0,0,7,2): return id_read(r, p->id_aa64mmfr2, out);
    case OCNEXT_A64_SYSREG_KEY(3,1,0,0,1): return id_read(r, p->clidr, out);
    case OCNEXT_A64_SYSREG_KEY(3,1,0,0,0): return cache_id(m, r, out);
    case OCNEXT_A64_SYSREG_KEY(3,2,0,0,0): /* CSSELR_EL1: InD[0], Level[3:1]; TnD needs MTE */
        EL1_ONLY();
        if (r->is_read) SERVE(m->csselr_el1);
        if (r->value >> 4) return stop(m, r->key, "CSSELR_EL1 bits 63:4 are RES0 (TnD needs MTE)");
        m->csselr_el1 = (uint32_t)r->value;
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(2,0,0,2,2): /* MDSCR_EL1 */
        EL1_ONLY();
        if (r->is_read) SERVE(m->mdscr_el1);
        /* Only TDCC(12) is modeled (XNU sets it). SS/KDE/MDE/... enable debug
         * exceptions or DCC paths that do not exist here. */
        if (r->value & ~UINT64_C(0x1000)) return stop(m, r->key, "MDSCR_EL1: only TDCC (bit12) is modeled; other bits need debug exceptions");
        m->mdscr_el1 = r->value;
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,1,0,1): /* ACTLR_EL1 */
        EL1_ONLY();
        if (r->is_read) SERVE(m->actlr_el1);
        if (r->value & ~p->actlr_el1_modeled_mask)
            return stop(m, r->key, "ACTLR_EL1 is Apple IMPDEF: bit semantics unknown, only profile-declared bits are accepted");
        m->actlr_el1 = r->value;
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,13,0,1): /* CONTEXTIDR_EL1: 32-bit, no trace/VHE effect */
        EL1_ONLY();
        if (r->is_read) SERVE(m->contextidr_el1);
        if (r->value >> 32) return stop(m, r->key, "CONTEXTIDR_EL1 bits 63:32 are RES0");
        m->contextidr_el1 = r->value;
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,14,1,0): /* CNTKCTL_EL1 */
        EL1_ONLY();
        if (r->is_read) SERVE(m->cntkctl_el1);
        if (r->value & ~UINT64_C(0x3ff)) return stop(m, r->key, "CNTKCTL_EL1 bits above 9 (FEAT_ECV) are not modeled");
        if (r->value & 4u) return stop(m, r->key, "CNTKCTL_EL1.EVNTEN: the event stream is not modeled");
        m->cntkctl_el1 = r->value;
        ocnext_a64_sysreg_poll(m);
        return OCNEXT_A64_SYSREG_OK;
    case OCNEXT_A64_SYSREG_KEY(3,0,12,1,0): /* ISR_EL1 */
        {
            uint64_t isr;
            EL1_ONLY();
            READ_ONLY();
            if (!m->ops || !m->ops->isr) return stop(m, r->key, "no interrupt source bound; ISR_EL1 is not read as 0");
            if (ocnext_a64_sysreg_poll(m) == 0 && m->ops->isr(m->ctx, &isr) == 0) SERVE(isr & UINT64_C(0x1c0));
            return stop(m, r->key, "interrupt source failed (or counter source missing for timer refresh)");
        }
    case OCNEXT_A64_SYSREG_KEY(3,3,14,0,0): /* CNTFRQ_EL0 */
        if (r->current_el == 0 && !(m->cntkctl_el1 & 3u)) return OCNEXT_A64_SYSREG_TRAP;
        if (!r->is_read) return stop(m, r->key, "CNTFRQ_EL0 writes are not modeled (profile constant)");
        SERVE(p->cntfrq);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,0,1): case OCNEXT_A64_SYSREG_KEY(3,3,14,0,2): {
        int virt = r->key == OCNEXT_A64_SYSREG_KEY(3,3,14,0,2);
        if (r->current_el == 0 && !((m->cntkctl_el1 >> (virt ? 1 : 0)) & 1u)) return OCNEXT_A64_SYSREG_TRAP;
        READ_ONLY();
        if (counters(m, &pc, &vc)) return stop(m, r->key, "no counter source bound (counter is not read as 0)");
        SERVE(virt ? vc : pc);
    }
    case OCNEXT_A64_SYSREG_KEY(3,3,14,2,0): return timer_reg(m, r, 0, 0, out);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,2,1): return timer_reg(m, r, 0, 1, out);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,2,2): return timer_reg(m, r, 0, 2, out);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,3,0): return timer_reg(m, r, 1, 0, out);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,3,1): return timer_reg(m, r, 1, 1, out);
    case OCNEXT_A64_SYSREG_KEY(3,3,14,3,2): return timer_reg(m, r, 1, 2, out);
    case OCNEXT_A64_SYSREG_KEY(3,4,15,5,0):
        return stop(m, r->key, "Apple IMPDEF register: semantics unknown (op1=4 encodes an EL2-level access; likely hypervisor-emulated on hardware); see docs/findings/sysreg-apple-profile.md");
    case OCNEXT_A64_SYSREG_KEY(3,4,15,1,4):
        return stop(m, r->key, "Apple IMPDEF register: semantics unknown (op1=4 encodes an EL2-level access; likely hypervisor-emulated on hardware); see docs/findings/sysreg-apple-profile.md");
    default:
        break;
    }
    /* ICC_*: op1=0, CRn=12, CRm 8..12 (ISR_EL1 is CRm=1, handled above); PMR is CRn=4. */
    if (r->key == OCNEXT_A64_SYSREG_KEY(3,0,4,6,0) ||
        (((r->key >> 14) & 1u) && ((r->key >> 11) & 7u) == 0 && ((r->key >> 7) & 15u) == 12 &&
         ((r->key >> 3) & 15u) >= 8)) return icc(m, r, out);
    return stop(m, r->key, "system register is not modeled");
}
