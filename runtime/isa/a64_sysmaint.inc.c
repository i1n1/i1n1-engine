/* Hints, PSTATE extension bits and cache/TLB/address-translation maintenance
 * for the A64 interpreter. Textually included by a64.c (after undefined_access)
 * so that the rest of the dispatch chain stays untouched; it relies on the
 * static helpers of that translation unit. Every path either performs the
 * architectural state change, delegates to the explicit maintenance provider,
 * or stops deterministically with a reason in cpu->fault.reserved. Nothing is
 * accepted as a NOP unless the architecture defines that instruction as having
 * no effect in this single-PE model (YIELD, BTI without enforcement).
 *
 * Encodings were derived from the Arm A64 instruction/system-register
 * encoding tables (op0/op1/CRn/CRm/op2) and are cross-checked by
 * tests/a64_sysmaint_test.c against independently assembled words. */

#define SM_CONTINUE ((enum ocnext_a64_result)-1)

static enum ocnext_a64_result sm_stop(struct ocnext_a64_cpu *cpu, uint32_t op, unsigned reason)
{
    enum ocnext_a64_result result = fault(cpu, OCNEXT_A64_FAULT_UNSUPPORTED,
                                          OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    cpu->fault.reserved = (uint8_t)reason;
    return result;
}

/* Returns 0 and the bit when SCTLR_EL1 is known; -1 when UNKNOWN. */
static int sm_sctlr_bit(const struct ocnext_a64_cpu *cpu, unsigned bit, unsigned *value)
{
    if (!(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)) return -1;
    *value = (unsigned)((cpu->system.mmu.sctlr_el1 >> bit) & 1u);
    return 0;
}

static int sm_is_hint(uint32_t op)
{
    unsigned imm = (op >> 5) & 127u;
    if ((op & UINT32_C(0xfffff01f)) != UINT32_C(0xd503201f)) return 0;
    return (imm >= 1 && imm <= 5) || imm == 32 || imm == 34 || imm == 36 || imm == 38;
}

static int sm_is_pstate_imm(uint32_t op)
{
    uint32_t id = op & UINT32_C(0xfffff0ff);
    return id == UINT32_C(0xd500409f) || id == UINT32_C(0xd500407f) ||
           id == UINT32_C(0xd503405f) || id == UINT32_C(0xd503403f);
}

static int sm_is_pstate_reg(uint32_t op)
{
    uint32_t id = op & UINT32_C(0xffdfffe0);
    return id == UINT32_C(0xd5184260) || id == UINT32_C(0xd5184280) ||
           id == UINT32_C(0xd51b42a0) || id == UINT32_C(0xd51b42c0) ||
           id == UINT32_C(0xd5187400) || id == UINT32_C(0xd51b00e0);
}

enum sm_kind_class { SM_NONE = 0, SM_ZVA, SM_PROVIDER };

/* Decode SYS-class maintenance. Fills kind/scope for provider operations. */
static int sm_decode_sys(uint32_t op, enum sm_kind_class *cls, unsigned *kind,
                         unsigned *scope, int *el0_uci, int *el1_only_va)
{
    uint32_t id = op & UINT32_C(0xffffffe0);
    *cls = SM_PROVIDER; *scope = OCNEXT_A64_MAINTENANCE_LOCAL; *el0_uci = 0; *el1_only_va = 0;
    switch (id) {
    case UINT32_C(0xd5087500): *kind = OCNEXT_A64_MAINTENANCE_IC_IALLU; return 1;
    case UINT32_C(0xd5087100): *kind = OCNEXT_A64_MAINTENANCE_IC_IALLUIS;
                               *scope = OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE; return 1;
    case UINT32_C(0xd50b7520): *kind = OCNEXT_A64_MAINTENANCE_IC_IVAU; *el0_uci = 1; return 1;
    case UINT32_C(0xd50b7420): *cls = SM_ZVA; *kind = 0; return 1;
    case UINT32_C(0xd5087620): *kind = OCNEXT_A64_MAINTENANCE_DC_IVAC; *el1_only_va = 1; return 1;
    case UINT32_C(0xd50b7a20): *kind = OCNEXT_A64_MAINTENANCE_DC_CVAC; *el0_uci = 1; return 1;
    case UINT32_C(0xd50b7b20): *kind = OCNEXT_A64_MAINTENANCE_DC_CVAU; *el0_uci = 1; return 1;
    case UINT32_C(0xd50b7e20): *kind = OCNEXT_A64_MAINTENANCE_DC_CIVAC; *el0_uci = 1; return 1;
    case UINT32_C(0xd5087640): *kind = OCNEXT_A64_MAINTENANCE_DC_ISW; return 1;
    case UINT32_C(0xd5087a40): *kind = OCNEXT_A64_MAINTENANCE_DC_CSW; return 1;
    case UINT32_C(0xd5087e40): *kind = OCNEXT_A64_MAINTENANCE_DC_CISW; return 1;
    case UINT32_C(0xd5087800): *kind = OCNEXT_A64_MAINTENANCE_AT_S1E1R; return 1;
    case UINT32_C(0xd5087820): *kind = OCNEXT_A64_MAINTENANCE_AT_S1E1W; return 1;
    case UINT32_C(0xd5087840): *kind = OCNEXT_A64_MAINTENANCE_AT_S1E0R; return 1;
    case UINT32_C(0xd5087860): *kind = OCNEXT_A64_MAINTENANCE_AT_S1E0W; return 1;
    default: break;
    }
    /* TLBI <op>, op1=0, CRn=8, CRm=3 (inner shareable) or 7 (local). */
    if ((op & UINT32_C(0xfffff000)) == UINT32_C(0xd5088000)) {
        unsigned crm = (op >> 8) & 15u, op2 = (op >> 5) & 7u;
        if (crm == 1 || crm == 2 || crm == 5 || crm == 6) { /* OS and range forms */
            static const unsigned char plain_ops[8] = {1, 1, 1, 1, 0, 1, 0, 1}; /* VMALLE1 VAE1 ASIDE1 VAAE1 - VALE1 - VAALE1 */
            static const unsigned char range_ops[8] = {0, 1, 0, 1, 0, 1, 0, 1};  /* RVAE1 RVAAE1 RVALE1 RVAALE1 */
            if (!((crm == 1 ? plain_ops : range_ops)[op2])) return 0;
            *kind = OCNEXT_A64_MAINTENANCE_TLBI_OTHER;
            *scope = crm == 6 ? OCNEXT_A64_MAINTENANCE_LOCAL : OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE;
            return 1;
        }
        if (crm != 3 && crm != 7) return 0;
        *scope = crm == 3 ? OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE : OCNEXT_A64_MAINTENANCE_LOCAL;
        switch (op2) {
        case 0: *kind = OCNEXT_A64_MAINTENANCE_VMALLE1; return 1;
        case 1: *kind = OCNEXT_A64_MAINTENANCE_TLBI_VAE1; return 1;
        case 2: *kind = OCNEXT_A64_MAINTENANCE_TLBI_ASIDE1; return 1;
        case 3: *kind = OCNEXT_A64_MAINTENANCE_TLBI_VAAE1; return 1;
        case 5: *kind = OCNEXT_A64_MAINTENANCE_TLBI_VALE1; return 1;
        case 7: *kind = OCNEXT_A64_MAINTENANCE_TLBI_VAALE1; return 1;
        default: return 0;
        }
    }
    return 0;
}

static int sm_match(uint32_t op)
{
    enum sm_kind_class cls; unsigned kind, scope; int a, b;
    return sm_is_hint(op) || sm_is_pstate_imm(op) || sm_is_pstate_reg(op) ||
           sm_decode_sys(op, &cls, &kind, &scope, &a, &b);
}

static unsigned sm_pstate_ext_flag(uint64_t mask)
{
    return mask == PSTATE_PAN ? OCNEXT_A64_EXT_PAN : mask == PSTATE_UAO ? OCNEXT_A64_EXT_UAO :
           mask == PSTATE_DIT ? OCNEXT_A64_EXT_DIT : OCNEXT_A64_EXT_SSBS;
}

static enum ocnext_a64_result sm_hint(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory, uint32_t op)
{
    unsigned imm = (op >> 5) & 127u, bit;
    if (!valid_maint(cpu) || (sync_profile(cpu) && !valid_system(cpu)))
        return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    if (imm == 1) return SM_CONTINUE; /* YIELD: a scheduling hint with no architectural effect on one PE. */
    if (imm == 4 || imm == 5) { /* SEV / SEVL set this PE's event register. */
        ext_set(cpu, OCNEXT_A64_EXT_EVENT, 1);
        return SM_CONTINUE;
    }
    if (imm == 2 || imm == 3) { /* WFE / WFI */
        int is_wfe = imm == 2;
        if (sync_profile(cpu) && cpu->system.current_el == 0) {
            /* EL0 execution traps to EL1 (EC 0x01, CV=1, COND=AL, TI) when
             * SCTLR_EL1.nTWE (bit18) / nTWI (bit16) is clear. */
            if (sm_sctlr_bit(cpu, is_wfe ? 18 : 16, &bit)) return sm_stop(cpu, op, OCNEXT_A64_REASON_SCTLR_UNKNOWN);
            if (!bit) return take_sync(cpu, memory, op, 0x01,
                                       (1u << 24) | (0xEu << 20) | (is_wfe ? 1u : 0u), cpu->pc, 0);
        }
        if (is_wfe) {
            if (!(cpu->ext_state & OCNEXT_A64_EXT_EVENT)) return sm_stop(cpu, op, OCNEXT_A64_REASON_WFE_NO_EVENT);
            ext_set(cpu, OCNEXT_A64_EXT_EVENT, 0); /* WFE consumes a pending event and falls through. */
            return SM_CONTINUE;
        }
        return sm_stop(cpu, op, OCNEXT_A64_REASON_WFI_NO_WAKE);
    }
    /* BTI [c|j|jc]: the instruction itself has no effect; only guarded-page
     * target checks (SCTLR_EL1.BT0/BT1 with GP descriptors) are observable and
     * are not modeled. Those enable bits are rejected on MSR SCTLR, but refuse
     * defensively if a known bank ever carries them. */
    if ((sm_sctlr_bit(cpu, 35, &bit) == 0 && bit) || (sm_sctlr_bit(cpu, 36, &bit) == 0 && bit))
        return sm_stop(cpu, op, OCNEXT_A64_REASON_BTI_ENFORCED);
    return SM_CONTINUE;
}

static enum ocnext_a64_result sm_pstate(struct ocnext_a64_cpu *cpu,
                                        const struct ocnext_a64_memory *memory, uint32_t op,
                                        struct transaction *tx)
{
    int immediate = sm_is_pstate_imm(op);
    uint32_t id = immediate ? (op & UINT32_C(0xfffff0ff)) : (op & UINT32_C(0xffdfffe0));
    int read = !immediate && ((op >> 21) & 1u);
    uint64_t mask = 0, value;
    if (!sync_profile(cpu)) return sm_stop(cpu, op, OCNEXT_A64_REASON_NONE);
    if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    if (id == UINT32_C(0xd51b00e0)) { /* DCZID_EL0: read-only, readable at EL0. */
        if (!read) return undefined_access(cpu, memory, op);
        if (!cpu->ext_dczid_bs) return sm_stop(cpu, op, OCNEXT_A64_REASON_DCZID_UNKNOWN);
        stage_write(tx, op & 31u, cpu->ext_dczid_bs, 64, 0); /* DZP=0, BS=log2(words) */
        return SM_CONTINUE;
    }
    if (id == UINT32_C(0xd5187400)) { /* PAR_EL1 */
        if (cpu->system.current_el == 0) return undefined_access(cpu, memory, op);
        if (!read) return sm_stop(cpu, op, OCNEXT_A64_REASON_PAR_WRITE);
        if (!(par_packed_load(cpu) >> 47)) return sm_stop(cpu, op, OCNEXT_A64_REASON_PAR_UNKNOWN);
        stage_write(tx, op & 31u, par_unpack(par_packed_load(cpu)), 64, 0);
        return SM_CONTINUE;
    }
    mask = (id == UINT32_C(0xd500409f) || id == UINT32_C(0xd5184260)) ? PSTATE_PAN :
           (id == UINT32_C(0xd500407f) || id == UINT32_C(0xd5184280)) ? PSTATE_UAO :
           (id == UINT32_C(0xd503405f) || id == UINT32_C(0xd51b42a0)) ? PSTATE_DIT : PSTATE_SSBS;
    if (cpu->system.current_el == 0 && (mask == PSTATE_PAN || mask == PSTATE_UAO))
        return undefined_access(cpu, memory, op);
    if (read) {
        stage_write(tx, op & 31u, (cpu->ext_state & sm_pstate_ext_flag(mask)) ? mask : 0, 64, 0);
        return SM_CONTINUE;
    }
    if (immediate) {
        unsigned crm = (op >> 8) & 15u;
        if (crm > 1) return sm_stop(cpu, op, OCNEXT_A64_REASON_PSTATE_FORMAT);
        value = crm ? mask : 0;
    } else {
        value = reg_read(cpu, op & 31u, 64, 0);
        if (value & ~mask) return sm_stop(cpu, op, OCNEXT_A64_REASON_PSTATE_FORMAT);
    }
    ext_set(cpu, sm_pstate_ext_flag(mask), value != 0);
    /* PAN is consumed by the MMU adapter; UAO only changes LDTR/STTR
     * (unprivileged loads/stores, which this interpreter does not decode and
     * therefore stops on); DIT/SSBS constrain timing/speculation that a
     * functional single-PE model does not have. The bit state is real and
     * visible through MRS, SPSR save/restore and the adapter. */
    if (mask == PSTATE_PAN || mask == PSTATE_SSBS) ext_set(cpu, OCNEXT_A64_EXT_TOUCHED, 1);
    return SM_CONTINUE;
}

static enum ocnext_a64_result sm_provider(struct ocnext_a64_cpu *cpu,
                                          const struct ocnext_a64_memory *memory, uint32_t op,
                                          unsigned kind, unsigned scope, uint64_t operand)
{
    struct ocnext_a64_maintenance_request request = {0};
    enum ocnext_a64_maintenance_result completed;
    int is_at = kind >= OCNEXT_A64_MAINTENANCE_AT_S1E1R && kind <= OCNEXT_A64_MAINTENANCE_AT_S1E0W;
    if (!memory->maintenance) return sm_stop(cpu, op, OCNEXT_A64_REASON_NO_PROVIDER);
    request.pc = cpu->pc; request.operand = operand; request.opcode = op;
    request.kind = (enum ocnext_a64_maintenance_kind)kind;
    request.current_el = cpu->system.current_el; request.scope = (uint8_t)scope;
    request.stage = OCNEXT_A64_MAINTENANCE_STAGE1;
    cpu->ext_at_active = is_at ? 1 : 0;
    completed = memory->maintenance(memory->context, &request);
    if (is_at) {
        unsigned published = cpu->ext_at_active == 2;
        cpu->ext_at_active = 0;
        if (completed == OCNEXT_A64_MAINTENANCE_COMPLETED && !published)
            return fault(cpu, OCNEXT_A64_FAULT_MAINTENANCE_PROVIDER, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    }
    if (completed == OCNEXT_A64_MAINTENANCE_UNSUPPORTED)
        return sm_stop(cpu, op, OCNEXT_A64_REASON_PROVIDER_REFUSED);
    if (completed != OCNEXT_A64_MAINTENANCE_COMPLETED)
        return fault(cpu, OCNEXT_A64_FAULT_MAINTENANCE_PROVIDER, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    return SM_CONTINUE;
}

static enum ocnext_a64_result sm_sys(struct ocnext_a64_cpu *cpu,
                                     const struct ocnext_a64_memory *memory, uint32_t op)
{
    enum sm_kind_class cls; unsigned kind, scope, bit; int el0_uci, el1_only_va;
    uint64_t operand;
    sm_decode_sys(op, &cls, &kind, &scope, &el0_uci, &el1_only_va);
    if (!sync_profile(cpu)) return sm_stop(cpu, op, OCNEXT_A64_REASON_NONE);
    if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    operand = reg_read(cpu, op & 31u, 64, 0);
    if (cpu->system.current_el == 0) {
        unsigned ctl = cls == SM_ZVA ? 14u : 26u; /* SCTLR_EL1.DZE / UCI */
        if (cls != SM_ZVA && !el0_uci) return undefined_access(cpu, memory, op);
        if (sm_sctlr_bit(cpu, ctl, &bit)) return sm_stop(cpu, op, OCNEXT_A64_REASON_SCTLR_UNKNOWN);
        if (!bit) return take_sync(cpu, memory, op, 0x18, system_iss(op), cpu->pc, 0);
    }
    if (cls == SM_ZVA) {
        uint8_t zeros[32] = {0};
        unsigned size, chunk, offset;
        uint64_t base;
        if (!cpu->ext_dczid_bs) return sm_stop(cpu, op, OCNEXT_A64_REASON_DCZID_UNKNOWN);
        size = 4u << cpu->ext_dczid_bs;
        base = operand & ~(uint64_t)(size - 1u);
        chunk = size < 32u ? size : 32u;
        if (base > UINT64_MAX - (size - 1u) || !memory->write)
            return fault(cpu, OCNEXT_A64_FAULT_WRITE, OCNEXT_A64_ACCESS_WRITE, base, chunk, op);
        /* The block is zeroed with ordinary stores, so MMU translation,
         * permissions and PAN apply exactly as for a store. A fault is
         * reported at the failing chunk; the first chunk of a block-aligned
         * (<= page size) region carries the translation/permission verdict
         * for the whole block, so partial zeroing needs a bus failure. */
        for (offset = 0; offset < size; offset += chunk)
            if (memory->write(memory->context, base + offset, zeros, chunk) != 0)
                return fault(cpu, OCNEXT_A64_FAULT_WRITE, OCNEXT_A64_ACCESS_WRITE, base + offset, chunk, op);
        return SM_CONTINUE;
    }
    if (kind == OCNEXT_A64_MAINTENANCE_VMALLE1) operand = 0; /* Xt is SBZ for VMALLE1. */
    return sm_provider(cpu, memory, op, kind, scope, operand);
}

/* Entry point from the dispatch chain. Returns SM_CONTINUE to commit normally. */
static enum ocnext_a64_result sm_exec(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory, uint32_t op,
                                      struct transaction *tx)
{
    enum sm_kind_class cls; unsigned kind, scope; int a, b;
    if (sm_is_hint(op)) return sm_hint(cpu, memory, op);
    if (sm_is_pstate_imm(op) || sm_is_pstate_reg(op)) return sm_pstate(cpu, memory, op, tx);
    if (sm_decode_sys(op, &cls, &kind, &scope, &a, &b)) return sm_sys(cpu, memory, op);
    return sm_stop(cpu, op, OCNEXT_A64_REASON_NONE);
}

int ocnext_a64_configure_dczid(struct ocnext_a64_cpu *cpu, unsigned bs)
{
    if (!cpu || bs < 2 || bs > 9 || cpu->retired || cpu->halted || cpu->system.exception_count ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE || cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC ||
        cpu->ext_dczid_bs) return -1;
    cpu->ext_dczid_bs = (uint8_t)bs;
    return 0;
}

int ocnext_a64_publish_par_el1(struct ocnext_a64_cpu *cpu, uint64_t par)
{
    uint64_t packed;
    if (!cpu || cpu->ext_at_active != 1 || !par_pack(par, &packed)) return -1;
    par_packed_store(cpu, packed);
    cpu->ext_at_active = 2;
    return 0;
}

int ocnext_a64_get_par_el1(const struct ocnext_a64_cpu *cpu, uint64_t *par)
{
    uint64_t packed;
    if (!cpu || !par) return -1;
    packed = par_packed_load(cpu);
    if (!(packed >> 47)) return -1;
    *par = par_unpack(packed);
    return 0;
}

const char *ocnext_a64_unsupported_reason_string(unsigned reason)
{
    switch (reason) {
    case OCNEXT_A64_REASON_NONE: return "unsupported instruction/encoding";
    case OCNEXT_A64_REASON_WFI_NO_WAKE: return "WFI would wait forever: no interrupt source is modeled";
    case OCNEXT_A64_REASON_WFE_NO_EVENT: return "WFE would wait forever: event register clear on a single PE";
    case OCNEXT_A64_REASON_BTI_ENFORCED: return "BTI enforcement (SCTLR_EL1.BT0/BT1) is not modeled";
    case OCNEXT_A64_REASON_SCTLR_UNKNOWN: return "required SCTLR_EL1 control bit is UNKNOWN";
    case OCNEXT_A64_REASON_PAR_UNKNOWN: return "PAR_EL1 read before any address-translation result";
    case OCNEXT_A64_REASON_PAR_WRITE: return "guest write of PAR_EL1 is not modeled";
    case OCNEXT_A64_REASON_DCZID_UNKNOWN: return "DCZID_EL0 / DC ZVA block size not configured";
    case OCNEXT_A64_REASON_DIT_ENTRY: return "exception entry with PSTATE.DIT=1 is not modeled";
    case OCNEXT_A64_REASON_ENTRY_SCTLR_UNKNOWN: return "SCTLR_EL1.SPAN/DSSBS UNKNOWN at exception entry after PAN/SSBS use";
    case OCNEXT_A64_REASON_NO_PROVIDER: return "no maintenance provider attached for cache/TLB/AT operation";
    case OCNEXT_A64_REASON_PROVIDER_REFUSED: return "maintenance provider does not support this operation";
    case OCNEXT_A64_REASON_OPERAND_FORMAT: return "maintenance operand outside the modeled format";
    case OCNEXT_A64_REASON_PSTATE_FORMAT: return "PSTATE field value outside the modeled bits";
    default: return "unknown unsupported reason";
    }
}
