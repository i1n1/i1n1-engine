#include "ocnext/mmu_cpu.h"
#include <stdatomic.h>

static void copy_bytes(void *out, const void *source, size_t bytes)
{
    uint8_t *destination = out;
    const uint8_t *input = source;
    while (bytes--) *destination++ = *input++;
}

static void zero_bytes(void *out, size_t bytes)
{
    uint8_t *destination = out;
    while (bytes--) *destination++ = 0;
}

static int project_bank(struct ocnext_mmu *view, const struct ocnext_a64_cpu *cpu)
{
    const struct ocnext_a64_mmu_registers *bank = &cpu->system.mmu;
    if ((bank->known_mask & ~OCNEXT_A64_MMU_KNOWN_ALL) || bank->reserved ||
        !(bank->known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) ||
        ((bank->sctlr_el1 & 1) && bank->known_mask != OCNEXT_A64_MMU_KNOWN_ALL)) return -1;
    view->config.tcr_el1 = bank->tcr_el1;
    view->config.ttbr0_el1 = bank->ttbr0_el1;
    view->config.ttbr1_el1 = bank->ttbr1_el1;
    view->config.sctlr_el1 = bank->sctlr_el1;
    view->config.mair_el1 = bank->mair_el1;
    view->config.current_el = cpu->system.current_el;
    /* PSTATE.PAN is CPU state; mmu.config.pan only seeds it at init. */
    view->config.pan = (cpu->ext_state & OCNEXT_A64_EXT_PAN) != 0;
    return 0;
}

static void invalid_bank(struct ocnext_mmu *mmu, uint64_t address,
                         enum ocnext_a64_access access)
{
    struct ocnext_mmu_fault fault = {0};
    fault.kind = OCNEXT_MMU_FAULT_ARGUMENT;
    fault.va = address; fault.access = access;
    mmu->fault = fault;
}

static int read_current(void *context, uint64_t address, uint8_t *out,
                        size_t size, enum ocnext_a64_access access)
{
    struct ocnext_mmu_cpu *adapter = context;
    struct ocnext_mmu view = *adapter->mmu;
    int result;
    if (project_bank(&view, adapter->cpu)) {
        invalid_bank(adapter->mmu, address, access); return -1;
    }
    /* One CPU access may be up to 64 bytes (LD4/ST4); the walker transfers at most
     * OCNEXT_MMU_MAX_TRANSFER at a time, so larger reads are issued in order. */
    result = 0;
    while (size && !result) {
        size_t chunk = size > OCNEXT_MMU_MAX_TRANSFER ? OCNEXT_MMU_MAX_TRANSFER : size;
        result = ocnext_mmu_read(&view, address, out, chunk, access);
        address += chunk; out += chunk; size -= chunk;
    }
    adapter->mmu->fault = view.fault;
    return result;
}

static int write_current(void *context, uint64_t address,
                         const uint8_t *source, size_t size)
{
    struct ocnext_mmu_cpu *adapter = context;
    struct ocnext_mmu view = *adapter->mmu;
    int result;
    if (project_bank(&view, adapter->cpu)) {
        invalid_bank(adapter->mmu, address, OCNEXT_A64_ACCESS_WRITE); return -1;
    }
    result = 0;
    if (size > OCNEXT_MMU_MAX_TRANSFER) {
        /* Larger stores (ST4, 64 bytes): prove every chunk is writable before the first byte
         * is stored, so a translation/permission fault leaves guest memory untouched. */
        size_t offset;
        for (offset = 0; offset < size && !result; offset += OCNEXT_MMU_MAX_TRANSFER) {
            struct ocnext_mmu_translation t;
            size_t chunk = size - offset > OCNEXT_MMU_MAX_TRANSFER ? OCNEXT_MMU_MAX_TRANSFER : size - offset;
            if (ocnext_mmu_translate(&view, address + offset, OCNEXT_A64_ACCESS_WRITE, &t) != OCNEXT_MMU_OK ||
                ocnext_mmu_translate(&view, address + offset + chunk - 1u, OCNEXT_A64_ACCESS_WRITE, &t) != OCNEXT_MMU_OK)
                result = -1;
        }
    }
    while (size && !result) {
        size_t chunk = size > OCNEXT_MMU_MAX_TRANSFER ? OCNEXT_MMU_MAX_TRANSFER : size;
        result = ocnext_mmu_write(&view, address, source, chunk);
        address += chunk; source += chunk; size -= chunk;
    }
    adapter->mmu->fault = view.fault;
    return result;
}

static int fetch_view(void *context, uint64_t address, uint8_t *out,
                      size_t size, unsigned el, uint64_t pstate)
{
    struct ocnext_mmu_cpu *adapter = context;
    struct ocnext_mmu view = *adapter->mmu;
    unsigned mode = (unsigned)(pstate & 31u);
    if (el > 1 || (pstate & ~(UINT64_C(0xf00003df) | UINT64_C(0x01c01000))) ||
        (mode != 0 && mode != 4 && mode != 5) || mode >> 2 != el)
        return -1;
    if (project_bank(&view, adapter->cpu)) return -1;
    view.config.current_el = (uint8_t)el;
    return ocnext_mmu_read(&view, address, out, size, OCNEXT_A64_ACCESS_FETCH);
}

static enum ocnext_a64_sync_result sync_current(void *context,
                          const struct ocnext_a64_sync_request *request)
{
    struct ocnext_mmu_cpu *adapter = context;
    if (!adapter || !adapter->cpu || !request || request->pc != adapter->cpu->pc ||
        request->current_el != adapter->cpu->system.current_el)
        return OCNEXT_A64_SYNC_FAILED;
    return ocnext_ordering_sync(&adapter->ordering, request);
}

int ocnext_mmu_cpu_configure_ordering(struct ocnext_mmu_cpu *adapter,
                                    enum ocnext_ordering_profile profile)
{
    if (!adapter || !adapter->cpu || !adapter->mmu ||
        adapter->memory.context != adapter || adapter->memory.sync ||
        adapter->cpu->retired || adapter->cpu->halted || adapter->cpu->system.exception_count ||
        adapter->cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        adapter->cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC ||
        ocnext_ordering_init(&adapter->ordering,profile)) return -1;
    adapter->memory.sync = sync_current;
    return 0;
}

static int initial_adapter(const struct ocnext_mmu_cpu *adapter)
{
    struct ocnext_mmu view;
    if (!adapter || !adapter->cpu || !adapter->mmu ||
        adapter->memory.context != adapter || adapter->memory.read != read_current ||
        adapter->memory.write != write_current || adapter->memory.fetch_view != fetch_view ||
        !adapter->mmu->bus.read || !adapter->mmu->bus.probe || !adapter->mmu->bus.writev ||
        adapter->cpu->retired || adapter->cpu->halted || adapter->cpu->system.exception_count ||
        adapter->cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        adapter->cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC ||
        adapter->cpu->system.current_el > 1 || adapter->abort_pending ||
        adapter->configuration_rejected) return 0;
    view = *adapter->mmu;
    return !project_bank(&view, adapter->cpu) && ocnext_mmu_validate(&view.config) == OCNEXT_MMU_OK;
}

/* Canonical SYS/TLBI/IC/DC/AT word with Rt cleared, or 0 for an unknown kind. */
static uint32_t maintenance_canonical(unsigned kind, unsigned scope, uint32_t opcode)
{
    uint32_t crm = scope == OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE ? 3u : 7u;
    switch (kind) {
    case OCNEXT_A64_MAINTENANCE_VMALLE1: return UINT32_C(0xd5088000) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_TLBI_VAE1: return UINT32_C(0xd5088020) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_TLBI_ASIDE1: return UINT32_C(0xd5088040) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_TLBI_VAAE1: return UINT32_C(0xd5088060) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_TLBI_VALE1: return UINT32_C(0xd50880a0) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_TLBI_VAALE1: return UINT32_C(0xd50880e0) | crm << 8;
    case OCNEXT_A64_MAINTENANCE_IC_IALLUIS: return UINT32_C(0xd5087100);
    case OCNEXT_A64_MAINTENANCE_IC_IALLU: return UINT32_C(0xd5087500);
    case OCNEXT_A64_MAINTENANCE_IC_IVAU: return UINT32_C(0xd50b7520);
    case OCNEXT_A64_MAINTENANCE_DC_IVAC: return UINT32_C(0xd5087620);
    case OCNEXT_A64_MAINTENANCE_DC_CVAC: return UINT32_C(0xd50b7a20);
    case OCNEXT_A64_MAINTENANCE_DC_CVAU: return UINT32_C(0xd50b7b20);
    case OCNEXT_A64_MAINTENANCE_DC_CIVAC: return UINT32_C(0xd50b7e20);
    case OCNEXT_A64_MAINTENANCE_DC_ISW: return UINT32_C(0xd5087640);
    case OCNEXT_A64_MAINTENANCE_DC_CSW: return UINT32_C(0xd5087a40);
    case OCNEXT_A64_MAINTENANCE_DC_CISW: return UINT32_C(0xd5087e40);
    case OCNEXT_A64_MAINTENANCE_AT_S1E1R: return UINT32_C(0xd5087800);
    case OCNEXT_A64_MAINTENANCE_AT_S1E1W: return UINT32_C(0xd5087820);
    case OCNEXT_A64_MAINTENANCE_AT_S1E0R: return UINT32_C(0xd5087840);
    case OCNEXT_A64_MAINTENANCE_AT_S1E0W: return UINT32_C(0xd5087860);
    case OCNEXT_A64_MAINTENANCE_TLBI_OTHER: {
        unsigned c = (opcode >> 8) & 15u, o = (opcode >> 5) & 7u;
        int ok = (opcode & UINT32_C(0xfffff000)) == UINT32_C(0xd5088000) &&
                 (c == 1 ? (o == 0 || o == 1 || o == 2 || o == 3 || o == 5 || o == 7)
                         : (c == 2 || c == 5 || c == 6) && (o == 1 || o == 3 || o == 5 || o == 7)) &&
                 scope == (c == 6 ? OCNEXT_A64_MAINTENANCE_LOCAL : OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE);
        return ok ? (opcode & UINT32_C(0xffffffe0)) : 0;
    }
    default: return 0;
    }
}

static int kind_is_tlbi(unsigned k)
{
    return (k >= OCNEXT_A64_MAINTENANCE_VMALLE1 && k <= OCNEXT_A64_MAINTENANCE_TLBI_VAALE1) ||
           k == OCNEXT_A64_MAINTENANCE_TLBI_OTHER;
}
static int kind_is_by_va_cache(unsigned k)
{
    return k == OCNEXT_A64_MAINTENANCE_IC_IVAU ||
           (k >= OCNEXT_A64_MAINTENANCE_DC_IVAC && k <= OCNEXT_A64_MAINTENANCE_DC_CIVAC);
}
static int kind_is_at(unsigned k)
{
    return k >= OCNEXT_A64_MAINTENANCE_AT_S1E1R && k <= OCNEXT_A64_MAINTENANCE_AT_S1E0W;
}

/* PAR_EL1 for a successful stage1 walk (F=0): ATTR[63:56], PA[47:12],
 * bit11 RES1, SH[8:7]. NS (bit 9) is 0 in this non-secure-only model. Device
 * and Normal Non-cacheable report SH=0b10 (outer shareable) regardless of the
 * descriptor. With SCTLR.M=0 the result is Device-nGnRnE, SH=0b10. */
static uint64_t par_success(const struct ocnext_mmu_translation *t, int mmu_on)
{
    uint64_t attr = mmu_on ? t->mair_attribute : 0;
    unsigned sh = (!mmu_on || t->device || attr == 0x44) ? 2u : t->shareability;
    return attr << 56 | (t->pa & UINT64_C(0x0000fffffffff000)) | UINT64_C(1) << 11 | (uint64_t)sh << 7;
}

/* Faulting AT (F=1): FST[6:1] is the fault status code of the would-be
 * abort, bit11 RES1; PTW=0 and S=0 (stage1 fault, no stage2). */
static uint64_t par_fault(const struct ocnext_mmu_fault *f)
{
    return UINT64_C(1) | (uint64_t)(f->esr_el1 & 63u) << 1 | UINT64_C(1) << 11;
}

static enum ocnext_a64_maintenance_result maintenance_current(void *context,
                      const struct ocnext_a64_maintenance_request *input)
{
    struct ocnext_mmu_cpu *adapter = context;
    struct ocnext_a64_maintenance_request request;
    struct ocnext_mmu_maintenance *state;
    uint32_t canonical;
    unsigned i;
    if (!adapter || !adapter->cpu || !input) return OCNEXT_A64_MAINTENANCE_FAILED;
    state = &adapter->maintenance;
    if (state->abi_version != OCNEXT_MMU_MAINTENANCE_ABI_VERSION ||
        state->profile != OCNEXT_MMU_MAINTENANCE_SERIAL_NORMAL_RAM)
        return OCNEXT_A64_MAINTENANCE_UNSUPPORTED;
    copy_bytes(&request,input,sizeof(request));
    canonical = maintenance_canonical(request.kind, request.scope, request.opcode);
    if (adapter->memory.context != adapter || adapter->memory.maintenance != maintenance_current ||
        adapter->memory.sync != sync_current ||
        adapter->ordering.abi_version != OCNEXT_ORDERING_ABI_VERSION ||
        adapter->ordering.profile != OCNEXT_ORDERING_SERIAL_RAM ||
        request.pc != adapter->cpu->pc || request.pc % 4 || request.pc > UINT64_MAX-4 ||
        request.current_el > 1 || request.current_el != adapter->cpu->system.current_el ||
        (request.current_el == 0 && !kind_is_by_va_cache(request.kind)) ||
        !canonical || (request.opcode & UINT32_C(0xffffffe0)) != canonical ||
        (kind_is_tlbi(request.kind) ? (request.scope != OCNEXT_A64_MAINTENANCE_LOCAL &&
                                       request.scope != OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE)
         : request.kind == OCNEXT_A64_MAINTENANCE_IC_IALLUIS ? request.scope != OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE
                                    : request.scope != OCNEXT_A64_MAINTENANCE_LOCAL) ||
        request.stage != OCNEXT_A64_MAINTENANCE_STAGE1 ||
        (request.kind == OCNEXT_A64_MAINTENANCE_VMALLE1 && request.operand) ||
        (request.kind == OCNEXT_A64_MAINTENANCE_IC_IALLU && request.operand) ||
        (request.kind == OCNEXT_A64_MAINTENANCE_IC_IALLUIS && request.operand) ||
        state->events == UINT64_MAX || state->host_fences == UINT64_MAX ||
        state->translation_epoch == UINT64_MAX ||
        adapter->ordering.instruction_epoch == UINT64_MAX) return OCNEXT_A64_MAINTENANCE_FAILED;
    for (i=0;i<sizeof(request.reserved);++i)
        if (request.reserved[i]) return OCNEXT_A64_MAINTENANCE_FAILED;
    /* TLBI operand: ASID[63:48], TTL[47:44] (FEAT_TTL absent: RES0), VA[43:0]. */
    if (request.kind >= OCNEXT_A64_MAINTENANCE_TLBI_VAE1 && request.kind <= OCNEXT_A64_MAINTENANCE_TLBI_VAALE1) {
        uint64_t reserved_bits = UINT64_C(0x0000f00000000000);
        if (request.kind == OCNEXT_A64_MAINTENANCE_TLBI_ASIDE1) reserved_bits |= UINT64_C(0x0000ffffffffffff);
        if (request.kind == OCNEXT_A64_MAINTENANCE_TLBI_VAAE1 || request.kind == OCNEXT_A64_MAINTENANCE_TLBI_VAALE1)
            reserved_bits |= UINT64_C(0xffff000000000000);
        if (request.operand & reserved_bits) return OCNEXT_A64_MAINTENANCE_UNSUPPORTED;
    }
    if (kind_is_by_va_cache(request.kind) || kind_is_at(request.kind)) {
        struct ocnext_mmu view = *adapter->mmu;
        struct ocnext_mmu_translation t;
        enum ocnext_mmu_result translated;
        enum ocnext_a64_access access = (request.kind == OCNEXT_A64_MAINTENANCE_DC_IVAC ||
                                         request.kind == OCNEXT_A64_MAINTENANCE_AT_S1E1W ||
                                         request.kind == OCNEXT_A64_MAINTENANCE_AT_S1E0W)
                                         ? OCNEXT_A64_ACCESS_WRITE : OCNEXT_A64_ACCESS_READ;
        if (project_bank(&view, adapter->cpu)) return OCNEXT_A64_MAINTENANCE_FAILED;
        if (request.kind == OCNEXT_A64_MAINTENANCE_AT_S1E0R || request.kind == OCNEXT_A64_MAINTENANCE_AT_S1E0W)
            view.config.current_el = 0; /* translate under the EL0 regime */
        translated = ocnext_mmu_translate(&view, request.operand, access, &t);
        adapter->mmu->fault = view.fault;
        if (kind_is_at(request.kind)) {
            int mmu_on = (int)(adapter->cpu->system.mmu.sctlr_el1 & 1u);
            uint64_t par;
            if (translated == OCNEXT_MMU_OK) par = par_success(&t, mmu_on);
            else if (translated == OCNEXT_MMU_ABORT && view.fault.syndrome_valid) par = par_fault(&view.fault);
            else return translated == OCNEXT_MMU_UNSUPPORTED ? OCNEXT_A64_MAINTENANCE_UNSUPPORTED
                                                             : OCNEXT_A64_MAINTENANCE_FAILED;
            /* AT never raises a translation abort; the verdict lives in PAR_EL1. */
            if (ocnext_a64_publish_par_el1(adapter->cpu, par)) return OCNEXT_A64_MAINTENANCE_FAILED;
        } else if (translated != OCNEXT_MMU_OK) {
            /* By-VA cache maintenance can take a data abort (CM=1 syndrome)
             * that is not modeled: stop with the walker verdict observable in
             * the adapter's mmu fault instead of delivering a guessed ESR. */
            return OCNEXT_A64_MAINTENANCE_FAILED;
        }
    }
    /* No translation cache, data/instruction cache or asynchronous guest
     * access exists in this explicitly certified model. The actual fence
     * completes preceding synchronous RAM accesses; every later dispatch/view
     * walks and fetches afresh. TLBI publishes a translation epoch; IC
     * publishes an instruction epoch so downstream translators discard code. */
    atomic_thread_fence(memory_order_seq_cst);
    ++state->events; ++state->host_fences;
    if (kind_is_tlbi(request.kind)) ++state->translation_epoch;
    if (request.kind == OCNEXT_A64_MAINTENANCE_IC_IALLU || request.kind == OCNEXT_A64_MAINTENANCE_IC_IALLUIS ||
        request.kind == OCNEXT_A64_MAINTENANCE_IC_IVAU) ++adapter->ordering.instruction_epoch;
    copy_bytes(&state->last,&request,sizeof(request));
    return OCNEXT_A64_MAINTENANCE_COMPLETED;
}

int ocnext_mmu_cpu_configure_maintenance(struct ocnext_mmu_cpu *adapter,
                                      enum ocnext_mmu_maintenance_profile profile)
{
    struct ocnext_mmu_maintenance state;
    if (profile != OCNEXT_MMU_MAINTENANCE_SERIAL_NORMAL_RAM || !initial_adapter(adapter) ||
        adapter->memory.maintenance || adapter->memory.sync != sync_current ||
        adapter->ordering.abi_version != OCNEXT_ORDERING_ABI_VERSION ||
        adapter->ordering.profile != OCNEXT_ORDERING_SERIAL_RAM || adapter->ordering.events ||
        adapter->ordering.host_fences || adapter->ordering.dmb || adapter->ordering.dsb ||
        adapter->ordering.isb || adapter->ordering.instruction_epoch) return -1;
    zero_bytes(&state,sizeof(state));
    state.abi_version = OCNEXT_MMU_MAINTENANCE_ABI_VERSION;
    state.profile = (uint32_t)profile;
    copy_bytes(&adapter->maintenance,&state,sizeof(state));
    adapter->memory.maintenance = maintenance_current;
    return 0;
}

int ocnext_mmu_cpu_configure_features(struct ocnext_mmu_cpu *adapter,
                                   enum ocnext_mmu_feature_profile profile)
{
    struct ocnext_a64_feature_registers bank = {0};
    if (profile != OCNEXT_MMU_FEATURE_SERIAL_S1_PA48_ASID16 || !initial_adapter(adapter) ||
        adapter->cpu->system.features.known_mask || adapter->cpu->system.features.reserved ||
        adapter->cpu->system.features.id_aa64mmfr0_el1) return -1;
    /* Issuer ties this value to the implemented fresh-walk stage1 provider:
     * PA48, ASID16, 4/16/64KiB; the _2 granule fields explicitly exclude
     * stage2. It is not a host/Apple CPU identity or a complete ISA claim. */
    bank.id_aa64mmfr0_el1 = UINT64_C(0x0000011100100025);
    bank.known_mask = OCNEXT_A64_FEATURE_KNOWN_MMFR0;
    return ocnext_a64_configure_feature_registers(adapter->cpu,&bank);
}

int ocnext_mmu_cpu_init(struct ocnext_mmu_cpu *out,
                       struct ocnext_a64_cpu *cpu, struct ocnext_mmu *mmu)
{
    struct ocnext_mmu_cpu adapter;
    struct ocnext_a64_mmu_registers bank = {0};
    zero_bytes(&adapter,sizeof(adapter));
    if (!out || !cpu || !mmu || cpu->retired || cpu->system.exception_count ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE || cpu->halted ||
        cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC ||
        cpu->system.current_el > 1 || !mmu->bus.read || !mmu->bus.probe ||
        !mmu->bus.writev || ocnext_mmu_validate(&mmu->config) != OCNEXT_MMU_OK)
        return -1;
    bank.tcr_el1 = mmu->config.tcr_el1; bank.ttbr0_el1 = mmu->config.ttbr0_el1;
    bank.ttbr1_el1 = mmu->config.ttbr1_el1; bank.sctlr_el1 = mmu->config.sctlr_el1;
    bank.mair_el1 = mmu->config.mair_el1; bank.known_mask = OCNEXT_A64_MMU_KNOWN_ALL;
    if (cpu->system.mmu.known_mask) {
        const struct ocnext_a64_mmu_registers *known = &cpu->system.mmu;
        if (!(known->known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) || known->reserved ||
            known->tcr_el1 != bank.tcr_el1 || known->ttbr0_el1 != bank.ttbr0_el1 ||
            known->ttbr1_el1 != bank.ttbr1_el1 || known->sctlr_el1 != bank.sctlr_el1 ||
            known->mair_el1 != bank.mair_el1) return -1;
        bank = *known;
    }
    /* Validation stays explicit: partial known M0 is allowed, M1 needs ALL.
     * configure API checks reserved/unknown fields and the CPU subset masks. */
    if ((bank.sctlr_el1 & 1) && bank.known_mask != OCNEXT_A64_MMU_KNOWN_ALL) return -1;
    if (ocnext_a64_configure_mmu_registers(cpu, &bank)) return -1;
    if (mmu->config.pan) cpu->ext_state |= OCNEXT_A64_EXT_PAN | OCNEXT_A64_EXT_TOUCHED;
    adapter.cpu = cpu;
    adapter.mmu = mmu;
    adapter.memory.context = out;
    adapter.memory.read = read_current;
    adapter.memory.write = write_current;
    adapter.memory.fetch_view = fetch_view;
    copy_bytes(out,&adapter,sizeof(adapter));
    return 0;
}

static int ordinary_fault(const struct ocnext_a64_fault *fault)
{
    return fault->code == OCNEXT_A64_FAULT_FETCH ||
           fault->code == OCNEXT_A64_FAULT_READ ||
           fault->code == OCNEXT_A64_FAULT_WRITE;
}

static int equal_fault(const struct ocnext_a64_fault *a,
                       const struct ocnext_a64_fault *b)
{
    return a->code == b->code && a->access == b->access && a->pc == b->pc &&
           a->address == b->address && a->opcode == b->opcode &&
           a->access_size == b->access_size && a->syndrome_ec == b->syndrome_ec &&
           a->target_el == b->target_el && a->has_syndrome == b->has_syndrome;
}

enum ocnext_mmu_result ocnext_mmu_cpu_translate(struct ocnext_mmu_cpu *adapter, uint64_t va,
                                               enum ocnext_a64_access access, unsigned el0, unsigned pan,
                                               struct ocnext_mmu_translation *out,
                                               struct ocnext_mmu_fault *fault)
{
    struct ocnext_mmu view;
    enum ocnext_mmu_result r;
    if (!adapter || !adapter->cpu || !adapter->mmu || !out || !fault || el0 > 1 || pan > 1) return OCNEXT_MMU_ARGUMENT;
    view = *adapter->mmu;
    if (project_bank(&view, adapter->cpu)) return OCNEXT_MMU_ARGUMENT;
    view.config.current_el = (uint8_t)(el0 ? 0 : 1);
    view.config.pan = (uint8_t)(el0 ? 0 : pan);
    r = ocnext_mmu_translate(&view, va, access, out);
    *fault = view.fault;
    return r;
}

enum ocnext_a64_result ocnext_mmu_cpu_step(struct ocnext_mmu_cpu *adapter)
{
    return ocnext_mmu_cpu_step_hooks(adapter, NULL);
}

enum ocnext_a64_result ocnext_mmu_cpu_step_hooks(struct ocnext_mmu_cpu *adapter,
                                               const struct ocnext_a64_hooks *hooks)
{
    enum ocnext_a64_result result;
    struct ocnext_a64_cpu before;
    const struct ocnext_a64_fault *cpu_fault;
    const struct ocnext_mmu_fault *mmu_fault;
    if (!adapter || !adapter->cpu || !adapter->mmu ||
        adapter->memory.context != adapter) return OCNEXT_A64_FAULTED;
    /* Re-observing a sticky fault does not discard its explicit delivery token. */
    if (adapter->cpu->fault.code != OCNEXT_A64_FAULT_NONE)
        return OCNEXT_A64_FAULTED;
    adapter->abort_pending = 0;
    adapter->configuration_rejected = 0;
    copy_bytes(&before, adapter->cpu, sizeof(before));
    result = ocnext_a64_step_hooks(adapter->cpu, &adapter->memory, hooks);
    /* A register MSR has no guest RAM write. Validate the whole bank only
     * after its staged core commit; reject invalid geometry atomically. No
     * next-PC mapping preflight: a valid MMU enable can cause a later fetch abort. */
    if (result == OCNEXT_A64_RETIRED &&
        (before.system.mmu.tcr_el1 != adapter->cpu->system.mmu.tcr_el1 ||
         before.system.mmu.ttbr0_el1 != adapter->cpu->system.mmu.ttbr0_el1 ||
         before.system.mmu.ttbr1_el1 != adapter->cpu->system.mmu.ttbr1_el1 ||
         before.system.mmu.sctlr_el1 != adapter->cpu->system.mmu.sctlr_el1 ||
         before.system.mmu.mair_el1 != adapter->cpu->system.mmu.mair_el1 ||
         before.system.mmu.known_mask != adapter->cpu->system.mmu.known_mask)) {
        struct ocnext_mmu proposed = *adapter->mmu;
        if (project_bank(&proposed, adapter->cpu) ||
            ocnext_mmu_validate(&proposed.config) != OCNEXT_MMU_OK) {
            uint32_t opcode = adapter->cpu->last_opcode;
            struct ocnext_a64_fault fault = {0};
            adapter->rejected_mmu = adapter->cpu->system.mmu;
            adapter->configuration_rejected = 1;
            copy_bytes(adapter->cpu, &before, sizeof(before));
            fault.code = OCNEXT_A64_FAULT_UNSUPPORTED;
            fault.access = OCNEXT_A64_ACCESS_FETCH;
            fault.pc = fault.address = before.pc;
            fault.opcode = opcode; fault.access_size = 4;
            adapter->cpu->fault = fault; adapter->cpu->last_opcode = opcode;
            return OCNEXT_A64_FAULTED;
        }
    }
    cpu_fault = &adapter->cpu->fault;
    mmu_fault = &adapter->mmu->fault;
    if (result == OCNEXT_A64_FAULTED && ordinary_fault(cpu_fault) &&
        (cpu_fault->code != OCNEXT_A64_FAULT_FETCH ||
         (cpu_fault->address == cpu_fault->pc && cpu_fault->access_size == 4)) &&
        mmu_fault->syndrome_valid && mmu_fault->access == cpu_fault->access &&
        cpu_fault->pc == adapter->cpu->pc && mmu_fault->va >= cpu_fault->address &&
        mmu_fault->va - cpu_fault->address < cpu_fault->access_size) {
        adapter->captured_abort = *mmu_fault;
        adapter->captured_cpu_fault = *cpu_fault;
        adapter->captured_el = adapter->cpu->system.current_el;
        adapter->captured_exception_count = adapter->cpu->system.exception_count;
        adapter->abort_pending = 1;
    }
    return result;
}

enum ocnext_a64_result ocnext_mmu_cpu_deliver_abort(struct ocnext_mmu_cpu *adapter)
{
    enum ocnext_a64_result result;
    if (!adapter || !adapter->cpu || !adapter->mmu || !adapter->abort_pending ||
        adapter->memory.context != adapter ||
        adapter->cpu->system.current_el != adapter->captured_el ||
        adapter->cpu->system.exception_count != adapter->captured_exception_count ||
        adapter->cpu->pc != adapter->captured_cpu_fault.pc ||
        !equal_fault(&adapter->cpu->fault, &adapter->captured_cpu_fault))
        return OCNEXT_A64_FAULTED;
    result = ocnext_a64_deliver_abort(adapter->cpu, &adapter->memory,
                adapter->captured_abort.esr_el1, adapter->captured_abort.va,
                adapter->captured_abort.far_valid);
    /* A failed vector preflight is terminal until caller recovery/reset; never
     * reinterpret it as a fresh guest abort or repeatedly overwrite ESR/FAR. */
    adapter->abort_pending = 0;
    return result;
}
