#include "ocnext/a64.h"
#include "ocnext/a64_adc_carry.h"
#include "ocnext/a64_divbit.h"
#include "ocnext/a64_multiply.h"
#include "ocnext/a64_ldra.h"
#include "ocnext/a64_atomic.h"
#include "ocnext/a64_fp_control.h"
#include "ocnext/a64_fmov.h"
#include "ocnext/a64_simd_integer.h"
#include "ocnext/a64_simd_ext.h"
#include "ocnext/pac_pointer.h"
#include "ocnext/pac_qarma5.h"
#include "ocnext/a64_sysreg.h"

_Static_assert(sizeof(struct ocnext_a64_cpu) == OCNEXT_A64_CPU_BYTES, "CPU ABI12 size");
_Static_assert(offsetof(struct ocnext_a64_cpu, system) == 328, "CPU system offset unchanged by ext_state");
_Static_assert(offsetof(struct ocnext_a64_cpu, pac) == 512, "CPU PAC append offset");
_Static_assert(sizeof(struct ocnext_a64_pac_registers) == 112, "CPU PAC bank ABI2");
_Static_assert(offsetof(struct ocnext_a64_cpu, fp) == 624, "CPU FP append offset");
_Static_assert(sizeof(struct ocnext_a64_fp_registers) == 32, "CPU FP bank ABI1");
_Static_assert(offsetof(struct ocnext_a64_fp_registers, known_mask) == 24, "CPU FP knowledge offset");
_Static_assert(offsetof(struct ocnext_a64_fp_registers, abi_version) == 28, "CPU FP ABI offset");
_Static_assert(offsetof(struct ocnext_a64_cpu, vector) == 656, "CPU vector append offset");
_Static_assert(sizeof(struct ocnext_a64_vector_registers) == 592, "CPU vector bank ABI1");
_Static_assert(_Alignof(struct ocnext_a64_cpu) == 16, "CPU vector alignment");

struct transaction {
    uint64_t next_pc;
    uint64_t value[4];
    uint8_t reg[4];
    uint8_t sp_write[4];
    unsigned count;
    uint32_t nzcv;
    uint8_t set_flags;
    uint8_t halt;
    uint16_t halt_immediate;
    uint8_t set_os_lock;
    uint8_t os_lock;
    uint8_t set_daif;
    uint32_t daif;
    uint8_t ext_set;
    uint64_t ext_value;
    unsigned sysreg;
    uint64_t system_value;
    uint8_t set_spsel;
    uint8_t spsel;
    uint32_t mmu_register;
    uint32_t tls_register;
    uint8_t branch;
    uint32_t pac_half;
    uint8_t set_fp;
    struct ocnext_a64_fp_registers fp_after;
    unsigned vector_count;
    uint8_t vector_reg[4];
    uint8_t vector_bytes[4][16];
    uint16_t vector_known[4];
};

enum staged_system_register { SYS_NONE, SYS_VBAR, SYS_ESR, SYS_FAR, SYS_ELR, SYS_SPSR, SYS_SP_EL0 };

static int sync_profile(const struct ocnext_a64_cpu *cpu)
{
    return cpu->system.profile == OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC;
}

/* The SYNC-profile SCTLR policy selector lives in system.reserved (0 = BASE,
 * SCTLR_PROFILE_APPLE_BYTE = APPLE); reserved_access/reserved_sync belong to
 * the PAR_EL1 pack above. Any other byte value is rejected as before. */
#define SCTLR_PROFILE_APPLE_BYTE 0x80u
static int sctlr_profile_valid(unsigned byte)
{
    return byte == 0 || byte == SCTLR_PROFILE_APPLE_BYTE;
}

static unsigned sctlr_profile(const struct ocnext_a64_cpu *cpu)
{
    return cpu->system.reserved == SCTLR_PROFILE_APPLE_BYTE ? OCNEXT_A64_SCTLR_PROFILE_APPLE
                                                           : OCNEXT_A64_SCTLR_PROFILE_BASE;
}

static int valid_system(const struct ocnext_a64_cpu *cpu);

#define SYSREG_BINDINGS 8u
struct sysreg_binding { const struct ocnext_a64_memory *memory; ocnext_a64_sysreg_fn fn; void *context; };
static struct sysreg_binding sysreg_bindings[SYSREG_BINDINGS];

static const struct sysreg_binding *find_sysreg_binding(const struct ocnext_a64_memory *memory)
{
    unsigned i;
    for (i = 0; i < SYSREG_BINDINGS; ++i)
        if (sysreg_bindings[i].fn && sysreg_bindings[i].memory == memory) return &sysreg_bindings[i];
    return 0;
}

int ocnext_a64_memory_bind_sysreg(const struct ocnext_a64_memory *memory,
                                  ocnext_a64_sysreg_fn fn, void *context)
{
    unsigned i, free_slot = SYSREG_BINDINGS;
    if (!memory) return -1;
    for (i = 0; i < SYSREG_BINDINGS; ++i) {
        if (sysreg_bindings[i].fn && sysreg_bindings[i].memory == memory) { free_slot = i; break; }
        if (!sysreg_bindings[i].fn && free_slot == SYSREG_BINDINGS) free_slot = i;
    }
    if (free_slot == SYSREG_BINDINGS) return -1;
    sysreg_bindings[free_slot].memory = fn ? memory : 0;
    sysreg_bindings[free_slot].fn = fn;
    sysreg_bindings[free_slot].context = fn ? context : 0;
    return 0;
}

static int mmu_value_supported(uint32_t id, uint64_t value, unsigned pac_profile, unsigned sctlr_profile)
{
    unsigned i;
    if (id == OCNEXT_A64_MMU_KNOWN_TCR)
        return !(value & ~OCNEXT_A64_TCR_SUPPORTED_MASK) && ((value >> 32) & 7u) <= 5u;
    if (id == OCNEXT_A64_MMU_KNOWN_TTBR0 || id == OCNEXT_A64_MMU_KNOWN_TTBR1)
        return !(value & UINT64_C(63)); /* No CnP; minimum base alignment64. */
    if (id == OCNEXT_A64_MMU_KNOWN_SCTLR && sctlr_profile == OCNEXT_A64_SCTLR_PROFILE_APPLE) {
        uint64_t canonical;
        /* A stored/configured value must already be canonical (RES1 set,
         * write-ignored bits clear); writes are canonicalised by the caller. */
        return ocnext_a64_sctlr_apple_write(value, pac_profile, &canonical, 0, 0) ==
                   OCNEXT_A64_SCTLR_OK && canonical == value;
    }
    if (id == OCNEXT_A64_MMU_KNOWN_SCTLR)
        return !(value & ~(OCNEXT_A64_SCTLR_RES1 | OCNEXT_A64_SCTLR_DYNAMIC_MASK |
                           (pac_profile ? OCNEXT_A64_SCTLR_PAC_ENABLE_MASK : 0))) &&
               (value & OCNEXT_A64_SCTLR_RES1) == OCNEXT_A64_SCTLR_RES1;
    if (id != OCNEXT_A64_MMU_KNOWN_MAIR) return 0;
    for (i = 0; i < 8; ++i) {
        unsigned attribute = (unsigned)((value >> (8u * i)) & 255u);
        if (!(attribute & 240u)) {
            if (attribute & 3u) return 0; /* Base Device encoding, no FEAT_XS. */
        } else if (!(attribute & 15u)) return 0; /* No XS/Tagged Normal. */
    }
    return 1;
}

static uint64_t mmu_register_value(const struct ocnext_a64_mmu_registers *bank, uint32_t id)
{
    if (id == OCNEXT_A64_MMU_KNOWN_TCR) return bank->tcr_el1;
    if (id == OCNEXT_A64_MMU_KNOWN_TTBR0) return bank->ttbr0_el1;
    if (id == OCNEXT_A64_MMU_KNOWN_TTBR1) return bank->ttbr1_el1;
    if (id == OCNEXT_A64_MMU_KNOWN_SCTLR) return bank->sctlr_el1;
    return bank->mair_el1;
}

static int valid_mmu_bank(const struct ocnext_a64_mmu_registers *bank, unsigned pac_profile, unsigned sctlr_profile)
{
    uint32_t id;
    if (bank->reserved || (bank->known_mask & ~OCNEXT_A64_MMU_KNOWN_ALL)) return 0;
    for (id = 1; id <= OCNEXT_A64_MMU_KNOWN_MAIR; id <<= 1) {
        uint64_t value = mmu_register_value(bank, id);
        if (bank->known_mask & id) {
            if (!mmu_value_supported(id, value, pac_profile, sctlr_profile)) return 0;
        } else if (value) return 0;
    }
    return 1;
}

static void clear_mmu_bank(struct ocnext_a64_mmu_registers *bank)
{
    bank->tcr_el1 = bank->ttbr0_el1 = bank->ttbr1_el1 = 0;
    bank->sctlr_el1 = bank->mair_el1 = 0;
    bank->known_mask = bank->reserved = 0;
}

static int valid_tls_bank(const struct ocnext_a64_tls_registers *bank)
{
    return !(bank->known_mask & ~OCNEXT_A64_TLS_KNOWN_ALL) && !bank->reserved &&
           ((bank->known_mask & OCNEXT_A64_TLS_KNOWN_EL0) || !bank->tpidr_el0) &&
           ((bank->known_mask & OCNEXT_A64_TLS_KNOWN_RO_EL0) || !bank->tpidrro_el0) &&
           ((bank->known_mask & OCNEXT_A64_TLS_KNOWN_EL1) || !bank->tpidr_el1);
}

static void clear_tls_bank(struct ocnext_a64_tls_registers *bank)
{
    bank->tpidr_el0 = bank->tpidrro_el0 = bank->tpidr_el1 = 0;
    bank->known_mask = bank->reserved = 0;
}

static int valid_feature_bank(const struct ocnext_a64_feature_registers *bank)
{
    return !bank->reserved && !(bank->known_mask & ~OCNEXT_A64_FEATURE_KNOWN_MMFR0) &&
           (bank->known_mask ? bank->id_aa64mmfr0_el1 == OCNEXT_A64_MMFR0_S1_PA48_ASID16 :
                               bank->id_aa64mmfr0_el1 == 0);
}

static void clear_feature_bank(struct ocnext_a64_feature_registers *bank)
{
    bank->id_aa64mmfr0_el1 = 0;
    bank->known_mask = bank->reserved = 0;
}

static int valid_pac_bank(const struct ocnext_a64_pac_registers *bank)
{
    unsigned i;
    if (bank->abi_version != OCNEXT_A64_PAC_REGISTERS_ABI_VERSION ||
        (bank->half_known_mask & ~OCNEXT_A64_PAC_HALF_KNOWN_ALL) ||
        bank->pointer_profile > OCNEXT_A64_PAC_PAUTH1 ||
        bank->combined_mode > OCNEXT_A64_PAC_COMBINED_FPAC) return 0;
    if (!bank->pointer_profile && (bank->owner_id || bank->write_epoch || bank->half_known_mask || bank->combined_mode)) return 0;
    if ((bank->pointer_profile == OCNEXT_A64_PAC_PAUTH2 || bank->pointer_profile == OCNEXT_A64_PAC_PAUTH1) &&
        bank->combined_mode == OCNEXT_A64_PAC_COMBINED_FPAC) return 0;
    if (bank->pointer_profile && (!bank->owner_id || !bank->write_epoch)) return 0;
    for (i = 0; i < OCNEXT_PAC_KEY_COUNT; ++i) {
        if (!(bank->half_known_mask & (1u << (2u*i))) && bank->keys[i].lo) return 0;
        if (!(bank->half_known_mask & (2u << (2u*i))) && bank->keys[i].hi) return 0;
    }
    return 1;
}

static void clear_pac_bank(struct ocnext_a64_pac_registers *bank)
{
    unsigned i;
    for (i = 0; i < OCNEXT_PAC_KEY_COUNT; ++i) bank->keys[i].lo = bank->keys[i].hi = 0;
    bank->owner_id = bank->write_epoch = 0;
    bank->pointer_profile = bank->half_known_mask = bank->combined_mode = 0;
    bank->abi_version = OCNEXT_A64_PAC_REGISTERS_ABI_VERSION;
}

/* Geometry is explicitly known TCR state. Disabled PAC never calls this.
 * XPAC uses the geometry directly without a fabricated/native key bank. */
static int pac_geometry(const struct ocnext_a64_cpu *cpu, struct ocnext_pac_pointer_config *out)
{
    uint64_t tcr;
    unsigned i;
    if (!(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_TCR)) return 0;
    tcr = cpu->system.mmu.tcr_el1;
    out->abi_version = OCNEXT_PAC_POINTER_ABI_VERSION;
    out->profile = cpu->pac.pointer_profile;
    out->reserved[0] = out->reserved[1] = 0;
    for (i = 0; i < 2; ++i) {
        unsigned size = (unsigned)((tcr >> (i ? 16 : 0)) & 63u);
        if (size < 16 || size > 39) return 0;
        out->va_bits[i] = (uint8_t)(64u-size);
        out->tbi[i] = (uint8_t)((tcr >> (i ? 38 : 37)) & 1u);
        out->tbid[i] = (uint8_t)((tcr >> (i ? 52 : 51)) & 1u);
    }
    return 1;
}

static int pac_key_known(const struct ocnext_a64_cpu *cpu, unsigned key)
{
    uint32_t mask = 3u << (2u*key);
    return (cpu->pac.half_known_mask & mask) == mask;
}

static void pac_native_snapshot(const struct ocnext_a64_cpu *cpu, struct ocnext_pac_key_bank *bank)
{
    unsigned i;
    bank->generation = cpu->pac.write_epoch;
    bank->owner_id = cpu->pac.owner_id;
    bank->profile = OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC;
    bank->known_mask = 0;
    bank->abi_version = OCNEXT_PAC_KEYS_ABI_VERSION;
    bank->reserved = 0;
    for (i = 0; i < OCNEXT_PAC_KEY_COUNT; ++i) {
        if (pac_key_known(cpu, i)) { bank->keys[i] = cpu->pac.keys[i]; bank->known_mask |= 1u << i; }
        else bank->keys[i].lo = bank->keys[i].hi = 0;
    }
}

static unsigned pac_half_identity(uint32_t op)
{
    static const uint32_t identities[10] = {
        UINT32_C(0xd5182100), UINT32_C(0xd5182120), UINT32_C(0xd5182140), UINT32_C(0xd5182160),
        UINT32_C(0xd5182200), UINT32_C(0xd5182220), UINT32_C(0xd5182240), UINT32_C(0xd5182260),
        UINT32_C(0xd5182300), UINT32_C(0xd5182320)
    };
    unsigned i;
    for (i = 0; i < 10; ++i) if ((op & UINT32_C(0xffdfffe0)) == identities[i]) return i+1;
    return 0;
}

/* Known EL1&0 TCR address controls only. The partial TBID control profile
 * does not advertise PAC keys/signing. Branch targets are normalized before
 * becoming PC, even with M=0; data addresses and actual raw FAR stay intact. */
static uint64_t instruction_address(const struct ocnext_a64_cpu *cpu, uint64_t raw)
{
    uint64_t tcr;
    unsigned region;
    if (!sync_profile(cpu) || !(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_TCR)) return raw;
    tcr = cpu->system.mmu.tcr_el1;
    region = (unsigned)((raw >> 55) & 1u);
    if ((tcr & (UINT64_C(1) << (region ? 38 : 37))) &&
        !(tcr & (UINT64_C(1) << (region ? 52 : 51))))
        return (raw & UINT64_C(0x00ffffffffffffff)) |
               (region ? UINT64_C(0xff00000000000000) : 0);
    return raw;
}

static void save_sp_bank(struct ocnext_a64_cpu *cpu)
{
    if (!sync_profile(cpu)) return;
    if (cpu->system.current_el == 0 || !cpu->system.spsel) cpu->system.sp_el0 = cpu->sp;
    else cpu->system.sp_el1 = cpu->sp;
}

static void select_sp(struct ocnext_a64_cpu *cpu, unsigned select)
{
    save_sp_bank(cpu);
    cpu->system.spsel = (uint8_t)select;
    cpu->sp = cpu->system.current_el == 0 || !select ? cpu->system.sp_el0 : cpu->system.sp_el1;
}

static uint64_t mask_for(unsigned width)
{
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
}

static uint64_t sign_extend(uint64_t value, unsigned width)
{
    uint64_t sign = UINT64_C(1) << (width - 1);
    value &= mask_for(width);
    return (value ^ sign) - sign;
}

static uint64_t reg_read(const struct ocnext_a64_cpu *cpu, unsigned reg,
                         unsigned width, int use_sp)
{
    uint64_t value = reg == 31 ? (use_sp ? cpu->sp : 0) : cpu->x[reg];
    return value & mask_for(width);
}

static void stage_write(struct transaction *tx, unsigned reg, uint64_t value,
                        unsigned width, int use_sp)
{
    tx->reg[tx->count] = (uint8_t)reg;
    tx->value[tx->count] = value & mask_for(width);
    tx->sp_write[tx->count] = (uint8_t)(use_sp != 0);
    ++tx->count;
}

static uint64_t shift(uint64_t value, unsigned amount, unsigned width, unsigned kind)
{
    uint64_t mask = mask_for(width);
    value &= mask;
    if (amount == 0) return value;
    if (kind == 0) return (value << amount) & mask;
    if (kind == 1) return value >> amount;
    if (kind == 2) {
        uint64_t result = value >> amount;
        if (value & (UINT64_C(1) << (width - 1)))
            result |= mask & (UINT64_MAX << (width - amount));
        return result;
    }
    return ((value >> amount) | (value << (width - amount))) & mask;
}

static uint32_t arithmetic_flags(uint64_t a, uint64_t b, uint64_t result,
                                 unsigned width, int subtract)
{
    uint64_t sign = UINT64_C(1) << (width - 1);
    uint32_t flags = result == 0 ? OCNEXT_A64_Z : 0;
    if (result & sign) flags |= OCNEXT_A64_N;
    if (subtract) {
        if (a >= b) flags |= OCNEXT_A64_C;
        if ((a ^ b) & (a ^ result) & sign) flags |= OCNEXT_A64_V;
    } else {
        if (width == 64 ? result < a : (a + b) > UINT32_MAX)
            flags |= OCNEXT_A64_C;
        if ((~(a ^ b)) & (a ^ result) & sign) flags |= OCNEXT_A64_V;
    }
    return flags;
}

static int condition_holds(uint32_t flags, unsigned condition)
{
    int n = (flags & OCNEXT_A64_N) != 0;
    int z = (flags & OCNEXT_A64_Z) != 0;
    int c = (flags & OCNEXT_A64_C) != 0;
    int v = (flags & OCNEXT_A64_V) != 0;
    int result;
    switch (condition >> 1) {
    case 0: result = z; break;
    case 1: result = c; break;
    case 2: result = n; break;
    case 3: result = v; break;
    case 4: result = c && !z; break;
    case 5: result = n == v; break;
    case 6: result = !z && n == v; break;
    default: result = 1; break;
    }
    return (condition & 1u) && condition != 15 ? !result : result;
}

static int logical_immediate(uint32_t opcode, unsigned width, uint64_t *result)
{
    unsigned n = (opcode >> 22) & 1u;
    unsigned immr = (opcode >> 16) & 63u;
    unsigned imms = (opcode >> 10) & 63u;
    unsigned encoded = (n << 6) | ((~imms) & 63u);
    unsigned length = 0, element, levels, s, r, offset;
    uint64_t pattern;
    if (width == 32 && n) return 0;
    while (encoded > 1) { encoded >>= 1; ++length; }
    if (length < 1) return 0;
    element = 1u << length;
    if (element > width) return 0;
    levels = element - 1;
    s = imms & levels;
    r = immr & levels;
    if (s == levels) return 0;
    pattern = shift(mask_for(s + 1), r, element, 3);
    *result = 0;
    for (offset = 0; offset < width; offset += element)
        *result |= pattern << offset;
    return 1;
}

static enum ocnext_a64_result fault(struct ocnext_a64_cpu *cpu,
                                    enum ocnext_a64_fault_code code,
                                    enum ocnext_a64_access access,
                                    uint64_t address, uint32_t size, uint32_t opcode)
{
    cpu->fault.code = code;
    cpu->fault.access = access;
    cpu->fault.pc = cpu->pc;
    cpu->fault.address = address;
    cpu->fault.opcode = opcode;
    cpu->fault.access_size = size;
    cpu->fault.syndrome_ec = 0;
    cpu->fault.target_el = 0;
    cpu->fault.has_syndrome = 0;
    cpu->fault.reserved = 0;
    return OCNEXT_A64_FAULTED;
}

static enum ocnext_a64_result system_access_trap(struct ocnext_a64_cpu *cpu, uint32_t op)
{
    enum ocnext_a64_result result = fault(cpu, OCNEXT_A64_FAULT_SYSTEM_ACCESS,
                                         OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    cpu->fault.syndrome_ec = UINT8_C(0x18);
    cpu->fault.target_el = 1;
    cpu->fault.has_syndrome = 1;
    return result;
}

static uint64_t little_read(const uint8_t *bytes, unsigned size)
{
    uint64_t result = 0;
    unsigned index;
    for (index = 0; index < size; ++index)
        result |= (uint64_t)bytes[index] << (index * 8);
    return result;
}

static void little_write(uint8_t *bytes, uint64_t value, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8));
}

static enum ocnext_a64_fault_code memory_transfer(
    struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
    uint64_t address, uint8_t *bytes, unsigned size, unsigned alignment, int load)
{
    if (address > UINT64_MAX - (size - 1u))
        return load ? OCNEXT_A64_FAULT_READ : OCNEXT_A64_FAULT_WRITE;
    if (cpu->strict_data_alignment && (address & (alignment - 1u)))
        return OCNEXT_A64_FAULT_ALIGNMENT;
    if (load) {
        if (!memory->read || memory->read(memory->context, address, bytes, size,
                                         OCNEXT_A64_ACCESS_READ) != 0)
            return OCNEXT_A64_FAULT_READ;
    } else {
        if (!memory->write || memory->write(memory->context, address, bytes, size) != 0)
            return OCNEXT_A64_FAULT_WRITE;
        ocnext_a64_exclusive_clear_overlap(cpu, address, size); /* plain store by this PE */
    }
    return OCNEXT_A64_FAULT_NONE;
}

static void clear_fp_bank(struct ocnext_a64_fp_registers *bank)
{
    bank->cpacr_el1=bank->fpcr=bank->fpsr=0;
    bank->known_mask=0;bank->abi_version=OCNEXT_A64_FP_REGISTERS_ABI_VERSION;
}

static void clear_ext_state(struct ocnext_a64_cpu *cpu)
{
    unsigned i;
    cpu->ext_state = cpu->ext_dczid_bs = cpu->ext_at_active = 0;
    for (i = 0; i < 3; ++i) cpu->system.reserved_access[i] = cpu->system.reserved_sync[i] = 0;
}

static void clear_vector_bank(struct ocnext_a64_vector_registers *bank)
{
    unsigned i,j;
    for(i=0;i<32;++i){for(j=0;j<16;++j)bank->bytes[i][j]=0;bank->known_bytes[i]=0;}
    bank->abi_version=OCNEXT_A64_VECTOR_REGISTERS_ABI_VERSION;
    for(i=0;i<sizeof(bank->reserved);++i)bank->reserved[i]=0;
}

static void stage_vector(struct transaction *tx,unsigned reg,const uint8_t *bytes,unsigned size)
{
    unsigned i,n=tx->vector_count++;
    tx->vector_reg[n]=(uint8_t)reg;
    for(i=0;i<16;++i)tx->vector_bytes[n][i]=i<size?bytes[i]:0;
    tx->vector_known[n]=OCNEXT_A64_VECTOR_KNOWN_ALL;
}

/* Whole image and knowledge are one logical publication. A preserved UNKNOWN
 * low half is not promoted by a known high-half write. The helper validates
 * deterministic unknown storage before this infallible staging operation. */
static void stage_vector_mask(struct transaction *tx,unsigned reg,
                              const uint8_t *bytes,uint16_t known)
{
    unsigned i,n=tx->vector_count++;
    tx->vector_reg[n]=(uint8_t)reg;
    for(i=0;i<16;++i)tx->vector_bytes[n][i]=bytes[i];
    tx->vector_known[n]=known;
}

void ocnext_a64_reset(struct ocnext_a64_cpu *cpu, uint64_t entry_pc, uint64_t sp)
{
    unsigned index;
    if (!cpu) return;
    for (index = 0; index < 31; ++index) cpu->x[index] = 0;
    cpu->sp = sp;
    cpu->pc = entry_pc;
    cpu->retired = 0;
    cpu->nzcv = 0;
    cpu->last_opcode = 0;
    cpu->fault.code = OCNEXT_A64_FAULT_NONE;
    cpu->fault.access = OCNEXT_A64_ACCESS_FETCH;
    cpu->fault.pc = 0;
    cpu->fault.address = 0;
    cpu->fault.opcode = 0;
    cpu->fault.access_size = 0;
    cpu->fault.syndrome_ec = 0;
    cpu->fault.target_el = 0;
    cpu->fault.has_syndrome = 0;
    cpu->fault.reserved = 0;
    cpu->halt_immediate = 0;
    cpu->halted = 0;
    cpu->allow_test_halt = 0;
    cpu->strict_data_alignment = 0;
    cpu->system.profile = OCNEXT_A64_SYSTEM_SCALAR;
    cpu->system.current_el = 0;
    cpu->system.os_lock = 0;
    cpu->system.reserved = 0;
    cpu->system.daif = 0;
    cpu->system.uma = 0;
    for (index = 0; index < 3; ++index) cpu->system.reserved_access[index] = 0;
    cpu->system.sp_el0 = 0;
    cpu->system.sp_el1 = 0;
    cpu->system.vbar_el1 = 0;
    cpu->system.esr_el1 = 0;
    cpu->system.far_el1 = 0;
    cpu->system.elr_el1 = 0;
    cpu->system.spsr_el1 = 0;
    cpu->system.exception_count = 0;
    cpu->system.known_state = 0;
    cpu->system.spsel = 0;
    clear_mmu_bank(&cpu->system.mmu);
    clear_tls_bank(&cpu->system.tls);
    clear_feature_bank(&cpu->system.features);
    clear_pac_bank(&cpu->pac);
    clear_fp_bank(&cpu->fp);
    clear_vector_bank(&cpu->vector);
    clear_ext_state(cpu);
}

int ocnext_a64_configure_system(struct ocnext_a64_cpu *cpu,
                               enum ocnext_a64_system_profile profile,
                               unsigned current_el)
{
    if (!cpu || cpu->retired || cpu->system.exception_count || cpu->halted || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        current_el > 1 || (profile != OCNEXT_A64_SYSTEM_SCALAR &&
                          profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_DEBUG &&
                          profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC) ||
        (profile == OCNEXT_A64_SYSTEM_SCALAR && current_el != 0)) return -1;
    cpu->system.profile = (uint8_t)profile;
    cpu->system.current_el = (uint8_t)current_el;
    cpu->system.os_lock = (uint8_t)(profile != OCNEXT_A64_SYSTEM_SCALAR);
    cpu->system.reserved = 0;
    cpu->system.daif = profile != OCNEXT_A64_SYSTEM_SCALAR ? OCNEXT_A64_DAIF_MASK : 0;
    cpu->system.uma = 0;
    cpu->system.reserved_access[0] = 0;
    cpu->system.reserved_access[1] = 0;
    cpu->system.reserved_access[2] = 0;
    cpu->system.spsel = (uint8_t)(profile == OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC && current_el == 1);
    cpu->system.sp_el0 = current_el == 0 ? cpu->sp : 0;
    cpu->system.sp_el1 = current_el == 1 ? cpu->sp : 0;
    clear_mmu_bank(&cpu->system.mmu);
    clear_tls_bank(&cpu->system.tls);
    clear_feature_bank(&cpu->system.features);
    clear_pac_bank(&cpu->pac);
    clear_fp_bank(&cpu->fp);
    clear_vector_bank(&cpu->vector);
    clear_ext_state(cpu);
    return 0;
}

int ocnext_a64_configure_daif_access(struct ocnext_a64_cpu *cpu,
                                    unsigned uma, uint32_t initial_daif)
{
    if (!cpu || cpu->retired || cpu->system.exception_count || cpu->halted || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        (cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_DEBUG && !sync_profile(cpu)) ||
        uma > 1 || (initial_daif & ~OCNEXT_A64_DAIF_MASK) ||
        ((cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) &&
         uma != (unsigned)((cpu->system.mmu.sctlr_el1 >> 9) & 1u))) return -1;
    cpu->system.uma = (uint8_t)uma;
    cpu->system.daif = initial_daif;
    return 0;
}

int ocnext_a64_configure_banked_sp(struct ocnext_a64_cpu *cpu,
                                  uint64_t sp_el0, uint64_t sp_el1, unsigned spsel)
{
    if (!cpu || cpu->retired || cpu->system.exception_count || cpu->halted ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE || !sync_profile(cpu) ||
        spsel > 1 || (cpu->system.current_el == 0 && spsel)) return -1;
    cpu->system.sp_el0 = sp_el0;
    cpu->system.sp_el1 = sp_el1;
    cpu->system.spsel = (uint8_t)spsel;
    cpu->sp = cpu->system.current_el == 0 || !spsel ? sp_el0 : sp_el1;
    return 0;
}

int ocnext_a64_configure_mmu_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_mmu_registers *bank)
{
    if (!cpu || !bank || !sync_profile(cpu) || !valid_system(cpu) || cpu->retired || cpu->halted ||
        cpu->system.exception_count || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        !valid_mmu_bank(bank, cpu->pac.pointer_profile, sctlr_profile(cpu))) return -1;
    cpu->system.mmu = *bank;
    if (bank->known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)
        cpu->system.uma = (uint8_t)((bank->sctlr_el1 >> 9) & 1u);
    return 0;
}

int ocnext_a64_configure_sctlr_profile(struct ocnext_a64_cpu *cpu, unsigned profile)
{
    if (!cpu || profile > OCNEXT_A64_SCTLR_PROFILE_APPLE || !sync_profile(cpu) || !valid_system(cpu) ||
        cpu->retired || cpu->halted || cpu->system.exception_count ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        (cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)) return -1;
    cpu->system.reserved = (uint8_t)(profile == OCNEXT_A64_SCTLR_PROFILE_APPLE ? SCTLR_PROFILE_APPLE_BYTE : 0);
    return 0;
}

int ocnext_a64_configure_tls_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_tls_registers *bank)
{
    if (!cpu || !bank || !sync_profile(cpu) || !valid_system(cpu) || cpu->retired || cpu->halted ||
        cpu->system.exception_count || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        !valid_tls_bank(bank)) return -1;
    cpu->system.tls = *bank;
    return 0;
}

int ocnext_a64_configure_feature_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_feature_registers *bank)
{
    if (!cpu || !bank || !sync_profile(cpu) || !valid_system(cpu) || cpu->retired || cpu->halted ||
        cpu->system.exception_count || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        !valid_feature_bank(bank)) return -1;
    cpu->system.features = *bank;
    return 0;
}

int ocnext_a64_configure_pac_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_pac_registers *bank)
{
    uintptr_t a = (uintptr_t)cpu, b = (uintptr_t)bank;
    if (!cpu || !bank || a % _Alignof(struct ocnext_a64_cpu) ||
        b % _Alignof(struct ocnext_a64_pac_registers) ||
        sizeof(*cpu) > UINTPTR_MAX-a || sizeof(*bank) > UINTPTR_MAX-b ||
        (a < b+sizeof(*bank) && b < a+sizeof(*cpu))) return -1;
    if (!sync_profile(cpu) || !valid_system(cpu) || cpu->retired || cpu->halted ||
        cpu->system.exception_count || cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        !valid_pac_bank(bank) ||
        (!bank->pointer_profile && (cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) &&
         (cpu->system.mmu.sctlr_el1 & OCNEXT_A64_SCTLR_PAC_ENABLE_MASK))) return -1;
    cpu->pac = *bank;
    return 0;
}

int ocnext_a64_provision_pac_keys(struct ocnext_a64_cpu *cpu,
                                 const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT])
{
    unsigned i;
    if (!cpu || !keys || !sync_profile(cpu) || !valid_system(cpu) || cpu->halted ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE || !cpu->pac.pointer_profile ||
        cpu->pac.half_known_mask || cpu->pac.write_epoch == UINT64_MAX) return -1;
    for (i = 0; i < OCNEXT_PAC_KEY_COUNT; ++i) cpu->pac.keys[i] = keys[i];
    cpu->pac.half_known_mask = OCNEXT_A64_PAC_HALF_KNOWN_ALL;
    ++cpu->pac.write_epoch;
    return 0;
}

int ocnext_a64_configure_fp_registers(struct ocnext_a64_cpu *cpu,
                                     const struct ocnext_a64_fp_registers *bank)
{
    uintptr_t a=(uintptr_t)cpu,b=(uintptr_t)bank;
    if(!cpu||!bank||a%_Alignof(struct ocnext_a64_cpu)||b%_Alignof(struct ocnext_a64_fp_registers)||
       sizeof(*cpu)>UINTPTR_MAX-a||sizeof(*bank)>UINTPTR_MAX-b||
       (a<b+sizeof(*bank)&&b<a+sizeof(*cpu)))return -1;
    if(!sync_profile(cpu)||!valid_system(cpu)||cpu->retired||cpu->halted||cpu->system.exception_count||
       cpu->fault.code!=OCNEXT_A64_FAULT_NONE||!ocnext_a64_fp_control_valid(bank))return -1;
    cpu->fp=*bank;return 0;
}

int ocnext_a64_configure_vector_registers(struct ocnext_a64_cpu *cpu,
                                         const struct ocnext_a64_vector_registers *bank)
{
    uintptr_t a=(uintptr_t)cpu,b=(uintptr_t)bank;
    if(!cpu||!bank||(a&15u)||(b&15u)||sizeof(*cpu)>UINTPTR_MAX-a||sizeof(*bank)>UINTPTR_MAX-b||
       (a<b+sizeof(*bank)&&b<a+sizeof(*cpu)))return -1;
    if(!sync_profile(cpu)||!valid_system(cpu)||cpu->retired||cpu->halted||cpu->system.exception_count||
       cpu->fault.code!=OCNEXT_A64_FAULT_NONE||!ocnext_a64_simd_integer_valid(bank))return -1;
    for(unsigned i=0;i<sizeof(*bank);++i)((uint8_t*)&cpu->vector)[i]=((const uint8_t*)bank)[i];
    return 0;
}

/* PSTATE extension bits as they appear in SPSR_EL1 and in MSR/MRS PAN, UAO,
 * DIT, SSBS (system-register form uses the same bit positions). */
#define PSTATE_PAN  (UINT64_C(1) << 22)
#define PSTATE_UAO  (UINT64_C(1) << 23)
#define PSTATE_DIT  (UINT64_C(1) << 24)
#define PSTATE_SSBS (UINT64_C(1) << 12)
#define PSTATE_EXT_MASK (PSTATE_PAN | PSTATE_UAO | PSTATE_DIT | PSTATE_SSBS)
#define SPSR_SUPPORTED_MASK (UINT64_C(0xf00003df) | PSTATE_EXT_MASK)

/* PAR_EL1 lives in system.reserved_access[0..2] (bits 0..23) and
 * system.reserved_sync[0..2] (bits 24..47) of the CPU. Packed form: bit47=known;
 * F=0: bit0=0, bits2:1=SH, bits10:3=ATTR, bits46:11=PA[47:12];
 * F=1: bit0=1, bits6:1=FST. Both architectural forms additionally have
 * RES1 bit11 (stored implicitly) and everything else RES0/zero here. */
static uint64_t par_packed_load(const struct ocnext_a64_cpu *cpu)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 3; ++i)
        v |= (uint64_t)cpu->system.reserved_access[i] << (8 * i) |
             (uint64_t)cpu->system.reserved_sync[i] << (24 + 8 * i);
    return v;
}

static void par_packed_store(struct ocnext_a64_cpu *cpu, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 3; ++i) {
        cpu->system.reserved_access[i] = (uint8_t)(v >> (8 * i));
        cpu->system.reserved_sync[i] = (uint8_t)(v >> (24 + 8 * i));
    }
}

static uint64_t par_unpack(uint64_t p)
{
    if (p & 1u) return UINT64_C(1) | (((p >> 1) & 63u) << 1) | (UINT64_C(1) << 11);
    return (((p >> 3) & 255u) << 56) | (((p >> 11) & UINT64_C(0xfffffffff)) << 12) |
           (UINT64_C(1) << 11) | (((p >> 1) & 3u) << 7);
}

/* Returns 1 and the packed form if v is exactly a canonical PAR_EL1. */
static int par_pack(uint64_t v, uint64_t *packed)
{
    uint64_t p;
    if (v & 1u) p = 1u | (((v >> 1) & 63u) << 1);
    else p = (((v >> 7) & 3u) << 1) | (((v >> 56) & 255u) << 3) | (((v >> 12) & UINT64_C(0xfffffffff)) << 11);
    p |= UINT64_C(1) << 47;
    *packed = p;
    return par_unpack(p) == v;
}

static int valid_maint(const struct ocnext_a64_cpu *cpu)
{
    uint64_t p = par_packed_load(cpu);
    if (cpu->ext_state & ~OCNEXT_A64_EXT_ALL) return 0;
    if (cpu->ext_at_active != 0) return 0;
    if (cpu->ext_dczid_bs != 0 && (cpu->ext_dczid_bs < 2 || cpu->ext_dczid_bs > 9)) return 0;
    if (!(p >> 47)) return p == 0;
    return (p & 1u) ? !((p >> 7) & UINT64_C(0xffffffffff)) : 1;
}

static uint64_t pstate_ext_bits(const struct ocnext_a64_cpu *cpu)
{
    return ((cpu->ext_state & OCNEXT_A64_EXT_PAN) ? PSTATE_PAN : 0) |
           ((cpu->ext_state & OCNEXT_A64_EXT_UAO) ? PSTATE_UAO : 0) |
           ((cpu->ext_state & OCNEXT_A64_EXT_DIT) ? PSTATE_DIT : 0) |
           ((cpu->ext_state & OCNEXT_A64_EXT_SSBS) ? PSTATE_SSBS : 0);
}

static void ext_set(struct ocnext_a64_cpu *cpu, unsigned mask, int on)
{
    if (on) cpu->ext_state = (uint8_t)(cpu->ext_state | mask);
    else cpu->ext_state = (uint8_t)(cpu->ext_state & ~mask);
}

static void pstate_ext_apply(struct ocnext_a64_cpu *cpu, uint64_t bits)
{
    ext_set(cpu, OCNEXT_A64_EXT_PAN, (bits & PSTATE_PAN) != 0);
    ext_set(cpu, OCNEXT_A64_EXT_UAO, (bits & PSTATE_UAO) != 0);
    ext_set(cpu, OCNEXT_A64_EXT_DIT, (bits & PSTATE_DIT) != 0);
    ext_set(cpu, OCNEXT_A64_EXT_SSBS, (bits & PSTATE_SSBS) != 0);
    if (bits & (PSTATE_PAN | PSTATE_SSBS)) ext_set(cpu, OCNEXT_A64_EXT_TOUCHED, 1);
}

/* Exception entry PSTATE rules for the extension bits (Arm ARM
 * AArch64.TakeException, target EL1): PAN:=1 if SCTLR_EL1.SPAN==0 (else
 * unchanged), UAO:=0, SSBS:=SCTLR_EL1.DSSBS. DIT's entry rule is not modeled:
 * entry with DIT=1 is a deterministic stop. If SCTLR is UNKNOWN and the guest
 * has used PAN/SSBS, SPAN/DSSBS cannot be known: stop rather than guess.
 * Returns 0 and the new bits, or a nonzero unsupported reason. */
static unsigned exception_entry_ext(const struct ocnext_a64_cpu *cpu, uint64_t *bits)
{
    uint64_t ext = pstate_ext_bits(cpu);
    if (cpu->ext_state & OCNEXT_A64_EXT_DIT) return OCNEXT_A64_REASON_DIT_ENTRY;
    ext &= ~PSTATE_UAO;
    if (cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) {
        uint64_t sctlr = cpu->system.mmu.sctlr_el1;
        if (!((sctlr >> 23) & 1u) || (cpu->ext_state & OCNEXT_A64_EXT_SPAN_CLEAR)) ext |= PSTATE_PAN;
        ext = (ext & ~PSTATE_SSBS) |
              ((((sctlr >> 44) & 1u) || (cpu->ext_state & OCNEXT_A64_EXT_DSSBS)) ? PSTATE_SSBS : 0);
    } else if (cpu->ext_state & OCNEXT_A64_EXT_TOUCHED) {
        return OCNEXT_A64_REASON_ENTRY_SCTLR_UNKNOWN;
    }
    *bits = ext;
    return 0;
}

static int valid_system(const struct ocnext_a64_cpu *cpu)
{
    return (cpu->system.profile == OCNEXT_A64_SYSTEM_ARMV8_EL1_DEBUG || sync_profile(cpu)) &&
           cpu->system.current_el <= 1 && cpu->system.os_lock <= 1 &&
           cpu->system.uma <= 1 && !(cpu->system.daif & ~OCNEXT_A64_DAIF_MASK) &&
           sctlr_profile_valid(cpu->system.reserved) &&
           (!sync_profile(cpu) || (cpu->system.spsel <= 1 &&
            !(cpu->system.current_el == 0 && cpu->system.spsel) &&
            valid_pac_bank(&cpu->pac) && ocnext_a64_fp_control_valid(&cpu->fp) &&
            ocnext_a64_simd_integer_valid(&cpu->vector) &&
            valid_mmu_bank(&cpu->system.mmu, cpu->pac.pointer_profile, sctlr_profile(cpu)) && valid_tls_bank(&cpu->system.tls) &&
            valid_feature_bank(&cpu->system.features) && valid_maint(cpu) &&
            (!(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) ||
             cpu->system.uma == (unsigned)((cpu->system.mmu.sctlr_el1 >> 9) & 1u))));
}

static int valid_vbar(uint64_t value)
{
    uint64_t upper = value >> 48;
    return !(value & 2047u) && value <= UINT64_MAX - 2047u &&
           (upper == 0 || upper == 65535u); /* no LVA or tagged vectors */
}

static uint32_t system_iss(uint32_t op)
{
    return ((op >> 21) & 1u) | (((op >> 8) & 15u) << 1) |
           ((op & 31u) << 5) | (((op >> 12) & 15u) << 10) |
           (((op >> 16) & 7u) << 14) | (((op >> 5) & 7u) << 17) |
           (((op >> 19) & 3u) << 20);
}

static int fetch_prospective(const struct ocnext_a64_memory *memory,
                             uint64_t address, uint8_t *bytes, unsigned el,
                             uint64_t pstate)
{
    if (memory->fetch_view)
        return memory->fetch_view(memory->context, address, bytes, 4, el, pstate);
    return memory->read(memory->context, address, bytes, 4, OCNEXT_A64_ACCESS_FETCH);
}

static enum ocnext_a64_result take_exception(struct ocnext_a64_cpu *cpu,
                                       const struct ocnext_a64_memory *memory,
                                       uint32_t op, unsigned ec, uint32_t iss,
                                       uint64_t return_pc, int retire,
                                       uint64_t kind_offset, int set_esr)
{
    uint8_t bytes[4];
    uint64_t offset, vector, saved, ext_bits;
    unsigned ext_reason;
    if (!valid_system(cpu) || !valid_vbar(instruction_address(cpu, cpu->system.vbar_el1)) ||
        !(cpu->system.known_state & OCNEXT_A64_KNOWN_VBAR) || cpu->system.exception_count == UINT64_MAX)
        return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    offset = (cpu->system.current_el == 0 ? UINT64_C(0x400) : cpu->system.spsel ? UINT64_C(0x200) : 0) + kind_offset;
    vector = instruction_address(cpu, cpu->system.vbar_el1 + offset);
    if (fetch_prospective(memory, vector, bytes, 1,
                          (uint64_t)cpu->nzcv | OCNEXT_A64_DAIF_MASK | UINT64_C(5)))
        return fault(cpu, OCNEXT_A64_FAULT_FETCH, OCNEXT_A64_ACCESS_FETCH, vector, 4, op);
    ext_reason = exception_entry_ext(cpu, &ext_bits);
    if (ext_reason) {
        enum ocnext_a64_result stopped = fault(cpu, OCNEXT_A64_FAULT_UNSUPPORTED,
                                               OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        cpu->fault.reserved = (uint8_t)ext_reason;
        return stopped;
    }
    saved = (uint64_t)cpu->nzcv | cpu->system.daif | pstate_ext_bits(cpu) |
            (uint64_t)cpu->system.current_el << 2 | (cpu->system.current_el ? cpu->system.spsel : 0);
    save_sp_bank(cpu);
    ocnext_a64_exclusive_clear(cpu); /* exception entry returns the local monitor to Open */
    cpu->system.elr_el1 = return_pc;
    cpu->system.spsr_el1 = saved;
    if (set_esr) {
        cpu->system.esr_el1 = (uint64_t)ec << 26 | UINT64_C(0x02000000) | iss;
        cpu->system.far_el1 = 0; /* UNKNOWN for these non-address exceptions. */
        cpu->system.known_state = (cpu->system.known_state | OCNEXT_A64_KNOWN_ELR |
                                  OCNEXT_A64_KNOWN_SPSR | OCNEXT_A64_KNOWN_ESR) & ~OCNEXT_A64_KNOWN_FAR;
    } else { /* asynchronous interrupts leave ESR/FAR untouched */
        cpu->system.known_state |= OCNEXT_A64_KNOWN_ELR | OCNEXT_A64_KNOWN_SPSR;
    }
    cpu->system.current_el = 1;
    cpu->system.spsel = 1;
    cpu->sp = cpu->system.sp_el1;
    cpu->system.daif = OCNEXT_A64_DAIF_MASK;
    pstate_ext_apply(cpu, ext_bits);
    cpu->pc = vector;
    ++cpu->system.exception_count;
    if (retire) ++cpu->retired;
    return OCNEXT_A64_EXCEPTION;
}

static enum ocnext_a64_result take_sync(struct ocnext_a64_cpu *cpu,
                                       const struct ocnext_a64_memory *memory,
                                       uint32_t op, unsigned ec, uint32_t iss,
                                       uint64_t return_pc, int retire)
{
    return take_exception(cpu, memory, op, ec, iss, return_pc, retire, 0, 1);
}

enum ocnext_a64_result ocnext_a64_take_async(struct ocnext_a64_cpu *cpu,
                                            const struct ocnext_a64_memory *memory,
                                            enum ocnext_a64_async_kind kind)
{
    uint32_t bit = kind == OCNEXT_A64_ASYNC_FIQ ? UINT32_C(0x40) : UINT32_C(0x80);
    if (!cpu || !memory || !memory->read || (kind != OCNEXT_A64_ASYNC_IRQ && kind != OCNEXT_A64_ASYNC_FIQ) ||
        !sync_profile(cpu) || cpu->halted || cpu->fault.code != OCNEXT_A64_FAULT_NONE)
        return OCNEXT_A64_FAULTED;
    if (cpu->system.daif & bit) return OCNEXT_A64_BUDGET; /* masked: nothing is taken */
    return take_exception(cpu, memory, 0, 0, 0, cpu->pc, 0,
                          kind == OCNEXT_A64_ASYNC_FIQ ? UINT64_C(0x100) : UINT64_C(0x80), 0);
}

static enum ocnext_a64_result undefined_access(struct ocnext_a64_cpu *cpu,
                                              const struct ocnext_a64_memory *memory, uint32_t op)
{
    if (sync_profile(cpu)) return take_sync(cpu, memory, op, 0, 0, cpu->pc, 0);
    return fault(cpu, OCNEXT_A64_FAULT_UNDEFINED, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
}

#include "a64_sysmaint.inc.c"

enum ocnext_a64_result ocnext_a64_deliver_abort(struct ocnext_a64_cpu *cpu,
                                              const struct ocnext_a64_memory *memory,
                                              uint32_t esr, uint64_t far, unsigned far_valid)
{
    unsigned ec = esr >> 26;
    enum ocnext_a64_result result;
    if (!cpu || !memory || !memory->read || !sync_profile(cpu) || !valid_system(cpu) ||
        far_valid > 1 || !(esr & UINT32_C(0x02000000)) ||
        (cpu->fault.code != OCNEXT_A64_FAULT_FETCH && cpu->fault.code != OCNEXT_A64_FAULT_READ &&
         cpu->fault.code != OCNEXT_A64_FAULT_WRITE) ||
        cpu->fault.pc != cpu->pc ||
        (cpu->fault.code == OCNEXT_A64_FAULT_FETCH &&
         (cpu->fault.address != cpu->pc || cpu->fault.access_size != 4 ||
          ec != (cpu->system.current_el ? 0x21u : 0x20u))) ||
        (cpu->fault.code != OCNEXT_A64_FAULT_FETCH &&
         (ec != (cpu->system.current_el ? 0x25u : 0x24u) ||
          (((esr >> 6) & 1u) != (unsigned)(cpu->fault.code == OCNEXT_A64_FAULT_WRITE)))))
        return OCNEXT_A64_FAULTED; /* Input rejection leaves the original fault intact. */
    result = take_sync(cpu, memory, cpu->fault.opcode, ec, esr & UINT32_C(0x01ffffff), cpu->pc, 0);
    if (result == OCNEXT_A64_EXCEPTION) {
        cpu->system.far_el1 = far_valid ? far : 0;
        if (far_valid) cpu->system.known_state |= OCNEXT_A64_KNOWN_FAR;
        cpu->fault.code = OCNEXT_A64_FAULT_NONE;
        cpu->fault.access = OCNEXT_A64_ACCESS_FETCH;
        cpu->fault.pc = cpu->fault.address = 0;
        cpu->fault.opcode = cpu->fault.access_size = 0;
        cpu->fault.syndrome_ec = cpu->fault.target_el = cpu->fault.has_syndrome = cpu->fault.reserved = 0;
    }
    return result;
}

/* Check the ORIGINAL selected SP, before effective offset/writeback and data
 * callbacks. Aligned SP proves the result without inventing SCTLR knowledge.
 * The scalar/debug profiles retain their separate bounded research policy. */
static int stop_sp_alignment(struct ocnext_a64_cpu *cpu,
                             const struct ocnext_a64_memory *memory,
                             uint32_t op,unsigned rn,enum ocnext_a64_result *result)
{
    if (rn != 31 || !sync_profile(cpu)) return 0;
    if (!valid_system(cpu)) {
        *result=fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        return 1;
    }
    if (!(cpu->sp & UINT64_C(15))) return 0;
    if (!(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)) {
        *result=fault(cpu,OCNEXT_A64_FAULT_UNSUPPORTED,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        return 1;
    }
    uint64_t control=cpu->system.current_el ? OCNEXT_A64_SCTLR_SA : OCNEXT_A64_SCTLR_SA0;
    if (!(cpu->system.mmu.sctlr_el1 & control)) return 0;
    *result=take_sync(cpu,memory,op,0x26,0,cpu->pc,0);
    return 1;
}

/* ExtendReg (Arm ARM shared pseudocode): take the low 8/16/32/64 bits of the
 * register, zero- or sign-extend, shift left, truncate to the operand width.
 * Callers validate option and amount; `amount` is at most 4. */
static uint64_t extend_register(uint64_t value, unsigned option, unsigned amount,
                                unsigned width)
{
    unsigned bits = 8u << (option & 3u);
    value &= mask_for(bits);
    if (option & 4u) value = sign_extend(value, bits);
    return (value << amount) & mask_for(width);
}

/* PRFM prefetch operation: type 0b11 and target 0b11 are reserved. The
 * architecturally defined hint has no state effect, but a reserved operation
 * is not silently accepted here. */
static int prefetch_operation_defined(unsigned prfop)
{
    return ((prfop >> 3) & 3u) != 3u && ((prfop >> 1) & 3u) != 3u;
}
#include "a64_more.inc"
#include "a64_simd_ldst.inc"

enum ocnext_a64_result ocnext_a64_step(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory)
{
    return ocnext_a64_step_hooks(cpu, memory, NULL);
}

enum ocnext_a64_result ocnext_a64_step_hooks(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory,
                                      const struct ocnext_a64_hooks *hooks)
{
    uint8_t bytes[32];
    uint32_t op;
    unsigned width, rd, rn, rm, index;
    struct transaction tx;
    struct ocnext_a64_simd_mem_plan mplan; /* a64_simd_ext.c structure loads/stores */
    struct simd_ldst_plan lplan;           /* a64_simd_ldst.inc pair / immediate loads/stores */
    uint8_t mbuf[64];
    int more;
    enum ocnext_a64_result more_result = OCNEXT_A64_FAULTED;
    if (!cpu) return OCNEXT_A64_FAULTED;
    if (cpu->fault.code != OCNEXT_A64_FAULT_NONE) return OCNEXT_A64_FAULTED;
    if (cpu->halted) return OCNEXT_A64_HALTED;
    if (!memory || !memory->read || cpu->retired == UINT64_MAX)
        return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, 0);
    if (cpu->pc & 3u)
        return fault(cpu, OCNEXT_A64_FAULT_ALIGNMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, 0);
    if (cpu->pc > UINT64_MAX - 3 ||
        memory->read(memory->context, cpu->pc, bytes, 4, OCNEXT_A64_ACCESS_FETCH) != 0)
        return fault(cpu, OCNEXT_A64_FAULT_FETCH, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, 0);
    op = (uint32_t)little_read(bytes, 4);
    cpu->last_opcode = op;
    width = (op >> 31) ? 64u : 32u;
    rd = op & 31u;
    rn = (op >> 5) & 31u;
    rm = (op >> 16) & 31u;
    tx.next_pc = cpu->pc + 4;
    tx.count = 0;
    tx.set_flags = 0;
    tx.nzcv = 0;
    tx.halt = 0;
    tx.halt_immediate = 0;
    tx.set_os_lock = 0;
    tx.os_lock = 0;
    tx.set_daif = 0;
    tx.ext_set = 0;
    tx.ext_value = 0;
    tx.daif = 0;
    tx.sysreg = SYS_NONE;
    tx.system_value = 0;
    tx.mmu_register = 0;
    tx.tls_register = 0;
    tx.pac_half = 0;
    tx.set_fp = 0;
    tx.vector_count = 0;
    tx.branch = 0;
    tx.set_spsel = 0;
    tx.spsel = 0;

    if (ocnext_a64_fp_control_decode(op)) {
        struct ocnext_a64_fp_control_request request={.operand=reg_read(cpu,rd,64,0),.opcode=op,
            .current_el=cpu->system.current_el,
            .profile=(hooks&&hooks->fp_traps_unimplemented)?OCNEXT_A64_FP_CONTROL_FPEN_NOTRAP:OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
        struct ocnext_a64_fp_control_effect effect;
        enum ocnext_a64_fp_control_result prepared;
        if(!sync_profile(cpu))goto unsupported;
        if(!valid_system(cpu))return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        prepared=ocnext_a64_fp_control_prepare(&cpu->fp,&request,&effect);
        if(prepared==OCNEXT_A64_FP_CONTROL_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(prepared!=OCNEXT_A64_FP_CONTROL_OK)goto unsupported;
        if(effect.action==OCNEXT_A64_FP_CONTROL_EXCEPTION)
            return take_sync(cpu,memory,op,effect.esr>>26,effect.esr&UINT32_C(0x01ffffff),cpu->pc,0);
        if(effect.action==OCNEXT_A64_FP_CONTROL_READ)stage_write(&tx,rd,effect.value,64,0);
        else if(effect.action==OCNEXT_A64_FP_CONTROL_WRITE){tx.fp_after=effect.bank_after;tx.set_fp=1;}
        else return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
    } else if (ocnext_a64_fmov_decode(op)) {
        unsigned form=ocnext_a64_fmov_decode(op);
        struct ocnext_a64_fmov_request request={
            .gpr_value=(form&1u)?0:reg_read(cpu,rn,64,0),
            .opcode=op,.current_el=cpu->system.current_el,
            .profile=OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
        struct ocnext_a64_fmov_effect effect;
        enum ocnext_a64_fmov_result prepared;
        if(!sync_profile(cpu))goto unsupported;
        if(!valid_system(cpu))return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        prepared=ocnext_a64_fmov_prepare(&cpu->vector,&cpu->fp,&request,&effect);
        if(prepared==OCNEXT_A64_FMOV_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(prepared!=OCNEXT_A64_FMOV_OK)goto unsupported;
        if(effect.action==OCNEXT_A64_FMOV_EXCEPTION)
            return take_sync(cpu,memory,op,effect.esr>>26,effect.esr&UINT32_C(0x01ffffff),cpu->pc,0);
        if(effect.action!=OCNEXT_A64_FMOV_RETIRE)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(effect.vector_write)stage_vector_mask(&tx,effect.vd,effect.vector_after,effect.known_after);
        if(effect.gpr_write)stage_write(&tx,effect.rd,effect.gpr_value,64,0);
    } else if (ocnext_a64_simd_integer_decode(op)) {
        struct ocnext_a64_fp_access_request access={.current_el=cpu->system.current_el,
            .profile=OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
        struct ocnext_a64_fp_access_effect permission;
        struct ocnext_a64_simd_integer_request request={.opcode=op};
        struct ocnext_a64_simd_integer_effect effect;
        enum ocnext_a64_fp_control_result allowed;
        enum ocnext_a64_simd_integer_result prepared;
        if(!sync_profile(cpu))goto unsupported;
        if(!valid_system(cpu))return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        allowed=ocnext_a64_fp_access_prepare(&cpu->fp,&access,&permission);
        if(allowed==OCNEXT_A64_FP_CONTROL_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(allowed!=OCNEXT_A64_FP_CONTROL_OK)goto unsupported;
        if(permission.action==OCNEXT_A64_FP_ACCESS_EXCEPTION)
            return take_sync(cpu,memory,op,permission.esr>>26,permission.esr&UINT32_C(0x01ffffff),cpu->pc,0);
        if(permission.action!=OCNEXT_A64_FP_ACCESS_ALLOWED)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        prepared=ocnext_a64_simd_integer_prepare(&cpu->vector,&request,&effect);
        if(prepared==OCNEXT_A64_SIMD_INTEGER_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(prepared!=OCNEXT_A64_SIMD_INTEGER_OK)goto unsupported;
        stage_vector_mask(&tx,effect.destination,effect.bytes,effect.known_bytes);
    } else if ((op & UINT32_C(0x0e000000)) == UINT32_C(0x0e000000) && ocnext_a64_simd_ext_decode(op)) {
        /* Register-only Advanced SIMD / scalar FP subset (a64_simd_ext.c).
         * Same FPEN access rule as the integer SIMD path; any source byte
         * with unknown value stops as unsupported, never guessed. */
        struct ocnext_a64_fp_access_request access={.current_el=cpu->system.current_el,
            .profile=OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
        struct ocnext_a64_fp_access_effect permission;
        struct ocnext_a64_simd_ext_request request={.opcode=op,.gpr_value=reg_read(cpu,rn,64,0),
            .fpcr=cpu->fp.fpcr,.nzcv=cpu->nzcv,
            .fpcr_known=(uint8_t)((cpu->fp.known_mask&OCNEXT_A64_FP_KNOWN_FPCR)!=0)};
        struct ocnext_a64_simd_ext_effect effect;
        enum ocnext_a64_fp_control_result allowed;
        enum ocnext_a64_simd_ext_result prepared;
        if(!sync_profile(cpu))goto unsupported;
        if(!valid_system(cpu))return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        allowed=ocnext_a64_fp_access_prepare(&cpu->fp,&access,&permission);
        if(allowed==OCNEXT_A64_FP_CONTROL_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(allowed!=OCNEXT_A64_FP_CONTROL_OK)goto unsupported;
        if(permission.action==OCNEXT_A64_FP_ACCESS_EXCEPTION)
            return take_sync(cpu,memory,op,permission.esr>>26,permission.esr&UINT32_C(0x01ffffff),cpu->pc,0);
        if(permission.action!=OCNEXT_A64_FP_ACCESS_ALLOWED)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        prepared=ocnext_a64_simd_ext_prepare(&cpu->vector,&request,&effect);
        if(prepared==OCNEXT_A64_SIMD_EXT_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(prepared!=OCNEXT_A64_SIMD_EXT_OK)goto unsupported;
        if(effect.qc){
            /* A saturation must be recorded in FPSR.QC; with FPSR unknown the
             * architectural result cannot be produced, so stop instead. */
            if(!(cpu->fp.known_mask&OCNEXT_A64_FP_KNOWN_FPSR))goto unsupported;
            tx.fp_after=cpu->fp;tx.fp_after.fpsr|=UINT64_C(1)<<27;tx.set_fp=1;
        }
        if(effect.fp_flags){
            /* Exception flags are cumulative FPSR state: with FPSR unknown the
             * architectural result cannot be produced, so stop. */
            if(!(cpu->fp.known_mask&OCNEXT_A64_FP_KNOWN_FPSR))goto unsupported;
            if(!effect.qc)tx.fp_after=cpu->fp;
            tx.fp_after.fpsr|=effect.fp_flags;tx.set_fp=1;
        }
        if(effect.nzcv_write){tx.set_flags=1;tx.nzcv=effect.nzcv;}
        if(effect.vector_write)stage_vector_mask(&tx,effect.destination,effect.bytes,effect.known_bytes);
        if(effect.gpr_write)stage_write(&tx,effect.gpr_rd,effect.gpr_value,64,0);
    } else if ((op & UINT32_C(0x0c000000)) == UINT32_C(0x0c000000) && ocnext_a64_simd_mem_decode(op,&mplan)) {
        /* Advanced SIMD structure loads/stores, SIMD&FP register-offset and
         * literal loads. Same FPEN rule as the other SIMD paths; the whole
         * transfer is one memory transaction, so a fault commits nothing. */
        struct ocnext_a64_fp_access_request access={.current_el=cpu->system.current_el,
            .profile=OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
        struct ocnext_a64_fp_access_effect permission;
        struct ocnext_a64_simd_mem_dest dest[4];
        enum ocnext_a64_fp_control_result allowed;
        enum ocnext_a64_fault_code code;
        enum ocnext_a64_result stopped;
        uint64_t base,address;
        unsigned ndest,k;
        if(!sync_profile(cpu))goto unsupported;
        if(!valid_system(cpu))return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        allowed=ocnext_a64_fp_access_prepare(&cpu->fp,&access,&permission);
        if(allowed==OCNEXT_A64_FP_CONTROL_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(allowed!=OCNEXT_A64_FP_CONTROL_OK)goto unsupported;
        if(permission.action==OCNEXT_A64_FP_ACCESS_EXCEPTION)
            return take_sync(cpu,memory,op,permission.esr>>26,permission.esr&UINT32_C(0x01ffffff),cpu->pc,0);
        if(permission.action!=OCNEXT_A64_FP_ACCESS_ALLOWED)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if(mplan.form==OCNEXT_A64_SIMD_MEM_LITERAL){
            base=0;address=cpu->pc+(uint64_t)mplan.literal;
        }else{
            if(stop_sp_alignment(cpu,memory,op,mplan.rn,&stopped))return stopped;
            base=reg_read(cpu,mplan.rn,64,1);
            address=mplan.form==OCNEXT_A64_SIMD_MEM_REGOFF?
                base+ocnext_a64_simd_mem_offset(&mplan,reg_read(cpu,mplan.rm,64,0)):base;
        }
        if(!mplan.load&&simd_mem_gather_policy(cpu,hooks,&mplan,mbuf)!=0)
            goto unsupported;
        code=memory_transfer(cpu,memory,address,mbuf,mplan.bytes,mplan.esize,mplan.load);
        if(code!=OCNEXT_A64_FAULT_NONE)
            return fault(cpu,code,mplan.load?OCNEXT_A64_ACCESS_READ:OCNEXT_A64_ACCESS_WRITE,
                         address,mplan.bytes,op);
        if(mplan.load){
            if(ocnext_a64_simd_mem_scatter(&cpu->vector,&mplan,mbuf,dest,&ndest)!=OCNEXT_A64_SIMD_EXT_OK)
                return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
            for(k=0;k<ndest;++k)stage_vector_mask(&tx,dest[k].reg,dest[k].bytes,dest[k].known_bytes);
        }
        if(mplan.wb)
            stage_write(&tx,mplan.rn,base+(mplan.wb==1?(uint64_t)mplan.bytes:reg_read(cpu,mplan.rm,64,0)),64,1);
    } else if (pac_half_identity(op)) {
        unsigned half = pac_half_identity(op)-1u, key = half/2u;
        uint32_t bit = 1u << half;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        /* EL0 is UNDEFINED before any half-knowledge/profile lookup. */
        if (!cpu->system.current_el) return undefined_access(cpu, memory, op);
        if (!cpu->pac.pointer_profile) goto unsupported;
        if ((op >> 21) & 1u) {
            if (!(cpu->pac.half_known_mask & bit)) goto unsupported;
            stage_write(&tx, rd, half & 1u ? cpu->pac.keys[key].hi : cpu->pac.keys[key].lo, 64, 0);
        } else {
            if (cpu->pac.write_epoch == UINT64_MAX) goto unsupported;
            tx.pac_half = half+1u; tx.system_value = reg_read(cpu, rd, 64, 0);
        }
    } else if (op == UINT32_C(0xd65f0bff) || op == UINT32_C(0xd65f0fff) ||
               (op & UINT32_C(0xfffff800)) == UINT32_C(0xd71f0800) ||
               (op & UINT32_C(0xfffff800)) == UINT32_C(0xd73f0800) ||
               (op & UINT32_C(0xfffff81f)) == UINT32_C(0xd61f081f) ||
               (op & UINT32_C(0xfffff81f)) == UINT32_C(0xd63f081f)) {
        unsigned key = (op >> 10) & 1u;
        int is_return = op == UINT32_C(0xd65f0bff) || op == UINT32_C(0xd65f0fff);
        int link = !is_return && (op & UINT32_C(0x00200000));
        uint64_t target = is_return ? cpu->x[30] : reg_read(cpu, rn, 64, 0);
        uint64_t modifier = is_return ? cpu->sp :
            ((op & UINT32_C(0x01000000)) ? reg_read(cpu, op & 31u, 64, 1) : 0);
        struct ocnext_pac_pointer_config geometry;
        struct ocnext_pac_key_bank bank;
        struct ocnext_pac_pointer_request request = {0};
        struct ocnext_pac_pointer_output out;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (!cpu->pac.pointer_profile || !(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)) goto unsupported;
        /* Disabled instruction keys resolve before combined-mode, geometry or
         * key knowledge. Both source operands (including X30 aliases) are old
         * values; authentication and vector preflight precede any LR commit. */
        if ((cpu->system.mmu.sctlr_el1 >> (key ? 30 : 31)) & 1u) {
            if (!cpu->pac.combined_mode || !pac_geometry(cpu, &geometry) || !pac_key_known(cpu, key)) goto unsupported;
            geometry.profile = cpu->pac.pointer_profile == OCNEXT_A64_PAC_PAUTH1 ?
                OCNEXT_PAC_POINTER_QARMA5_PAUTH1 :
                cpu->pac.combined_mode == OCNEXT_A64_PAC_COMBINED_FPAC ?
                OCNEXT_PAC_POINTER_QARMA5_FPAC : OCNEXT_PAC_POINTER_QARMA5_PAUTH2;
            pac_native_snapshot(cpu, &bank);
            request.pointer = target; request.modifier = modifier;
            request.owner_id = cpu->pac.owner_id; request.generation = cpu->pac.write_epoch;
            request.operation = OCNEXT_PAC_POINTER_AUTH; request.key_index = key;
            request.current_el = cpu->system.current_el; request.key_enabled = 1;
            if (ocnext_pac_pointer_execute(&bank, &geometry, &request, &out) != OCNEXT_PAC_POINTER_OK) goto unsupported;
            if (out.outcome == OCNEXT_PAC_POINTER_AUTH_EXCEPTION)
                return take_sync(cpu, memory, op, 0x1c, (uint32_t)out.esr & UINT32_C(0x01ffffff), cpu->pc, 0);
            target = out.pointer;
        }
        /* BranchTo stores the target; a corrupted NoTrap target faults on its
         * subsequent instruction fetch, not as a faulting authentication. */
        tx.branch = 1; tx.next_pc = target;
        if (link) stage_write(&tx, 30, cpu->pc + 4, 64, 0);
    } else if ((op & UINT32_C(0xffffc000)) == UINT32_C(0xdac10000) ||
               (op & UINT32_C(0xfffffbe0)) == UINT32_C(0xdac143e0) ||
               (op & UINT32_C(0xffe0fc00)) == UINT32_C(0x9ac03000) ||
               op == UINT32_C(0xd50320ff) || op == UINT32_C(0xd503211f) ||
               op == UINT32_C(0xd503215f) || op == UINT32_C(0xd503219f) ||
               op == UINT32_C(0xd50321df) || op == UINT32_C(0xd503231f) ||
               op == UINT32_C(0xd503233f) || op == UINT32_C(0xd503235f) ||
               op == UINT32_C(0xd503237f) || op == UINT32_C(0xd503239f) ||
               op == UINT32_C(0xd50323bf) || op == UINT32_C(0xd50323df) ||
               op == UINT32_C(0xd50323ff)) {
        unsigned key = (op >> 10) & 3u, auth = (op >> 12) & 1u, strip = 0, generic = 0;
        uint64_t modifier = 0, value;
        struct ocnext_pac_pointer_config geometry;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (!cpu->pac.pointer_profile) goto unsupported;
        if ((op & UINT32_C(0xffe0fc00)) == UINT32_C(0x9ac03000)) {
            generic = 1; key = OCNEXT_PAC_KEY_GA;
            value = reg_read(cpu, rn, 64, 0); modifier = reg_read(cpu, rm, 64, 1);
        } else {
            if ((op & UINT32_C(0xfffffbe0)) == UINT32_C(0xdac143e0)) { strip = 1; key = (op & 1024u) ? 2u : 0u; }
            else if (op == UINT32_C(0xd50320ff)) { strip = 1; key = 0; rd = 30; }
            else if ((op & UINT32_C(0xffffc000)) == UINT32_C(0xdac10000)) {
                if (op & UINT32_C(0x2000)) { if (rn != 31) goto unsupported; }
                else modifier = reg_read(cpu, rn, 64, 1);
            } else {
                key = (op >> 6) & 1u; auth = (op >> 7) & 1u;
                if ((op & UINT32_C(0xffffff00)) == UINT32_C(0xd5032100)) { rd = 17; modifier = cpu->x[16]; }
                else { rd = 30; if (op & 32u) modifier = cpu->sp; }
            }
            value = reg_read(cpu, rd, 64, 0);
        }
        if (generic) {
            if (!pac_key_known(cpu, key)) goto unsupported;
            value = ocnext_pac_qarma5_mac(value, modifier, cpu->pac.keys[key].lo,
                                        cpu->pac.keys[key].hi) & UINT64_C(0xffffffff00000000);
        } else if (strip) {
            unsigned region, width_pac, tagged;
            uint64_t extension;
            if (!pac_geometry(cpu, &geometry)) goto unsupported;
            region = (unsigned)((value >> 55) & 1u); width_pac = geometry.va_bits[region];
            tagged = geometry.tbi[region] && ((key & 2u) || !geometry.tbid[region]);
            extension = UINT64_MAX << width_pac;
            if (tagged) extension &= UINT64_C(0x00ffffffffffffff);
            value = (value & ~extension) | (region ? extension : 0);
        } else {
            static const unsigned enable_bits[4] = {31, 30, 27, 13};
            struct ocnext_pac_key_bank bank;
            struct ocnext_pac_pointer_request request = {0};
            struct ocnext_pac_pointer_output out;
            if (!(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR)) goto unsupported;
            /* A known disabled key returns the original pointer before TCR,
             * UNKNOWN halves, MAC/native authority, or higher-EL traps. */
            if ((cpu->system.mmu.sctlr_el1 >> enable_bits[key]) & 1u) {
                if (!pac_geometry(cpu, &geometry) || !pac_key_known(cpu, key)) goto unsupported;
                pac_native_snapshot(cpu, &bank);
                request.pointer = value; request.modifier = modifier;
                request.owner_id = cpu->pac.owner_id; request.generation = cpu->pac.write_epoch;
                request.operation = auth ? OCNEXT_PAC_POINTER_AUTH : OCNEXT_PAC_POINTER_SIGN;
                request.key_index = key; request.current_el = cpu->system.current_el; request.key_enabled = 1;
                if (ocnext_pac_pointer_execute(&bank, &geometry, &request, &out) != OCNEXT_PAC_POINTER_OK) goto unsupported;
                if (out.outcome == OCNEXT_PAC_POINTER_AUTH_EXCEPTION)
                    return take_sync(cpu, memory, op, 0x1c, (uint32_t)out.esr & UINT32_C(0x01ffffff), cpu->pc, 0);
                value = out.pointer;
            }
        }
        stage_write(&tx, rd, value, 64, 0);
    } else if (ocnext_a64_mul_decode(op)) {
        struct ocnext_a64_mul_request request = {0};
        struct ocnext_a64_mul_effect effect;
        enum ocnext_a64_mul_status status;
        request.abi_version = OCNEXT_A64_MUL_ABI;
        request.opcode = op;
        /* Snapshot whole old software GPRs. The helper applies RN/RM32 and
         * RA64 for long forms and validates aliases at common read width.
         * Register31 is ZR here, never SP; high Ra31 is inactive. */
        request.rn_value = reg_read(cpu, rn, 64, 0);
        request.rm_value = reg_read(cpu, rm, 64, 0);
        request.ra_value = reg_read(cpu, (op >> 10) & 31u, 64, 0);
        request.nzcv = cpu->nzcv;
        request.operand_known = OCNEXT_A64_MUL_KNOWN_ALL;
        request.nzcv_known = 15u; /* CPU12 complete scalar software state. */
        status = ocnext_a64_mul_prepare(&request, &effect);
        if (status == OCNEXT_A64_MUL_ARGUMENT)
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (status != OCNEXT_A64_MUL_OK) goto unsupported;
        if (effect.write_gpr)
            stage_write(&tx, effect.destination, effect.result, effect.width, 0);
        /* No SP/NZCV/bank effect and no feature or Apple-state authority. */
    } else if (ocnext_a64_divbit_decode(op)) {
        struct ocnext_a64_divbit_request request = {0};
        struct ocnext_a64_divbit_effect effect;
        enum ocnext_a64_divbit_result status;
        request.abi_version = OCNEXT_A64_DIVBIT_ABI;
        request.opcode = op;
        request.rn_value = reg_read(cpu, rn, width, 0);
        request.rm_value = reg_read(cpu, rm, width, 0);
        request.operand_known = OCNEXT_A64_DIVBIT_KNOWN_RN | OCNEXT_A64_DIVBIT_KNOWN_RM;
        status = ocnext_a64_divbit_prepare(&request, &effect);
        /* This separate native enum orders ARGUMENT/UNSUPPORTED differently
         * from carry. Numeric status reinterpretation is forbidden. */
        if (status == OCNEXT_A64_DIVBIT_ARGUMENT)
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (status != OCNEXT_A64_DIVBIT_OK) goto unsupported;
        if (effect.write_gpr)
            stage_write(&tx, effect.destination, effect.result, effect.width, 0);
        /* The operation has no NZCV or SP effect. */
    } else if (ocnext_a64_adc_decode(op)) {
        struct ocnext_a64_adc_request request = {0};
        struct ocnext_a64_adc_effect effect;
        enum ocnext_a64_adc_status status;
        request.abi_version = OCNEXT_A64_ADC_ABI;
        request.opcode = op;
        request.rn_value = reg_read(cpu, rn, width, 0);
        request.rm_value = reg_read(cpu, rm, width, 0);
        request.nzcv = cpu->nzcv;
        /* CPU12's scalar software state is complete. This adapter supplies
         * that contract explicitly; it issues no Apple initial-state or
         * CPU-feature authority. Both operands snapshot before any write. */
        request.operand_known = OCNEXT_A64_ADC_RN_KNOWN | OCNEXT_A64_ADC_RM_KNOWN;
        request.nzcv_known = OCNEXT_A64_ADC_FLAGS_ALL;
        status = ocnext_a64_adc_prepare(&request, &effect);
        if (status == OCNEXT_A64_ADC_ARGUMENT)
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (status != OCNEXT_A64_ADC_OK) goto unsupported;
        if (effect.write_gpr)
            stage_write(&tx, effect.destination, effect.result, effect.width, 0);
        if (effect.write_nzcv) {
            tx.set_flags = 1;
            tx.nzcv = effect.nzcv;
        }
    } else if ((op & UINT32_C(0x1fe00410)) == UINT32_C(0x1a400000)) {
        /* CCMN/CCMP, immediate (bit 11) and register forms. S must be 1;
         * o2 (bit 10) and o3 (bit 4) must be 0, otherwise unallocated. */
        unsigned condition = (op >> 12) & 15u;
        int subtract = ((op >> 30) & 1u) != 0;
        uint64_t a, b, result;
        if (!((op >> 29) & 1u)) goto unsupported;
        a = reg_read(cpu, rn, width, 0);
        b = (op & (1u << 11)) ? (uint64_t)rm : reg_read(cpu, rm, width, 0);
        tx.set_flags = 1;
        if (condition_holds(cpu->nzcv, condition)) {
            result = (subtract ? a - b : a + b) & mask_for(width);
            tx.nzcv = arithmetic_flags(a, b, result, width, subtract);
        } else {
            tx.nzcv = (op & 15u) << 28;
        }
    } else if ((op & UINT32_C(0x1fe00000)) == UINT32_C(0x0b200000)) {
        /* ADD/ADDS/SUB/SUBS, extended register. opt (23:22) must be 0 and
         * the left shift is at most 4. Rn and a non-flag Rd may be SP. */
        int subtract = ((op >> 30) & 1u) != 0;
        int set_flags = ((op >> 29) & 1u) != 0;
        unsigned amount = (op >> 10) & 7u;
        uint64_t a, b, result;
        if (((op >> 22) & 3u) || amount > 4) goto unsupported;
        a = reg_read(cpu, rn, width, 1);
        b = extend_register(reg_read(cpu, rm, 64, 0), (op >> 13) & 7u, amount, width);
        result = (subtract ? a - b : a + b) & mask_for(width);
        stage_write(&tx, rd, result, width, !set_flags);
        if (set_flags) {
            tx.set_flags = 1;
            tx.nzcv = arithmetic_flags(a, b, result, width, subtract);
        }
    } else if ((op & UINT32_C(0x3f200c00)) == UINT32_C(0x38200800)) {
        /* Integer load/store/PRFM, register offset. option<1> must be 1
         * (UXTW, LSL, SXTW, SXTX); S selects a shift of log2(size). */
        unsigned size_log = op >> 30, opc = (op >> 22) & 3u;
        unsigned option = (op >> 13) & 7u;
        unsigned size = 1u << size_log;
        int load = opc != 0;
        uint64_t base, address, value;
        enum ocnext_a64_fault_code code;
        enum ocnext_a64_result stopped;
        if (!(option & 2u) || (opc == 3 && size_log >= 2)) goto unsupported;
        if (opc == 2 && size_log == 3) { /* PRFM (register): hint, no access */
            if (!prefetch_operation_defined(rd)) goto unsupported;
        } else {
            if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) return stopped;
            base = reg_read(cpu, rn, 64, 1);
            address = base + extend_register(reg_read(cpu, rm, 64, 0), option,
                                             ((op >> 12) & 1u) ? size_log : 0u, 64);
            if (!load) little_write(bytes, reg_read(cpu, rd, size == 8 ? 64 : 32, 0), size);
            code = memory_transfer(cpu, memory, address, bytes, size, size, load);
            if (code != OCNEXT_A64_FAULT_NONE)
                return fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE,
                             address, size, op);
            if (load) {
                value = little_read(bytes, size);
                if (opc >= 2) value = sign_extend(value, size * 8);
                stage_write(&tx, rd, value, opc == 2 || size == 8 ? 64 : 32, 0);
            }
        }
    } else if ((op & UINT32_C(0x3f000000)) == UINT32_C(0x18000000)) {
        /* LDR/LDRSW/PRFM (literal), integer registers only; V=1 literal
         * stays unsupported. Address = PC + SignExtend(imm19:00). */
        unsigned opc = op >> 30;
        uint64_t address = cpu->pc + (sign_extend((op >> 5) & 524287u, 19) << 2);
        uint64_t value;
        unsigned size = opc == 1 ? 8u : 4u;
        enum ocnext_a64_fault_code code;
        if (opc == 3) { /* PRFM (literal): hint, no access */
            if (!prefetch_operation_defined(rd)) goto unsupported;
        } else {
            code = memory_transfer(cpu, memory, address, bytes, size, size, 1);
            if (code != OCNEXT_A64_FAULT_NONE)
                return fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, size, op);
            value = little_read(bytes, size);
            if (opc == 2) value = sign_extend(value, 32);
            stage_write(&tx, rd, value, opc == 0 ? 32 : 64, 0);
        }
    } else if ((op & UINT32_C(0x1f800000)) == UINT32_C(0x12800000)) {
        unsigned opc = (op >> 29) & 3u;
        unsigned amount = ((op >> 21) & 3u) * 16u;
        uint64_t immediate = (uint64_t)((op >> 5) & 65535u) << amount;
        uint64_t value;
        if (opc == 1 || amount >= width) goto unsupported;
        if (opc == 0) value = ~immediate;
        else if (opc == 2) value = immediate;
        else value = (reg_read(cpu, rd, width, 0) & ~(UINT64_C(65535) << amount)) | immediate;
        stage_write(&tx, rd, value, width, 0);
    } else if ((op & UINT32_C(0x1f800000)) == UINT32_C(0x11000000) ||
               (op & UINT32_C(0x1f200000)) == UINT32_C(0x0b000000)) {
        int immediate = (op & UINT32_C(0x1f800000)) == UINT32_C(0x11000000);
        int subtract = ((op >> 30) & 1u) != 0;
        int set_flags = ((op >> 29) & 1u) != 0;
        uint64_t a = reg_read(cpu, rn, width, immediate);
        uint64_t b, result;
        if (immediate) {
            b = (op >> 10) & 4095u;
            if (op & (1u << 22)) b <<= 12;
        } else {
            unsigned kind = (op >> 22) & 3u;
            unsigned amount = (op >> 10) & 63u;
            if (kind == 3 || amount >= width) goto unsupported;
            b = shift(reg_read(cpu, rm, width, 0), amount, width, kind);
        }
        result = (subtract ? a - b : a + b) & mask_for(width);
        stage_write(&tx, rd, result, width, immediate && !set_flags);
        if (set_flags) {
            tx.set_flags = 1;
            tx.nzcv = arithmetic_flags(a, b, result, width, subtract);
        }
    } else if ((op & UINT32_C(0x1f000000)) == UINT32_C(0x0a000000) ||
               (op & UINT32_C(0x1f800000)) == UINT32_C(0x12000000)) {
        int immediate = (op & UINT32_C(0x1f800000)) == UINT32_C(0x12000000);
        unsigned opc = (op >> 29) & 3u;
        uint64_t a = reg_read(cpu, rn, width, 0), b, result;
        if (immediate) {
            if (!logical_immediate(op, width, &b)) goto unsupported;
        } else {
            unsigned amount = (op >> 10) & 63u;
            if (amount >= width) goto unsupported;
            b = shift(reg_read(cpu, rm, width, 0), amount, width, (op >> 22) & 3u);
            if (op & (1u << 21)) b = (~b) & mask_for(width);
        }
        if (opc == 0 || opc == 3) result = a & b;
        else if (opc == 1) result = a | b;
        else result = a ^ b;
        stage_write(&tx, rd, result, width, immediate && opc != 3);
        if (opc == 3) {
            tx.set_flags = 1;
            tx.nzcv = (result == 0 ? OCNEXT_A64_Z : 0) |
                      (result & (UINT64_C(1) << (width - 1)) ? OCNEXT_A64_N : 0);
        }
    } else if ((op & UINT32_C(0x1f800000)) == UINT32_C(0x13000000)) {
        unsigned opc = (op >> 29) & 3u;
        unsigned n = (op >> 22) & 1u;
        unsigned r = (op >> 16) & 63u, s = (op >> 10) & 63u;
        uint64_t src, dst, wmask, tmask, bottom, result;
        if (opc == 3 || n != (width == 64) || r >= width || s >= width)
            goto unsupported;
        /* Allocated bitfield encodings force DecodeBitMasks(FALSE)'s element
         * size to datasize. Unlike logical immediates, all-ones is legal. */
        wmask = shift(mask_for(s + 1), r, width, 3);
        tmask = mask_for(((s - r) & (width - 1u)) + 1u);
        src = reg_read(cpu, rn, width, 0);
        dst = reg_read(cpu, rd, width, 0);
        bottom = shift(src, r, width, 3) & wmask;
        if (opc == 0) { /* SBFM: the original source bit s supplies the sign. */
            uint64_t top = (src & (UINT64_C(1) << s)) ? mask_for(width) : 0;
            result = (top & ~tmask) | (bottom & tmask);
        } else if (opc == 1) { /* BFM: preserve both destination mask regions. */
            bottom |= dst & ~wmask;
            result = (dst & ~tmask) | (bottom & tmask);
        } else result = bottom & tmask; /* UBFM */
        stage_write(&tx, rd, result, width, 0);
    } else if ((op & UINT32_C(0x7fa00000)) == UINT32_C(0x13800000)) {
        unsigned n = (op >> 22) & 1u, amount = (op >> 10) & 63u;
        uint64_t high, low, result;
        if (n != (width == 64) || amount >= width) goto unsupported;
        high = reg_read(cpu, rn, width, 0);
        low = reg_read(cpu, rm, width, 0);
        /* Extract from high:low without an undefined shift by 32 or 64. */
        result = amount ? (low >> amount) | (high << (width - amount)) : low;
        stage_write(&tx, rd, result, width, 0);
    } else if ((op & UINT32_C(0x7fe0f000)) == UINT32_C(0x1ac02000)) {
        unsigned kind = (op >> 10) & 3u;
        unsigned amount = (unsigned)(reg_read(cpu, rm, width, 0) & (width - 1u));
        stage_write(&tx, rd, shift(reg_read(cpu, rn, width, 0), amount, width, kind), width, 0);
    } else if ((op & UINT32_C(0x3fe00800)) == UINT32_C(0x1a800000)) {
        unsigned invert = (op >> 30) & 1u, increment = (op >> 10) & 1u;
        uint64_t result;
        if (condition_holds(cpu->nzcv, (op >> 12) & 15u)) {
            result = reg_read(cpu, rn, width, 0);
        } else {
            result = reg_read(cpu, rm, width, 0);
            if (invert) result = ~result;
            if (increment) ++result;
        }
        /* CSEL/CSINC/CSINV/CSNEG do not update flags. Source31 is ZR and
         * destination31 is discard; aliases use the same allocated encodings. */
        stage_write(&tx, rd, result, width, 0);
    } else if ((op & UINT32_C(0x7c000000)) == UINT32_C(0x14000000)) {
        tx.branch = 1;
        tx.next_pc = cpu->pc + (sign_extend(op & UINT32_C(0x03ffffff), 26) << 2);
        if (op >> 31) stage_write(&tx, 30, cpu->pc + 4, 64, 0);
    } else if ((op & UINT32_C(0xff000010)) == UINT32_C(0x54000000)) {
        if (condition_holds(cpu->nzcv, op & 15u)) {
            tx.branch = 1;
            tx.next_pc = cpu->pc + (sign_extend((op >> 5) & 524287u, 19) << 2);
        }
    } else if ((op & UINT32_C(0x7e000000)) == UINT32_C(0x34000000)) {
        int nonzero = (op & (1u << 24)) != 0;
        if ((reg_read(cpu, rd, width, 0) != 0) == nonzero) {
            tx.branch = 1;
            tx.next_pc = cpu->pc + (sign_extend((op >> 5) & 524287u, 19) << 2);
        }
    } else if ((op & UINT32_C(0x7e000000)) == UINT32_C(0x36000000)) {
        unsigned bit = ((op >> 26) & 32u) | ((op >> 19) & 31u);
        int nonzero = (op & (1u << 24)) != 0;
        if (((reg_read(cpu, rd, 64, 0) >> bit) & 1u) == (unsigned)nonzero) {
            tx.branch = 1;
            tx.next_pc = cpu->pc + (sign_extend((op >> 5) & 16383u, 14) << 2);
        }
    } else if ((op & UINT32_C(0xfffffc1f)) == UINT32_C(0xd61f0000) ||
               (op & UINT32_C(0xfffffc1f)) == UINT32_C(0xd63f0000) ||
               (op & UINT32_C(0xfffffc1f)) == UINT32_C(0xd65f0000)) {
        tx.branch = 1;
        tx.next_pc = reg_read(cpu, rn, 64, 0);
        if ((op & UINT32_C(0xfffffc1f)) == UINT32_C(0xd63f0000))
            stage_write(&tx, 30, cpu->pc + 4, 64, 0);
    } else if ((op & UINT32_C(0x1f000000)) == UINT32_C(0x10000000)) {
        uint64_t immediate = sign_extend(((op >> 5) & 524287u) << 2 | ((op >> 29) & 3u), 21);
        uint64_t base = cpu->pc;
        if (op >> 31) { base &= ~UINT64_C(4095); immediate <<= 12; }
        stage_write(&tx, rd, base + immediate, 64, 0);
    } else if (ocnext_a64_atomic_decode(op)) {
        /* Exclusives, ordered/RCpc accesses and LSE atomics: a64_atomic.c. */
        struct ocnext_a64_atomic_effect effect;
        enum ocnext_a64_result stopped;
        if (!ocnext_a64_atomic_is_clrex(op) && stop_sp_alignment(cpu,memory,op,rn,&stopped)) return stopped;
        switch (ocnext_a64_atomic_execute(cpu, memory, op, &effect)) {
        case OCNEXT_A64_ATOMIC_OK: break;
        case OCNEXT_A64_ATOMIC_FAULT:
            return fault(cpu, effect.fault_code, effect.fault_access, effect.fault_address,
                         effect.fault_size, op);
        default: goto unsupported;
        }
        for (index = 0; index < effect.count; ++index)
            stage_write(&tx, effect.reg[index], effect.value[index], effect.width[index], 0);
    } else if (ocnext_a64_ldra_decode(op)) {
        unsigned key=(op & (UINT32_C(1)<<23)) ? 3u : 2u;
        unsigned enable_bit=key==2 ? 27u : 13u;
        uint64_t base=reg_read(cpu,rn,64,1);
        enum ocnext_a64_result stopped;
        struct ocnext_a64_ldra_request request={.selected_base=base,.opcode=op,
            .abi_version=OCNEXT_A64_LDRA_ABI,.known_mask=OCNEXT_A64_LDRA_BASE_KNOWN,
            .address_add_profile=OCNEXT_A64_LDRA_ADDRESS_NORMAL_BASE64_NO_MTE};
        struct ocnext_a64_ldra_effect effect;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu))
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if (cpu->pac.pointer_profile==OCNEXT_A64_PAC_NONE ||
            !(cpu->system.mmu.known_mask & OCNEXT_A64_MMU_KNOWN_SCTLR) ||
            ((op & (UINT32_C(1)<<11)) && rn==rd && rn!=31)) goto unsupported;
        /* Known-disabled enable is resolved before TCR, keys or combined-mode.
         * This does not turn a NONE/UNKNOWN CPU feature profile into PAuth. */
        if ((cpu->system.mmu.sctlr_el1 >> enable_bit) & 1u) {
            struct ocnext_pac_key_bank bank;
            struct ocnext_pac_pointer_config geometry;
            struct ocnext_pac_pointer_request auth={.pointer=base,.modifier=0,
                .operation=OCNEXT_PAC_POINTER_AUTH,.key_index=key,
                .current_el=cpu->system.current_el,.key_enabled=1};
            struct ocnext_pac_pointer_output out;
            if (cpu->pac.combined_mode==OCNEXT_A64_PAC_COMBINED_UNKNOWN ||
                !pac_geometry(cpu,&geometry) || !pac_key_known(cpu,key)) goto unsupported;
            geometry.profile=cpu->pac.pointer_profile==OCNEXT_A64_PAC_PAUTH1 ?
                OCNEXT_PAC_POINTER_QARMA5_PAUTH1 :
                cpu->pac.combined_mode==OCNEXT_A64_PAC_COMBINED_FPAC ?
                OCNEXT_PAC_POINTER_QARMA5_FPAC : OCNEXT_PAC_POINTER_QARMA5_PAUTH2;
            pac_native_snapshot(cpu,&bank);
            auth.owner_id=bank.owner_id;auth.generation=bank.generation;
            if (ocnext_pac_pointer_execute(&bank,&geometry,&auth,&out)!=OCNEXT_PAC_POINTER_OK)
                goto unsupported;
            if (out.outcome==OCNEXT_PAC_POINTER_AUTH_EXCEPTION)
                return take_sync(cpu,memory,op,0x1c,
                    (uint32_t)out.esr & UINT32_C(0x01ffffff),cpu->pc,0);
            if (out.outcome!=OCNEXT_PAC_POINTER_AUTH_SUCCESS &&
                out.outcome!=OCNEXT_PAC_POINTER_AUTH_CORRUPTED) goto unsupported;
            request.selected_base=out.pointer;
        }
        if (stop_sp_alignment(cpu,memory,op,rn,&stopped)) return stopped;
        enum ocnext_a64_ldra_status prepared=ocnext_a64_ldra_prepare(&request,&effect);
        if (prepared==OCNEXT_A64_LDRA_ARGUMENT)
            return fault(cpu,OCNEXT_A64_FAULT_ARGUMENT,OCNEXT_A64_ACCESS_FETCH,cpu->pc,4,op);
        if (prepared!=OCNEXT_A64_LDRA_OK) goto unsupported;
        enum ocnext_a64_fault_code code=memory_transfer(cpu,memory,effect.access_address,bytes,8,8,1);
        if (code!=OCNEXT_A64_FAULT_NONE)
            return fault(cpu,code,OCNEXT_A64_ACCESS_READ,effect.access_address,8,op);
        stage_write(&tx,rd,little_read(bytes,8),64,0);
        if (effect.writeback) stage_write(&tx,rn,effect.writeback_value,64,1);
    } else if (simd_ldst_decode(op, &lplan)) {
        /* SIMD&FP LDP/STP/LDNP/STNP and immediate LDR/STR/LDUR/STUR: a64_simd_ldst.inc. */
        more = simd_ldst_exec(cpu, memory, hooks, &lplan, &tx, &more_result);
        if (more == MORE_UNSUPPORTED) goto unsupported;
        if (more == MORE_RESULT) return more_result;
    } else if ((op & UINT32_C(0x3b000000)) == UINT32_C(0x39000000) ||
               (op & UINT32_C(0x3b200000)) == UINT32_C(0x38000000)) {
        unsigned size = 1u << (op >> 30);
        unsigned opc = (op >> 22) & 3u;
        int unsigned_offset = (op & UINT32_C(0x3b000000)) == UINT32_C(0x39000000);
        unsigned mode = unsigned_offset ? 0u : (op >> 10) & 3u;
        uint64_t base = reg_read(cpu, rn, 64, 1), offset, address, value;
        int load = opc != 0;
        enum ocnext_a64_fault_code code;
        if ((op & (1u << 26)) || (!unsigned_offset && mode == 2) ||
            (opc == 2 && size == 8) || (opc == 3 && size >= 4)) goto unsupported;
        if (!unsigned_offset && (mode == 1 || mode == 3) && rn != 31 && rn == rd)
            goto unsupported; /* constrained-unpredictable writeback overlap */
        enum ocnext_a64_result stopped;
        if (stop_sp_alignment(cpu,memory,op,rn,&stopped)) return stopped;
        offset = unsigned_offset ? (uint64_t)((op >> 10) & 4095u) * size :
                                   sign_extend((op >> 12) & 511u, 9);
        address = mode == 1 ? base : base + offset;
        if (!load) little_write(bytes, reg_read(cpu, rd, size == 8 ? 64 : 32, 0), size);
        code = memory_transfer(cpu, memory, address, bytes, size, size, load);
        if (code != OCNEXT_A64_FAULT_NONE)
            return fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE,
                         address, size, op);
        if (load) {
            value = little_read(bytes, size);
            if (opc >= 2) value = sign_extend(value, size * 8);
            stage_write(&tx, rd, value, opc == 2 || size == 8 ? 64 : 32, 0);
        }
        if (!unsigned_offset && (mode == 1 || mode == 3))
            stage_write(&tx, rn, base + offset, 64, 1);
    } else if ((op & UINT32_C(0x3a000000)) == UINT32_C(0x28000000)) {
        unsigned opc = op >> 30;
        unsigned mode = (op >> 23) & 3u;
        unsigned rt2 = (op >> 10) & 31u;
        int load = (op & (1u << 22)) != 0;
        unsigned size = opc == 2 ? 8u : 4u;
        uint64_t base = reg_read(cpu, rn, 64, 1);
        uint64_t offset = sign_extend((op >> 15) & 127u, 7) * size;
        uint64_t address = mode == 1 ? base : base + offset;
        enum ocnext_a64_fault_code code;
        if ((op & (1u << 26)) || opc == 3 || (mode == 0 && opc == 1) || (opc == 1 && !load) ||
            (load && rd == rt2) ||
            ((mode == 1 || mode == 3) && rn != 31 && (rn == rd || rn == rt2))) goto unsupported;
        enum ocnext_a64_result stopped;
        if (stop_sp_alignment(cpu,memory,op,rn,&stopped)) return stopped;
        if (!load) {
            little_write(bytes, reg_read(cpu, rd, size == 8 ? 64 : 32, 0), size);
            little_write(bytes + size, reg_read(cpu, rt2, size == 8 ? 64 : 32, 0), size);
        }
        code = memory_transfer(cpu, memory, address, bytes, size * 2, size, load);
        if (code != OCNEXT_A64_FAULT_NONE)
            return fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE,
                         address, size * 2, op);
        if (load) {
            uint64_t a = little_read(bytes, size), b = little_read(bytes + size, size);
            if (opc == 1) { a = sign_extend(a, 32); b = sign_extend(b, 32); }
            stage_write(&tx, rd, a, opc == 0 ? 32 : 64, 0);
            stage_write(&tx, rt2, b, opc == 0 ? 32 : 64, 0);
        }
        if (mode == 1 || mode == 3) stage_write(&tx, rn, base + offset, 64, 1);
    } else if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd5101080) ||
               (op & UINT32_C(0xffffffe0)) == UINT32_C(0xd5301180)) {
        /* Exact tuples only: MSR OSLAR_EL1 (2,0,1,0,4),
         * MRS OSLSR_EL1 (2,0,1,1,4). No wildcard system-register NOPs.
         * Arm DDI0595 ID061021, printed pages 1259..1262. */
        if (cpu->system.profile == OCNEXT_A64_SYSTEM_SCALAR) goto unsupported;
        if (!valid_system(cpu))
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0)
            return undefined_access(cpu, memory, op);
        if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd5101080)) {
            uint64_t value = reg_read(cpu, rd, 64, 0);
            /* RES0 nonzero behavior is outside this narrow profile. This
             * rejection is implementation coverage, not an Arm fault rule. */
            if (value & ~UINT64_C(1)) goto unsupported;
            tx.os_lock = (uint8_t)value;
            tx.set_os_lock = 1;
        } else {
            /* OSLM=0b10 split across bits 3,0; nTT=RAZ; OSLK=bit1.
             * All remaining bits read zero. */
            stage_write(&tx, rd, UINT64_C(8) | (uint64_t)cpu->system.os_lock << 1, 64, 0);
        }
    } else if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd53b4220) ||
               (op & UINT32_C(0xffffffe0)) == UINT32_C(0xd51b4220) ||
               (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50340df) ||
               (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50340ff)) {
        if (cpu->system.profile == OCNEXT_A64_SYSTEM_SCALAR) goto unsupported;
        if (!valid_system(cpu))
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0 && !cpu->system.uma) {
            if (sync_profile(cpu)) return take_sync(cpu, memory, op, 0x18, system_iss(op), cpu->pc, 0);
            return system_access_trap(cpu, op);
        }
        if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd53b4220)) {
            stage_write(&tx, rd, cpu->system.daif, 64, 0);
        } else if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd51b4220)) {
            uint64_t value = reg_read(cpu, rd, 64, 0);
            /* Nonzero RES0 is outside coverage, not a mandated Arm fault. */
            if (value & ~((uint64_t)OCNEXT_A64_DAIF_MASK)) goto unsupported;
            tx.daif = (uint32_t)value;
            tx.set_daif = 1;
        } else {
            uint32_t bits = ((op >> 8) & 15u) << 6;
            tx.daif = (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50340df) ?
                      cpu->system.daif | bits : cpu->system.daif & ~bits;
            tx.set_daif = 1;
        }
    } else if ((op & UINT32_C(0xffffffe0)) == UINT32_C(0xd5384240)) {
        if (cpu->system.profile == OCNEXT_A64_SYSTEM_SCALAR) goto unsupported;
        if (!valid_system(cpu))
            return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0)
            return undefined_access(cpu, memory, op);
        stage_write(&tx, rd, (uint64_t)cpu->system.current_el << 2, 64, 0);
    } else if ((op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5180700)) {
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        /* No FEAT_IDST/EL2/EL3: EL0 MRS is UNDEFINED. The MSR form is an
         * unallocated read-only-register write at either supported EL. */
        if (cpu->system.current_el == 0 || !((op >> 21) & 1u))
            return undefined_access(cpu, memory, op);
        if (!(cpu->system.features.known_mask & OCNEXT_A64_FEATURE_KNOWN_MMFR0)) goto unsupported;
        stage_write(&tx, rd, cpu->system.features.id_aa64mmfr0_el1, 64, 0);
    } else if ((op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd51bd040) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd51bd060) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd518d080)) {
        uint32_t identity = op & UINT32_C(0xffdfffe0), id;
        uint64_t value;
        unsigned read = (op >> 21) & 1u;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        id = identity == UINT32_C(0xd51bd040) ? OCNEXT_A64_TLS_KNOWN_EL0 :
             identity == UINT32_C(0xd51bd060) ? OCNEXT_A64_TLS_KNOWN_RO_EL0 : OCNEXT_A64_TLS_KNOWN_EL1;
        if (cpu->system.current_el == 0 &&
            (id == OCNEXT_A64_TLS_KNOWN_EL1 || (id == OCNEXT_A64_TLS_KNOWN_RO_EL0 && !read)))
            return undefined_access(cpu, memory, op);
        if (read) {
            if (!(cpu->system.tls.known_mask & id)) goto unsupported;
            value = id == OCNEXT_A64_TLS_KNOWN_EL0 ? cpu->system.tls.tpidr_el0 :
                    id == OCNEXT_A64_TLS_KNOWN_RO_EL0 ? cpu->system.tls.tpidrro_el0 : cpu->system.tls.tpidr_el1;
            stage_write(&tx, rd, value, 64, 0);
        } else {
            tx.tls_register = id; tx.system_value = reg_read(cpu, rd, 64, 0);
        }
    } else if ((op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5182040) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5182000) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5182020) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5181000) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd518a200)) {
        uint32_t identity = op & UINT32_C(0xffdfffe0), id;
        uint64_t value;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        /* Base no-EL2 regime: accesses to these EL1 registers at EL0 are
         * UNDEFINED; DAIF's configurable UMA trap is a different rule. */
        if (cpu->system.current_el == 0) return undefined_access(cpu, memory, op);
        id = identity == UINT32_C(0xd5182040) ? OCNEXT_A64_MMU_KNOWN_TCR :
             identity == UINT32_C(0xd5182000) ? OCNEXT_A64_MMU_KNOWN_TTBR0 :
             identity == UINT32_C(0xd5182020) ? OCNEXT_A64_MMU_KNOWN_TTBR1 :
             identity == UINT32_C(0xd5181000) ? OCNEXT_A64_MMU_KNOWN_SCTLR : OCNEXT_A64_MMU_KNOWN_MAIR;
        if ((op >> 21) & 1u) {
            if (!(cpu->system.mmu.known_mask & id)) goto unsupported;
            value = mmu_register_value(&cpu->system.mmu, id);
            if (id == OCNEXT_A64_MMU_KNOWN_SCTLR && hooks && hooks->sctlr_ext_mask) {
                if (!hooks->sctlr_ext_value) goto unsupported;
                value = (value & ~hooks->sctlr_ext_mask) | (*hooks->sctlr_ext_value & hooks->sctlr_ext_mask);
            }
            stage_write(&tx, rd, value, 64, 0);
        } else {
            value = reg_read(cpu, rd, 64, 0);
            if (id == OCNEXT_A64_MMU_KNOWN_SCTLR &&
                sctlr_profile(cpu) == OCNEXT_A64_SCTLR_PROFILE_APPLE) {
                uint64_t canonical;
                if (ocnext_a64_sctlr_apple_write(value, cpu->pac.pointer_profile, &canonical, 0, 0) !=
                    OCNEXT_A64_SCTLR_OK) goto unsupported;
                value = canonical;
            } else if (id == OCNEXT_A64_MMU_KNOWN_SCTLR && hooks && hooks->sctlr_ext_mask) {
                /* Profile-accepted bits are stored outside the bank; the bank keeps RES1 on. */
                if (!hooks->sctlr_ext_value) goto unsupported;
                tx.ext_set = 1; tx.ext_value = value & hooks->sctlr_ext_mask;
                value = (value & ~hooks->sctlr_ext_mask) | (OCNEXT_A64_SCTLR_RES1 & hooks->sctlr_ext_mask);
            }
            if (!mmu_value_supported(id, value, cpu->pac.pointer_profile,
                                     sctlr_profile(cpu))) goto unsupported;
            tx.mmu_register = id; tx.system_value = value;
        }
    } else if ((op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd518c000) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5185200) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5186000) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5184020) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5184000) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5184100) ||
               (op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd5184200) ||
               (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50040bf)) {
        uint32_t identity = op & UINT32_C(0xffdfffe0);
        uint64_t value = 0;
        unsigned id = SYS_NONE;
        int immediate = (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50040bf);
        int read = !immediate && ((op >> 21) & 1u);
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0) return undefined_access(cpu, memory, op);
        if (identity == UINT32_C(0xd518c000)) { id = SYS_VBAR; value = cpu->system.vbar_el1; }
        else if (identity == UINT32_C(0xd5185200)) { id = SYS_ESR; value = cpu->system.esr_el1; }
        else if (identity == UINT32_C(0xd5186000)) { id = SYS_FAR; value = cpu->system.far_el1; }
        else if (identity == UINT32_C(0xd5184020)) { id = SYS_ELR; value = cpu->system.elr_el1; }
        else if (identity == UINT32_C(0xd5184000)) { id = SYS_SPSR; value = cpu->system.spsr_el1; }
        else if (identity == UINT32_C(0xd5184100)) {
            if (!cpu->system.spsel) return undefined_access(cpu, memory, op);
            id = SYS_SP_EL0; value = cpu->system.sp_el0;
        } else value = cpu->system.spsel;
        if (read) stage_write(&tx, rd, value, 64, 0);
        else {
            value = immediate ? ((op >> 8) & 15u) : reg_read(cpu, rd, 64, 0);
            if (id == SYS_NONE) {
                if (value > 1) goto unsupported;
                tx.set_spsel = 1; tx.spsel = (uint8_t)value;
            } else {
                if (id == SYS_VBAR) {
                    if (!valid_vbar(instruction_address(cpu, value))) goto unsupported;
                    /* Architectural register write does not fetch vectors.
                     * The actual taken exception probes its destination EL
                     * FETCH4 before changing CPU/retirement state. */
                }
                if ((id == SYS_ESR && value > UINT32_MAX) ||
                    (id == SYS_SPSR && (value & ~SPSR_SUPPORTED_MASK))) goto unsupported;
                tx.sysreg = id; tx.system_value = value;
            }
        }
    } else if ((op & UINT32_C(0xffdfffe0)) == UINT32_C(0xd51b4200)) {
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if ((op >> 21) & 1u) stage_write(&tx, rd, cpu->nzcv, 64, 0);
        else {
            uint64_t value = reg_read(cpu, rd, 64, 0);
            if (value & ~UINT64_C(0xf0000000)) goto unsupported;
            tx.set_flags = 1; tx.nzcv = (uint32_t)value;
        }
    } else if (op == UINT32_C(0xd69f03e0)) {
        uint64_t state, target;
        unsigned mode;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0) return undefined_access(cpu, memory, op);
        state = cpu->system.spsr_el1; target = instruction_address(cpu, cpu->system.elr_el1); mode = (unsigned)(state & 31u);
        if ((cpu->system.known_state & (OCNEXT_A64_KNOWN_ELR | OCNEXT_A64_KNOWN_SPSR)) !=
            (OCNEXT_A64_KNOWN_ELR | OCNEXT_A64_KNOWN_SPSR) ||
            (state & ~SPSR_SUPPORTED_MASK) || (mode != 0 && mode != 4 && mode != 5) || (target & 3u))
            return fault(cpu, OCNEXT_A64_FAULT_EXCEPTION_RETURN, OCNEXT_A64_ACCESS_FETCH, target, 4, op);
        if (target > UINT64_MAX - 3 || fetch_prospective(memory, target, bytes, mode >> 2, state))
            return fault(cpu, OCNEXT_A64_FAULT_FETCH, OCNEXT_A64_ACCESS_FETCH, target, 4, op);
        save_sp_bank(cpu);
        ocnext_a64_exclusive_clear(cpu); /* ERET clears the local monitor (architectural) */
        cpu->system.current_el = (uint8_t)(mode >> 2);
        cpu->system.spsel = (uint8_t)(mode & 1u);
        cpu->sp = mode == 5 ? cpu->system.sp_el1 : cpu->system.sp_el0;
        cpu->nzcv = (uint32_t)state & UINT32_C(0xf0000000);
        cpu->system.daif = (uint32_t)state & OCNEXT_A64_DAIF_MASK;
        pstate_ext_apply(cpu, state);
        cpu->system.elr_el1 = cpu->system.spsr_el1 = cpu->system.esr_el1 = cpu->system.far_el1 = 0;
        cpu->system.known_state &= OCNEXT_A64_KNOWN_VBAR;
        cpu->pc = target;
        ++cpu->retired;
        return OCNEXT_A64_RETIRED;
    } else if ((op & UINT32_C(0xffe0001f)) == UINT32_C(0xd4000001)) {
        if (!sync_profile(cpu)) goto unsupported;
        return take_sync(cpu, memory, op, 0x15, (op >> 5) & 65535u, cpu->pc + 4, 1);
    } else if ((op & UINT32_C(0xffe0001f)) == UINT32_C(0xd4000002)) {
        struct ocnext_a64_hvc_request request;
        uint64_t out_x[4] = {0, 0, 0, 0}, resume = 0;
        uint32_t nx = 0, i;
        enum ocnext_a64_hvc_result completed;
        if (!sync_profile(cpu) || !hooks || !hooks->hvc) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (cpu->system.current_el == 0) return undefined_access(cpu, memory, op);
        request.pc = cpu->pc; request.retired = cpu->retired; request.opcode = op;
        request.imm16 = (op >> 5) & 65535u;
        request.pstate = (uint64_t)(cpu->nzcv & UINT32_C(0xf0000000)) | cpu->system.daif |
                         ((uint64_t)cpu->system.current_el << 2) | cpu->system.spsel;
        for (i = 0; i < 8; ++i) request.x[i] = cpu->x[i];
        completed = hooks->hvc(hooks->hvc_context, &request, out_x, &nx, &resume);
        if (completed == OCNEXT_A64_HVC_UNSUPPORTED || completed == OCNEXT_A64_HVC_FAILED) goto unsupported;
        if (completed != OCNEXT_A64_HVC_COMPLETED || nx > 4 || resume != cpu->pc + 4)
            return fault(cpu, OCNEXT_A64_FAULT_HVC_PROVIDER, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        for (i = 0; i < nx; ++i) stage_write(&tx, i, out_x[i], 64, 0);
    } else if ((op & UINT32_C(0xffff0000)) == 0) {
        if (!sync_profile(cpu)) goto unsupported;
        return undefined_access(cpu, memory, op);
    } else if ((op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50330bf) ||
               (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd503309f) ||
               (op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50330df)) {
        struct ocnext_a64_sync_request request = {0};
        enum ocnext_a64_sync_result completed;
        uint32_t identity = op & UINT32_C(0xfffff0ff);
        unsigned option = (op >> 8) & 15u;
        uint32_t op_canonical = op;
        if (!sync_profile(cpu)) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        request.kind = identity == UINT32_C(0xd50330bf) ? OCNEXT_A64_SYNC_DMB :
                       identity == UINT32_C(0xd503309f) ? OCNEXT_A64_SYNC_DSB : OCNEXT_A64_SYNC_ISB;
        if (!memory->sync) goto unsupported;
        /* Reserved ISB CRm and reserved DMB/DSB option values (CRm[1:0]==0)
         * execute as the SY form architecturally. DSB #0 / #4 are SSBB / PSSBB
         * (speculative-store-bypass barriers); this interpreter has no
         * speculation, and DSB SY is a legal, strictly stronger implementation
         * of both, so they are issued to the provider as DSB SY. The request
         * carries the canonical encoding of the barrier actually performed. */
        if (request.kind == OCNEXT_A64_SYNC_ISB ? option != 15 : !(option & 3u)) {
            option = 15;
            op_canonical = identity | (15u << 8);
        }
        request.pc = cpu->pc; request.opcode = op_canonical;
        request.option = (uint8_t)option; request.current_el = cpu->system.current_el;
        request.domain = (enum ocnext_a64_sync_domain)(option >> 2);
        request.types = (enum ocnext_a64_sync_types)(option & 3u);
        completed = memory->sync(memory->context, &request);
        if (completed == OCNEXT_A64_SYNC_UNSUPPORTED) goto unsupported;
        if (completed != OCNEXT_A64_SYNC_COMPLETED)
            return fault(cpu, OCNEXT_A64_FAULT_SYNC_PROVIDER, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    } else if (op == UINT32_C(0xd503201f)) {
        /* Architecturally defined NOP only, no wildcard hint acceptance. */
    } else if (sm_match(op)) {
        /* Hints (YIELD/WFE/WFI/SEV/SEVL/BTI), PSTATE PAN/UAO/DIT/SSBS, PAR_EL1,
         * DCZID_EL0, DC/IC/TLBI/AT: see a64_sysmaint.inc.c. */
        enum ocnext_a64_result sm = sm_exec(cpu, memory, op, &tx);
        if (sm != SM_CONTINUE) return sm;
    } else if ((op & UINT32_C(0xffe0001f)) == UINT32_C(0xd4400000)) {
        uint16_t immediate = (uint16_t)((op >> 5) & 65535u);
        if (!cpu->allow_test_halt || immediate != OCNEXT_A64_TEST_HALT_IMMEDIATE)
            return fault(cpu, OCNEXT_A64_FAULT_DEBUG_HALT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        tx.halt = 1;
        tx.halt_immediate = immediate;
    } else if ((more = more_exec(cpu, memory, hooks, op, &tx, bytes, &more_result)) != MORE_NONE) {
        if (more == MORE_UNSUPPORTED) goto unsupported;
        if (more == MORE_RESULT) return more_result;
    } else if ((op & UINT32_C(0xffd00000)) == UINT32_C(0xd5100000)) {
        /* MRS/MSR (register) not claimed by an exact handler above: first the bound sysreg provider
         * (ocnext/a64_sysreg.h), then the caller's hook (M-BOOT vm_sysreg). No provider and no hook, or an
         * unknown encoding, is an unsupported stop; never RAZ/WI. */
        const struct sysreg_binding *binding = find_sysreg_binding(memory);
        if (!sync_profile(cpu) || (!binding && !(hooks && hooks->sysreg))) goto unsupported;
        if (!valid_system(cpu)) return fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        if (binding) {
            struct ocnext_a64_sysreg_request request = {0};
            uint64_t read_value = 0;
            enum ocnext_a64_sysreg_result served;
            request.pc = cpu->pc; request.opcode = op;
            request.key = (uint16_t)((op >> 5) & 0x7fffu);
            request.is_read = (uint8_t)((op >> 21) & 1u);
            request.current_el = cpu->system.current_el;
            if (!request.is_read) request.value = reg_read(cpu, rd, 64, 0);
            served = binding->fn(binding->context, &request, &read_value);
            if (served == OCNEXT_A64_SYSREG_UNDEFINED) return undefined_access(cpu, memory, op);
            if (served == OCNEXT_A64_SYSREG_TRAP) return take_sync(cpu, memory, op, 0x18, system_iss(op), cpu->pc, 0);
            if (served != OCNEXT_A64_SYSREG_OK) goto unsupported;
            if (request.is_read) stage_write(&tx, rd, read_value, 64, 0);
        } else {
            struct ocnext_a64_hook_sysreg_request request;
            uint64_t value = 0;
            enum ocnext_a64_hook_sysreg_result completed;
            request.op0 = (uint8_t)(2u + ((op >> 19) & 1u)); request.op1 = (uint8_t)((op >> 16) & 7u);
            request.crn = (uint8_t)((op >> 12) & 15u); request.crm = (uint8_t)((op >> 8) & 15u);
            request.op2 = (uint8_t)((op >> 5) & 7u); request.is_read = (uint8_t)((op >> 21) & 1u);
            request.current_el = cpu->system.current_el; request.reserved = 0;
            if (cpu->system.current_el == 0 && request.op1 != 3) return undefined_access(cpu, memory, op);
            request.pc = cpu->pc; request.retired = cpu->retired; request.opcode = op;
            request.value = request.is_read ? 0 : reg_read(cpu, rd, 64, 0);
            completed = hooks->sysreg(hooks->sysreg_context, &request, &value);
            if (completed != OCNEXT_A64_HOOK_SYSREG_COMPLETED) goto unsupported;
            if (request.is_read) stage_write(&tx, rd, value, 64, 0);
        }
    } else {
unsupported:
        /* Encodings the A64 top-level table leaves unallocated (op1 = 0001 / 0011) or reserves as UDF
         * (op0 = 0, op1 = 0000, imm16 form) are architecturally UNDEFINED: a synchronous exception
         * with EC 0, not an emulator stop. XNU's DebuggerTrap (0xe7ffdeff) relies on exactly this. */
        if (sync_profile(cpu) && (((op >> 25) & 15u) == 1u || ((op >> 25) & 15u) == 3u ||
                                  (op >> 16) == 0u))
            return undefined_access(cpu, memory, op);
        return fault(cpu, OCNEXT_A64_FAULT_UNSUPPORTED, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
    }

    for (index = 0; index < tx.count; ++index) {
        unsigned reg = tx.reg[index];
        if (reg != 31) cpu->x[reg] = tx.value[index];
        else if (tx.sp_write[index]) { cpu->sp = tx.value[index]; save_sp_bank(cpu); }
    }
    if(tx.set_fp)cpu->fp=tx.fp_after;
    for(index=0;index<tx.vector_count;++index){
        unsigned j,reg=tx.vector_reg[index];
        for(j=0;j<16;++j)cpu->vector.bytes[reg][j]=tx.vector_bytes[index][j];
        cpu->vector.known_bytes[reg]=tx.vector_known[index];
    }
    if (tx.pac_half) {
        unsigned half = tx.pac_half-1u, key = half/2u;
        if (half & 1u) cpu->pac.keys[key].hi = tx.system_value;
        else cpu->pac.keys[key].lo = tx.system_value;
        cpu->pac.half_known_mask |= 1u << half; ++cpu->pac.write_epoch;
    }
    if (tx.set_flags) cpu->nzcv = tx.nzcv;
    if (tx.set_os_lock) cpu->system.os_lock = tx.os_lock;
    if (tx.set_daif) cpu->system.daif = tx.daif;
    if (tx.ext_set) {
        *hooks->sctlr_ext_value = tx.ext_value;
        /* SCTLR_EL1.SPAN (bit23) and DSSBS (bit44) live outside the bank when the caller's
         * profile stores them (they are RES1/unsupported in the bank); mirror what exception
         * entry needs into ext_state so take_async/deliver_abort stay hook-free. */
        if (hooks->sctlr_ext_mask & (UINT64_C(1) << 23))
            ext_set(cpu, OCNEXT_A64_EXT_SPAN_CLEAR, !((tx.ext_value >> 23) & 1u));
        if (hooks->sctlr_ext_mask & (UINT64_C(1) << 44))
            ext_set(cpu, OCNEXT_A64_EXT_DSSBS, (tx.ext_value >> 44) & 1u);
    }
    if (tx.tls_register) {
        if (tx.tls_register == OCNEXT_A64_TLS_KNOWN_EL0) cpu->system.tls.tpidr_el0 = tx.system_value;
        else if (tx.tls_register == OCNEXT_A64_TLS_KNOWN_RO_EL0) cpu->system.tls.tpidrro_el0 = tx.system_value;
        else cpu->system.tls.tpidr_el1 = tx.system_value;
        cpu->system.tls.known_mask |= tx.tls_register;
    }
    if (tx.mmu_register) {
        if (tx.mmu_register == OCNEXT_A64_MMU_KNOWN_TCR) cpu->system.mmu.tcr_el1 = tx.system_value;
        else if (tx.mmu_register == OCNEXT_A64_MMU_KNOWN_TTBR0) cpu->system.mmu.ttbr0_el1 = tx.system_value;
        else if (tx.mmu_register == OCNEXT_A64_MMU_KNOWN_TTBR1) cpu->system.mmu.ttbr1_el1 = tx.system_value;
        else if (tx.mmu_register == OCNEXT_A64_MMU_KNOWN_SCTLR) {
            cpu->system.mmu.sctlr_el1 = tx.system_value;
            cpu->system.uma = (uint8_t)((tx.system_value >> 9) & 1u);
        } else cpu->system.mmu.mair_el1 = tx.system_value;
        cpu->system.mmu.known_mask |= tx.mmu_register;
    }
    if (tx.set_spsel) select_sp(cpu, tx.spsel);
    switch (tx.sysreg) {
    case SYS_VBAR: cpu->system.vbar_el1 = tx.system_value; cpu->system.known_state |= OCNEXT_A64_KNOWN_VBAR; break;
    case SYS_ESR: cpu->system.esr_el1 = tx.system_value; cpu->system.known_state |= OCNEXT_A64_KNOWN_ESR; break;
    case SYS_FAR: cpu->system.far_el1 = tx.system_value; cpu->system.known_state |= OCNEXT_A64_KNOWN_FAR; break;
    case SYS_ELR: cpu->system.elr_el1 = tx.system_value; cpu->system.known_state |= OCNEXT_A64_KNOWN_ELR; break;
    case SYS_SPSR: cpu->system.spsr_el1 = tx.system_value; cpu->system.known_state |= OCNEXT_A64_KNOWN_SPSR; break;
    case SYS_SP_EL0: cpu->system.sp_el0 = tx.system_value; break;
    default: break;
    }
    cpu->pc = tx.branch ? instruction_address(cpu, tx.next_pc) : tx.next_pc;
    ++cpu->retired;
    if (tx.halt) { cpu->halted = 1; cpu->halt_immediate = tx.halt_immediate; }
    return tx.halt ? OCNEXT_A64_HALTED : OCNEXT_A64_RETIRED;
}

enum ocnext_a64_result ocnext_a64_run(struct ocnext_a64_cpu *cpu,
                                     const struct ocnext_a64_memory *memory,
                                     uint64_t budget)
{
    uint64_t count;
    if (!cpu) return OCNEXT_A64_FAULTED;
    if (cpu->fault.code != OCNEXT_A64_FAULT_NONE) return OCNEXT_A64_FAULTED;
    if (cpu->halted) return OCNEXT_A64_HALTED;
    for (count = 0; count < budget; ++count) {
        enum ocnext_a64_result result = ocnext_a64_step(cpu, memory);
        if (result != OCNEXT_A64_RETIRED && result != OCNEXT_A64_EXCEPTION) return result;
    }
    return OCNEXT_A64_BUDGET;
}

const char *ocnext_a64_fault_string(enum ocnext_a64_fault_code code)
{
    switch (code) {
    case OCNEXT_A64_FAULT_NONE: return "none";
    case OCNEXT_A64_FAULT_UNSUPPORTED: return "unsupported instruction/encoding";
    case OCNEXT_A64_FAULT_FETCH: return "instruction fetch failed";
    case OCNEXT_A64_FAULT_READ: return "data read failed";
    case OCNEXT_A64_FAULT_WRITE: return "data write failed";
    case OCNEXT_A64_FAULT_ALIGNMENT: return "address alignment policy failed";
    case OCNEXT_A64_FAULT_DEBUG_HALT: return "HLT debug exception requires a future privileged provider";
    case OCNEXT_A64_FAULT_ARGUMENT: return "invalid runtime argument";
    case OCNEXT_A64_FAULT_UNDEFINED: return "architectural UNDEFINED observed; exception delivery unavailable";
    case OCNEXT_A64_FAULT_SYSTEM_ACCESS: return "modeled system access trap; exception delivery unavailable";
    case OCNEXT_A64_FAULT_EXCEPTION_RETURN: return "exception return outside supported profile; commit cancelled";
    case OCNEXT_A64_FAULT_SYNC_PROVIDER: return "memory synchronization provider failed";
    case OCNEXT_A64_FAULT_MAINTENANCE_PROVIDER: return "translation maintenance provider failed";
    case OCNEXT_A64_FAULT_HVC_PROVIDER: return "hvc provider broke its contract";
    default: return "unknown fault code";
    }
}
