#ifndef OCNEXT_A64_H
#define OCNEXT_A64_H

#include <stddef.h>
#include <stdint.h>
#include "ocnext/pac_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ABI v12: bounded A64 interpreter with explicit optional EL1
 * register profile. This is not a complete privileged CPU/MMU model.
 * No allocation or libc dependency. All guest accesses are little-endian and
 * go through the supplied memory callbacks. x[0..30] are GPRs; encoding 31 is
 * interpreted as SP or ZR by each instruction, never a mutable x[31].
 */
#define OCNEXT_A64_ABI_VERSION 12u
#define OCNEXT_A64_CPU_BYTES 1248u
#define OCNEXT_A64_VECTOR_REGISTERS_ABI_VERSION 1u
#define OCNEXT_A64_VECTOR_REGISTERS_BYTES 592u
#define OCNEXT_A64_VECTOR_KNOWN_ALL UINT16_C(0xffff)
#define OCNEXT_A64_FP_REGISTERS_ABI_VERSION 1u
#define OCNEXT_A64_FP_KNOWN_CPACR 1u
#define OCNEXT_A64_FP_KNOWN_FPCR 2u
#define OCNEXT_A64_FP_KNOWN_FPSR 4u
#define OCNEXT_A64_FP_KNOWN_ALL 7u
#define OCNEXT_A64_PAC_REGISTERS_ABI_VERSION 2u
#define OCNEXT_A64_PAC_HALF_KNOWN_ALL UINT32_C(0x3ff)
#define OCNEXT_A64_MEMORY_ABI_VERSION 4u
#define OCNEXT_A64_FEATURE_KNOWN_MMFR0 1u
/* Named software stage-1 profile, not the development Mac's CPU identity:
 * PA48, ASID16, 4/16/64KiB, little endian, no stage2/EL2/EL3. A validated
 * software-MMU adapter issues this capability; a flat bus does not. */
#define OCNEXT_A64_MMFR0_S1_PA48_ASID16 UINT64_C(0x0000011100100025)
#define OCNEXT_A64_TLS_KNOWN_EL0 1u
#define OCNEXT_A64_TLS_KNOWN_RO_EL0 2u
#define OCNEXT_A64_TLS_KNOWN_EL1 4u
#define OCNEXT_A64_TLS_KNOWN_ALL 7u
#define OCNEXT_A64_MMU_KNOWN_TCR 1u
#define OCNEXT_A64_MMU_KNOWN_TTBR0 2u
#define OCNEXT_A64_MMU_KNOWN_TTBR1 4u
#define OCNEXT_A64_MMU_KNOWN_SCTLR 8u
#define OCNEXT_A64_MMU_KNOWN_MAIR 16u
#define OCNEXT_A64_MMU_KNOWN_ALL 31u
/* Chosen base no-AArch32/no-PAN/no-ExS profile RES1 fields. Requiring them
 * in writes is conservative coverage policy, not an architectural fault rule. */
#define OCNEXT_A64_SCTLR_RES1 UINT64_C(0x30d009a0)
#define OCNEXT_A64_SP_ALIGN_CONTRACT 1u
#define OCNEXT_A64_SCTLR_SA UINT64_C(0x8)
#define OCNEXT_A64_SCTLR_SA0 UINT64_C(0x10)
#define OCNEXT_A64_SCTLR_DYNAMIC_MASK UINT64_C(0x00080219) /* WXN, UMA, SA0, SA, M */
/* EnIA, EnIB, EnDA, EnDB: accepted only under an explicitly configured
 * synthetic PAC research profile. They do not advertise architectural IDs. */
#define OCNEXT_A64_SCTLR_PAC_ENABLE_MASK UINT64_C(0xc8002000)
#define OCNEXT_A64_TCR_SUPPORTED_MASK UINT64_C(0x00180077ffffffbf)
#define OCNEXT_A64_KNOWN_ELR 1u
#define OCNEXT_A64_KNOWN_SPSR 2u
#define OCNEXT_A64_KNOWN_ESR 4u
#define OCNEXT_A64_KNOWN_FAR 8u
#define OCNEXT_A64_KNOWN_VBAR 16u
#define OCNEXT_A64_DAIF_MASK UINT32_C(0x3c0)
#define OCNEXT_A64_N UINT32_C(0x80000000)
#define OCNEXT_A64_Z UINT32_C(0x40000000)
#define OCNEXT_A64_C UINT32_C(0x20000000)
#define OCNEXT_A64_V UINT32_C(0x10000000)
#define OCNEXT_A64_TEST_HALT_IMMEDIATE UINT16_C(0x4f4e)

enum ocnext_a64_access {
    OCNEXT_A64_ACCESS_FETCH = 0,
    OCNEXT_A64_ACCESS_READ = 1,
    OCNEXT_A64_ACCESS_WRITE = 2
};

enum ocnext_a64_fault_code {
    OCNEXT_A64_FAULT_NONE = 0,
    OCNEXT_A64_FAULT_UNSUPPORTED = 1,
    OCNEXT_A64_FAULT_FETCH = 2,
    OCNEXT_A64_FAULT_READ = 3,
    OCNEXT_A64_FAULT_WRITE = 4,
    OCNEXT_A64_FAULT_ALIGNMENT = 5,
    OCNEXT_A64_FAULT_DEBUG_HALT = 6,
    OCNEXT_A64_FAULT_ARGUMENT = 7,
    /* Legacy debug profile's software UNDEFINED observation. The separate
     * sync profile performs guest entry instead of emitting this runtime code. */
    OCNEXT_A64_FAULT_UNDEFINED = 8,
    /* Legacy debug profile's trap observation; sync profile enters a vector. */
    OCNEXT_A64_FAULT_SYSTEM_ACCESS = 9,
    /* Invalid/unsupported return under this model, not implementation of
     * architectural illegal-return PSTATE.IL handling. CPU commit cancelled. */
    OCNEXT_A64_FAULT_EXCEPTION_RETURN = 10,
    /* Provider rejected/failed a modeled barrier. No guest syndrome is
     * invented and the instruction/architectural state is not committed. */
    OCNEXT_A64_FAULT_SYNC_PROVIDER = 11,
    OCNEXT_A64_FAULT_MAINTENANCE_PROVIDER = 12,
    /* HVC hook broke its contract (bad nx / resume_pc / status). No CPU commit. */
    OCNEXT_A64_FAULT_HVC_PROVIDER = 13
};

enum ocnext_a64_system_profile {
    OCNEXT_A64_SYSTEM_SCALAR = 0,
    /* Armv8 OS lock + DAIF/CurrentEL; only EL0/EL1 exist, no EL2/EL3 traps,
     * external debug interface or exception delivery. OSLAR accepts 0/1;
     * MSR DAIF accepts bits9:6 only. Nonzero RES0 writes are unsupported-model
     * policy, not mandated faults. UMA controls EL0 DAIF access explicitly. */
    OCNEXT_A64_SYSTEM_ARMV8_EL1_DEBUG = 1,
    /* Actual A64 synchronous EL0/EL1 vector entry and bounded ERET subset.
     * No internal MMU, IRQ, EL2/3, AArch32 or complete PSTATE support.
     * An external adapter can explicitly deliver captured memory aborts. */
    OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC = 2
};

/* CPU-owned, caller-initialized bank. Reset has known_mask=0 (UNKNOWN),
 * distinguishable from explicitly supplied SCTLR.M=0. No TLB/cache is modeled.
 * Each unknown field must be stored as zero under this deterministic policy.
 * Base MAIR only, no CnP, no PA52/LPA2/MTE/HA/HD/HPD/DS.
 * The optional PAC bank below gates PAC enable bits; no algorithm IDs are
 * advertised by this bounded research interpreter. */
struct ocnext_a64_mmu_registers {
    uint64_t tcr_el1, ttbr0_el1, ttbr1_el1, sctlr_el1, mair_el1;
    uint32_t known_mask, reserved;
};

/* Opaque software IDs, not pointers dereferenced by the CPU. Unknown fields
 * use stored0/known-clear and cannot be read as fabricated known values. */
struct ocnext_a64_tls_registers {
    uint64_t tpidr_el0, tpidrro_el0, tpidr_el1;
    uint32_t known_mask, reserved;
};

/* Reset UNKNOWN is stored0/known-clear. A known MMFR0 is accepted only for
 * the named software profile; it does not qualify an Apple CPU or boot state. */
struct ocnext_a64_feature_registers {
    uint64_t id_aa64mmfr0_el1;
    uint32_t known_mask, reserved;
};

enum ocnext_a64_pac_profile {
    OCNEXT_A64_PAC_NONE = 0,
    OCNEXT_A64_PAC_PAUTH2 = 1,
    OCNEXT_A64_PAC_FPAC = 2,
    /* FEAT_PAuth without PAuth2/FPAC (e.g. original v8.3 behaviour): a failed
     * authentication retires with an error code in the pointer. Combined
     * branch authentication uses the same failure behaviour. */
    OCNEXT_A64_PAC_PAUTH1 = 3
};
enum ocnext_a64_pac_combined_mode {
    OCNEXT_A64_PAC_COMBINED_UNKNOWN = 0,
    OCNEXT_A64_PAC_NO_COMBINED_FPAC = 1,
    OCNEXT_A64_PAC_COMBINED_FPAC = 2
};
/* CPU-owned native POD ABI2/112B, appended at CPU offset512. This is distinct
 * from the native issuer key-bank ABI; guest key writes never provision that
 * bank or Apple services. Each key's Lo/Hi knowledge is independent:
 * bit(2*index) for Lo, bit(2*index+1) for Hi. Unknown halves are stored0.
 * Reset is ABI2 with all other fields0; NONE means coverage UNKNOWN.
 * Active profiles require owner_id!=0 and write_epoch>=1, and permit an empty
 * knowledge mask. write_epoch advances atomically on a guest half-register
 * write; it is a software diagnostic, not Apple key diversification.
 * PAUTH2/FPAC select synthetic QARMA5 pointer behavior only. No CPU feature
 * register, full PAuth ISA, host key or Apple boot capability is implied.
 * combined_mode independently declares the behavior of combined branch/auth;
 * UNKNOWN never implies COMBINED_FPAC from the standalone FPAC profile.
 * NO_COMBINED_FPAC uses PAuth2 corruption for combined authentication even
 * under standalone FPAC. This modeled APA4 composition has no current APA4
 * differential qualification; actual QEMU references cover APA3/APA5 only. */
struct ocnext_a64_pac_registers {
    struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT];
    uint64_t owner_id, write_epoch;
    uint32_t pointer_profile, half_known_mask, abi_version, combined_mode;
};
/* CPU-owned native ABI1/32B at offset624. UNKNOWN reset is stored0 with
 * known bits clear, not an architectural reset-value or Apple boot claim.
 * This bank records explicitly modeled control/access state only. It does
 * not implement floating-point arithmetic, vector data, SVE or advertise an
 * ID register. CPU12's separate vector bank and integer/memory subsets use
 * a known CPACR as their access prerequisite, as do FPCR/FPSR accesses.
 * Unsupported feature/control bits are rejected by the bounded profile. */
struct ocnext_a64_fp_registers {
    uint64_t cpacr_el1, fpcr, fpsr;
    uint32_t known_mask, abi_version;
};

struct ocnext_a64_system_state {
    uint8_t profile;
    uint8_t current_el;
    uint8_t os_lock; /* Cold reset 1 under the opt-in Armv8 profile. */
    uint8_t reserved; /* SCTLR policy selector (ocnext_a64_configure_sctlr_profile); 0 = BASE. */
    uint32_t daif; /* PSTATE bits9:6 only; IRQ delivery is not implemented. */
    uint8_t uma; /* Derived from known bank.SCTLR bit9; legacy explicit policy otherwise. */
    uint8_t reserved_access[3];
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t vbar_el1;
    uint64_t esr_el1;
    uint64_t far_el1;
    uint64_t elr_el1;
    uint64_t spsr_el1;
    uint64_t exception_count;
    uint32_t known_state;
    uint8_t spsel;
    uint8_t reserved_sync[3];
    struct ocnext_a64_mmu_registers mmu;
    struct ocnext_a64_tls_registers tls;
    struct ocnext_a64_feature_registers features;
};

enum ocnext_a64_result {
    OCNEXT_A64_RETIRED = 0,
    OCNEXT_A64_HALTED = 1,
    OCNEXT_A64_FAULTED = 2,
    OCNEXT_A64_BUDGET = 3,
    OCNEXT_A64_EXCEPTION = 4 /* Guest sync entry committed; run continues. */
};

struct ocnext_a64_fault {
    enum ocnext_a64_fault_code code;
    enum ocnext_a64_access access;
    uint64_t pc;
    uint64_t address;
    uint32_t opcode;
    uint32_t access_size;
    uint8_t syndrome_ec;
    uint8_t target_el;
    uint8_t has_syndrome;
    uint8_t reserved;
};

/* Native CPU-owned ABI1/592B, alignment16. Byte i is architectural bits
 * [8i+7:8i] independently of native integer/host SIMD layout. A clear
 * knowledge bit requires stored0; it never denotes an architectural zero.
 * All V0..V31 are ordinary registers. There is no vector ZR/SP encoding.
 * This bank is not an XSTATE context, wire resource or feature issuer. */
struct ocnext_a64_vector_registers {
#ifdef __cplusplus
    alignas(16) uint8_t bytes[32][16];
#else
    _Alignas(16) uint8_t bytes[32][16];
#endif
    uint16_t known_bytes[32];
    uint32_t abi_version;
    uint8_t reserved[12];
};

/* Hint / maintenance state lives in what used to be padding, so the frozen
 * CPU12/1248B layout and every bank offset stay unchanged:
 *   - cpu.ext_state (3 bytes after strict_data_alignment): ext_state bits are
 *     OCNEXT_A64_EXT_*; ext_dczid_bs is DCZID_EL0.BS (0 = not configured);
 *     ext_at_active is a transient AT-callback handshake and is 0 between steps.
 *   - system.reserved_access[3] + system.reserved_sync[3]: PAR_EL1, packed into
 *     48 bits (bit 47 = known). Only canonical values produced by an AT result
 *     can be stored (see ocnext_a64_publish_par_el1).
 * PSTATE.PAN/UAO/DIT/SSBS, the single-PE event register (SEV/SEVL set, WFE
 * consumes) and the TOUCHED marker (guest used PAN/SSBS, so exception entry
 * needs SCTLR.SPAN/DSSBS) are reset to 0. */
#define OCNEXT_A64_EXT_PAN 1u
#define OCNEXT_A64_EXT_UAO 2u
#define OCNEXT_A64_EXT_DIT 4u
#define OCNEXT_A64_EXT_SSBS 8u
#define OCNEXT_A64_EXT_EVENT 16u
#define OCNEXT_A64_EXT_TOUCHED 32u
/* Mirrors of SCTLR_EL1.SPAN==0 / DSSBS==1 when a caller profile stores those bits outside the
 * MMU bank (ocnext_a64_hooks.sctlr_ext_mask); exception entry reads them. Reset to 0. */
#define OCNEXT_A64_EXT_SPAN_CLEAR 64u
#define OCNEXT_A64_EXT_DSSBS 128u
#define OCNEXT_A64_EXT_ALL 255u

/* Sub-reason for a deterministic OCNEXT_A64_FAULT_UNSUPPORTED stop, stored in
 * cpu->fault.reserved (0 = plain unsupported encoding). Pure diagnostics. */
enum ocnext_a64_unsupported_reason {
    OCNEXT_A64_REASON_NONE = 0,
    OCNEXT_A64_REASON_WFI_NO_WAKE = 1,      /* WFI: no interrupt source is modeled */
    OCNEXT_A64_REASON_WFE_NO_EVENT = 2,     /* WFE with event register clear, single PE */
    OCNEXT_A64_REASON_BTI_ENFORCED = 3,     /* SCTLR.BT0/BT1 set: guarded-page checks unmodeled */
    OCNEXT_A64_REASON_SCTLR_UNKNOWN = 4,    /* required SCTLR control bit is UNKNOWN */
    OCNEXT_A64_REASON_PAR_UNKNOWN = 5,      /* MRS PAR_EL1 before any AT result */
    OCNEXT_A64_REASON_PAR_WRITE = 6,        /* guest MSR PAR_EL1 is not modeled */
    OCNEXT_A64_REASON_DCZID_UNKNOWN = 7,    /* DC ZVA block size not configured */
    OCNEXT_A64_REASON_DIT_ENTRY = 8,        /* exception entry with PSTATE.DIT=1 unmodeled */
    OCNEXT_A64_REASON_ENTRY_SCTLR_UNKNOWN = 9, /* SPAN/DSSBS needed at exception entry */
    OCNEXT_A64_REASON_NO_PROVIDER = 10,     /* maintenance provider not attached */
    OCNEXT_A64_REASON_PROVIDER_REFUSED = 11,/* provider reported UNSUPPORTED */
    OCNEXT_A64_REASON_OPERAND_FORMAT = 12,  /* operand value outside modeled format */
    OCNEXT_A64_REASON_PSTATE_FORMAT = 13,   /* MSR/MRS PSTATE value outside modeled bits */
    OCNEXT_A64_REASON_COUNT = 14
};
const char *ocnext_a64_unsupported_reason_string(unsigned reason);

struct ocnext_a64_cpu {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t retired;
    uint32_t nzcv; /* ARM architectural bits 31..28; other bits stay zero. */
    uint32_t last_opcode;
    struct ocnext_a64_fault fault;
    uint16_t halt_immediate;
    uint8_t halted;
    uint8_t allow_test_halt; /* Default 0. Only exact 0x4f4e fixture sentinel. */
    uint8_t strict_data_alignment; /* Optional bounded RAM-test policy. */
    uint8_t ext_state, ext_dczid_bs, ext_at_active; /* see OCNEXT_A64_EXT_* */
    struct ocnext_a64_system_state system;
    struct ocnext_a64_pac_registers pac;
    struct ocnext_a64_fp_registers fp;
    struct ocnext_a64_vector_registers vector;
};

/* Return 0 only after the whole requested range has been transferred.
 * Callbacks must check address+size overflow and ownership/bounds. A failure
 * must not change guest memory. Writes (including 16-byte pairs) are atomic
 * as a callback transaction: preflight every byte/page before mutation.
 * Successful reads have no externally visible partial-transfer side effects.
 * Callbacks alone do not create syndromes. External translation providers can
 * supply captured ESR/FAR through explicit abort delivery. MMIO/device ordering
 * remains unsupported; providers must retain the exact-fault contract.
 */
typedef int (*ocnext_a64_read_fn)(void *context, uint64_t address,
                                uint8_t *destination, size_t size,
                                enum ocnext_a64_access access);
typedef int (*ocnext_a64_write_fn)(void *context, uint64_t address,
                                 const uint8_t *source, size_t size);
/* Optional prospective instruction read for exception-entry/ERET validation.
 * Returns bytes under the destination EL/PSTATE view without changing CPU or
 * source-provider state. PSTATE contains only this profile's modeled fields.
 * This replaces the preflight read, avoiding a second read under the old EL.
 * NULL selects legacy flat-provider FETCH behavior. Always zero-initialize
 * the memory struct before assigning callbacks; ABI4 size is 48 on x64/arm64. */
typedef int (*ocnext_a64_fetch_view_fn)(void *context, uint64_t address,
                                      uint8_t *destination, size_t size,
                                      unsigned prospective_el,
                                      uint64_t prospective_pstate);

enum ocnext_a64_sync_kind { OCNEXT_A64_SYNC_DMB=1, OCNEXT_A64_SYNC_DSB=2, OCNEXT_A64_SYNC_ISB=3 };
enum ocnext_a64_sync_domain { OCNEXT_A64_SYNC_OUTER=0, OCNEXT_A64_SYNC_NONSHAREABLE=1,
    OCNEXT_A64_SYNC_INNER=2, OCNEXT_A64_SYNC_SYSTEM=3 };
enum ocnext_a64_sync_types { OCNEXT_A64_SYNC_READS=1, OCNEXT_A64_SYNC_WRITES=2, OCNEXT_A64_SYNC_ALL=3 };
enum ocnext_a64_sync_result { OCNEXT_A64_SYNC_COMPLETED=0, OCNEXT_A64_SYNC_UNSUPPORTED=1,
    OCNEXT_A64_SYNC_FAILED=2 };
/* Request ABI1/32 bytes on supported x64/arm64. DMB READS means reads before
 * to reads AND writes after; WRITES means writes before/after; ALL means both.
 * DSB additionally requires completion of selected accesses. ISB requires a
 * context synchronization event, not just data ordering. option is the exact
 * CRm immediate. The supported subset excludes reserved, SSBB/PSSBB and nXS.
 * request has callback lifetime only; copy it by value for diagnostics. */
struct ocnext_a64_sync_request {
    uint64_t pc;
    uint32_t opcode;
    enum ocnext_a64_sync_kind kind;
    enum ocnext_a64_sync_domain domain;
    enum ocnext_a64_sync_types types;
    uint8_t option, current_el, reserved[6];
};
/* Explicit provider capability. Return COMPLETED only after the requested
 * operation is fulfilled under the provider's documented execution model.
 * Unsupported/failure must not publish a successful event or mutate CPU/RAM.
 * Missing callback is unsupported; the core never substitutes a NOP/fence.
 * Provider/host fences do not prove SMP, DMA/MMIO, cache or TLB correctness. */
typedef enum ocnext_a64_sync_result (*ocnext_a64_sync_fn)(void *context,
                                       const struct ocnext_a64_sync_request *request);

enum ocnext_a64_maintenance_kind { OCNEXT_A64_MAINTENANCE_VMALLE1=1,
    /* TLBI by VA/ASID, operand = Xt. Local and inner-shareable scopes. */
    OCNEXT_A64_MAINTENANCE_TLBI_VAE1=2, OCNEXT_A64_MAINTENANCE_TLBI_ASIDE1=3,
    OCNEXT_A64_MAINTENANCE_TLBI_VAAE1=4, OCNEXT_A64_MAINTENANCE_TLBI_VALE1=5,
    OCNEXT_A64_MAINTENANCE_TLBI_VAALE1=6,
    /* Instruction cache. IVAU operand = VA. */
    OCNEXT_A64_MAINTENANCE_IC_IALLUIS=7, OCNEXT_A64_MAINTENANCE_IC_IALLU=8,
    OCNEXT_A64_MAINTENANCE_IC_IVAU=9,
    /* Data cache by VA (operand = VA) and by set/way (operand = Xt). ZVA is
     * executed by the core as real zero stores and never reaches a provider. */
    OCNEXT_A64_MAINTENANCE_DC_IVAC=10, OCNEXT_A64_MAINTENANCE_DC_CVAC=11,
    OCNEXT_A64_MAINTENANCE_DC_CVAU=12, OCNEXT_A64_MAINTENANCE_DC_CIVAC=13,
    OCNEXT_A64_MAINTENANCE_DC_ISW=14, OCNEXT_A64_MAINTENANCE_DC_CSW=15,
    OCNEXT_A64_MAINTENANCE_DC_CISW=16,
    /* Stage1 address translation, operand = VA. On COMPLETED the provider must
     * have published PAR_EL1 with ocnext_a64_publish_par_el1() (canonical F=0
     * ATTR/PA/SH or F=1 FST forms with RES1 bit11 only); the core
     * refuses to retire the AT otherwise. */
    OCNEXT_A64_MAINTENANCE_AT_S1E1R=17, OCNEXT_A64_MAINTENANCE_AT_S1E1W=18,
    OCNEXT_A64_MAINTENANCE_AT_S1E0R=19, OCNEXT_A64_MAINTENANCE_AT_S1E0W=20,
    /* Stage1 EL1&0 TLBI in its outer-shareable (CRm=1,5) or range (CRm=2,5,6) encodings. request.opcode
     * identifies the operation; scope is INNER_SHAREABLE for CRm 1,2,5 and LOCAL for CRm 6. On a single
     * PE with no TLB these are ordering events that publish a translation epoch like the plain forms;
     * the range operand format is not interpreted (no TLB state to select). */
    OCNEXT_A64_MAINTENANCE_TLBI_OTHER=21 };
enum ocnext_a64_maintenance_scope { OCNEXT_A64_MAINTENANCE_LOCAL=1,
    OCNEXT_A64_MAINTENANCE_INNER_SHAREABLE=2 };
enum ocnext_a64_maintenance_stage { OCNEXT_A64_MAINTENANCE_STAGE1=1 };
enum ocnext_a64_maintenance_result { OCNEXT_A64_MAINTENANCE_COMPLETED=0,
    OCNEXT_A64_MAINTENANCE_UNSUPPORTED=1, OCNEXT_A64_MAINTENANCE_FAILED=2 };
/* Request ABI1/32 bytes. Exact local EL1&0 stage1 VMALLE1 only, all ASIDs and
 * levels, operand0/Rt31. This capability is separate from ordinary barriers.
 * Callback lifetime only; failures publish no CPU/RAM/event mutation. */
struct ocnext_a64_maintenance_request {
    uint64_t pc, operand;
    uint32_t opcode;
    enum ocnext_a64_maintenance_kind kind;
    uint8_t current_el, scope, stage, reserved[5];
};
typedef enum ocnext_a64_maintenance_result (*ocnext_a64_maintenance_fn)(void *,
                                    const struct ocnext_a64_maintenance_request *);

/* System-register provider (ocnext/a64_sysreg.h implements one), bound with
 * ocnext_a64_memory_bind_sysreg() below. Handles
 * MRS/MSR encodings the core has no dedicated handler for. `key` is opcode
 * bits [19:5] (o0-2, op1, CRn, CRm, op2). Missing callback or an encoding the
 * provider does not know is an UNSUPPORTED stop; the core never substitutes
 * RAZ/WI. A provider must not mutate its state when returning anything but OK.
 * UNDEFINED enters the guest UNDEFINED path, TRAP the EC 0x18 system-access
 * path. A read OK result is staged to Rt by the core. */
#define OCNEXT_A64_SYSREG_KEY(o0, op1, crn, crm, op2) \
    ((uint16_t)((((o0) - 2u) << 14) | ((op1) << 11) | ((crn) << 7) | ((crm) << 3) | (op2)))
enum ocnext_a64_sysreg_result {
    OCNEXT_A64_SYSREG_OK = 0, OCNEXT_A64_SYSREG_UNSUPPORTED = 1,
    OCNEXT_A64_SYSREG_UNDEFINED = 2, OCNEXT_A64_SYSREG_TRAP = 3
};
struct ocnext_a64_sysreg_request {
    uint64_t pc, value; /* value: MSR source operand */
    uint32_t opcode;
    uint16_t key;
    uint8_t is_read, current_el;
};
typedef enum ocnext_a64_sysreg_result (*ocnext_a64_sysreg_fn)(void *context,
        const struct ocnext_a64_sysreg_request *request, uint64_t *read_value);

struct ocnext_a64_memory {
    void *context;
    ocnext_a64_read_fn read;
    ocnext_a64_write_fn write;
    ocnext_a64_fetch_view_fn fetch_view;
    ocnext_a64_sync_fn sync;
    ocnext_a64_maintenance_fn maintenance;
};
/* Interim sysreg-provider binding. struct ocnext_a64_memory is ABI4 (48 bytes,
 * pinned by engine tests and firmware reports), so the provider is bound to
 * the memory object's ADDRESS instead of a new member. Bind before running,
 * from the thread that owns the memory object; the same address must be passed
 * to ocnext_a64_step/run (the DBT does). Returns 0, or -1 on bad argument /
 * full table (8 bindings). fn == NULL unbinds. Rebinding replaces. */
int ocnext_a64_memory_bind_sysreg(const struct ocnext_a64_memory *memory,
                                  ocnext_a64_sysreg_fn fn, void *context);

void ocnext_a64_reset(struct ocnext_a64_cpu *cpu, uint64_t entry_pc, uint64_t sp);
/* Initial-state configuration only: before retirement/halt/fault. Return 0 on
 * success; invalid profiles/EL or non-initial state return -1 without mutation.
 * Scalar reset remains the default. EL1 debug cold state starts locked; EL0
 * uses the same supported register identities but observes UNDEFINED access.
 */
int ocnext_a64_configure_system(struct ocnext_a64_cpu *cpu,
                               enum ocnext_a64_system_profile profile,
                               unsigned current_el);
/* Optional initial UMA/DAIF selection under the enabled EL1 profile. Default
 * UMA=0, DAIF=0x3c0 (masked reset-like policy; not a qualified Apple boot state).
 * Accept only UMA 0/1 and DAIF bits9:6, before retirement/halt/fault. */
int ocnext_a64_configure_daif_access(struct ocnext_a64_cpu *cpu,
                                    unsigned uma, uint32_t initial_daif);
/* Initial-only: declare the DC ZVA block size as DCZID_EL0.BS (log2 of the
 * size in 4-byte words, 2..9 => 16..2048 bytes; DZP=0). Until configured, DC ZVA
 * and MRS DCZID_EL0 are unsupported-model stops. Returns -1 unchanged on error. */
int ocnext_a64_configure_dczid(struct ocnext_a64_cpu *cpu, unsigned bs);
/* Maintenance-provider only, from inside an AT callback: publish the PAR_EL1
 * result. Rejects calls made outside an AT step. Returns 0 on success. */
int ocnext_a64_publish_par_el1(struct ocnext_a64_cpu *cpu, uint64_t par);
/* Returns 0 and PAR_EL1 once an AT result exists, -1 while it is UNKNOWN. */
int ocnext_a64_get_par_el1(const struct ocnext_a64_cpu *cpu, uint64_t *par);
int ocnext_a64_configure_banked_sp(struct ocnext_a64_cpu *cpu,
                                  uint64_t sp_el0, uint64_t sp_el1,
                                  unsigned spsel);
/* Initial-only SYNC-profile bank configuration, including explicit UNKNOWN
 * fields. No geometry/MMU-provider validation is performed here. Unsupported
 * field values, nonzero unknown values or reserved bytes return -1 unchanged.
 * If SCTLR is known, UMA derives from its bit9 and replaces legacy UMA policy.
 * MRS of an UNKNOWN bank field is an unsupported-model runtime fault.
 * EL0 access to these EL1 registers is UNDEFINED (EC0), not DAIF's EC0x18. */
int ocnext_a64_configure_mmu_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_mmu_registers *bank);
/* Initial-only SYNC-profile TLS state. All 64 bits are opaque software IDs;
 * partial known banks are permitted, unknown fields must be stored0. TPIDR_EL0
 * is RW at EL0/EL1, TPIDRRO_EL0 is EL0 R / EL1 RW, TPIDR_EL1 is EL1 RW.
 * Disallowed EL0 accesses enter UNDEFINED EC0; EL2/EL3 traps are not modeled. */
/* Initial-only SYNC-profile SCTLR_EL1 policy selection (before
 * ocnext_a64_configure_mmu_registers). BASE is the historical narrow policy;
 * APPLE is the documented per-bit policy of ocnext/a64_sysreg.h. */
#define OCNEXT_A64_SCTLR_PROFILE_BASE 0u
#define OCNEXT_A64_SCTLR_PROFILE_APPLE 1u
int ocnext_a64_configure_sctlr_profile(struct ocnext_a64_cpu *cpu, unsigned profile);
int ocnext_a64_configure_tls_registers(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_tls_registers *bank);
/* Initial-only SYNC-profile feature bank. Trusted initializer must bind a
 * known value to a validated software-MMU capability (adapter issuer API).
 * Only the exact named MMFR0 profile is allowed, no arbitrary host identity.
 * UNKNOWN stored0 remains permitted; invalid state is rejected unchanged. */
int ocnext_a64_configure_feature_registers(struct ocnext_a64_cpu *cpu,
                                  const struct ocnext_a64_feature_registers *bank);
/* Initial-only SYNC-profile configuration. Requires a valid native snapshot,
 * explicit owner/epoch for an active profile and stored0 unknown halves.
 * NONE cannot coexist with known nonzero SCTLR PAC enable bits. Rejects
 * invalid state without mutation. No guest memory or native issuer mutation. */
/* Post-start provisioning of ALL five PAC keys (IA,IB,DA,DB,GA), e.g. after a
 * platform INIT service derived them. Requires an active pointer profile and
 * every half currently UNKNOWN; sets all halves known and advances write_epoch.
 * Returns 0, or -1 without mutation. */
int ocnext_a64_provision_pac_keys(struct ocnext_a64_cpu *cpu,
                                 const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT]);
int ocnext_a64_configure_pac_registers(struct ocnext_a64_cpu *cpu,
                                   const struct ocnext_a64_pac_registers *bank);
/* Initial-only SYNC-profile configuration of explicit control knowledge.
 * Stable, aligned, disjoint CPU/bank native spans are required. Unknown
 * stored values must0. Failure preserves the whole CPU. No Apple boot-state,
 * FP/SIMD arithmetic or CPU feature capability is issued by this API. */
int ocnext_a64_configure_fp_registers(struct ocnext_a64_cpu *cpu,
                                    const struct ocnext_a64_fp_registers *bank);
/* Initial-only SYNC configuration of byte knowledge. Native16-aligned CPU
 * and bank spans must remain stable, serialized and disjoint; failure
 * preserves the CPU. No host SIMD/XSTATE or Apple initial state is inferred. */
int ocnext_a64_configure_vector_registers(struct ocnext_a64_cpu *cpu,
                                    const struct ocnext_a64_vector_registers *bank);
/* Explicit adapter for a captured, syndrome-valid MMU memory fault. Caller
 * snapshots provider fault before vector preflight (which can change provider
 * diagnostics). Accept only an existing ordinary FETCH/READ/WRITE fault and
 * A64 abort EC/IL/WnR matching current EL/access. On success clears runtime
 * fault and enters the mapped guest vector. Does not implement MMU/IRQ. */
enum ocnext_a64_result ocnext_a64_deliver_abort(struct ocnext_a64_cpu *cpu,
                                              const struct ocnext_a64_memory *memory,
                                              uint32_t esr, uint64_t far,
                                              unsigned far_valid);
/* Asynchronous interrupt exception entry at an instruction boundary (sync profile). IRQ is taken
 * only when PSTATE.I is clear, FIQ only when PSTATE.F is clear; otherwise nothing changes and
 * OCNEXT_A64_BUDGET is returned. On entry ELR=PC (the instruction not yet executed), SPSR holds the
 * old PSTATE, DAIF is fully masked, ESR/FAR are untouched, and OCNEXT_A64_EXCEPTION is returned.
 * Vector offsets follow the current EL/SP selection (+0x80 IRQ, +0x100 FIQ). Not retired. */
enum ocnext_a64_async_kind { OCNEXT_A64_ASYNC_IRQ = 1, OCNEXT_A64_ASYNC_FIQ = 2 };
enum ocnext_a64_result ocnext_a64_take_async(struct ocnext_a64_cpu *cpu,
                                            const struct ocnext_a64_memory *memory,
                                            enum ocnext_a64_async_kind kind);
enum ocnext_a64_result ocnext_a64_step(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory);

/* HVC #imm callback (sync profile only; there is no modeled EL2, so an EL1
 * HVC is a hypervisor-service call). Separate from ocnext_a64_memory so the
 * pinned memory/CPU ABIs are unchanged. A missing hook keeps HVC UNSUPPORTED
 * (deterministic fault, no NOP). HVC from EL0 is UNDEFINED and never reaches
 * the hook. */
#define OCNEXT_A64_HVC_ABI_VERSION 1u
enum ocnext_a64_hvc_result { OCNEXT_A64_HVC_COMPLETED = 0, OCNEXT_A64_HVC_UNSUPPORTED = 1,
    OCNEXT_A64_HVC_FAILED = 2 };
/* Callback-lifetime request. pstate is NZCV|DAIF|EL<<2|SPSel as modeled.
 * x[] are X0..X7 before the call; retired excludes the HVC itself. */
struct ocnext_a64_hvc_request {
    uint64_t pc, pstate, retired;
    uint64_t x[8];
    uint32_t opcode, imm16;
};
/* COMPLETED: engine writes out_x[0..nx-1] (nx <= 4) to X0.., requires
 * *resume_pc == pc + 4, retires the HVC and sets PC. Any other result (or a
 * contract violation) commits nothing: UNSUPPORTED/FAILED fault UNSUPPORTED,
 * a violation faults HVC_PROVIDER. The callback owns the stop reason. */
typedef enum ocnext_a64_hvc_result (*ocnext_a64_hvc_fn)(void *context,
        const struct ocnext_a64_hvc_request *request, uint64_t out_x[4],
        uint32_t *out_nx, uint64_t *out_resume_pc);
/* Generic MRS/MSR (register) callback for system registers the core does not
 * model natively. The policy (which registers exist, their read-only values,
 * stored-only semantics) belongs to the caller; the core only decodes. Missing
 * callback or UNSUPPORTED/FAILED commits nothing and faults UNSUPPORTED, so an
 * unknown register is a deterministic stop, never a NOP or zero. EL0 access to
 * op1!=3 registers is UNDEFINED in the core and never reaches the callback.
 * A write passes the Rt value; a read returns *read_value. */
#define OCNEXT_A64_HOOK_SYSREG_ABI_VERSION 1u
enum ocnext_a64_hook_sysreg_result { OCNEXT_A64_HOOK_SYSREG_COMPLETED = 0, OCNEXT_A64_HOOK_SYSREG_UNSUPPORTED = 1,
    OCNEXT_A64_HOOK_SYSREG_FAILED = 2 };
struct ocnext_a64_hook_sysreg_request {
    uint64_t pc, retired, value;
    uint32_t opcode;
    uint8_t op0, op1, crn, crm, op2, is_read, current_el, reserved;
};
typedef enum ocnext_a64_hook_sysreg_result (*ocnext_a64_hook_sysreg_fn)(void *context,
        const struct ocnext_a64_hook_sysreg_request *request, uint64_t *read_value);

/* Caller-owned hooks, callback lifetime. NULL members are unsupported.
 * sctlr_ext_mask/sctlr_ext_value: SCTLR_EL1 bits the caller's CPU profile
 * accepts as stored-with-no-modeled-effect (e.g. cache enables when no cache is
 * modeled). The core keeps the bank normalized (RES1 forced on in the mask) and
 * stores the real bits in *sctlr_ext_value; reads merge them back. Bits outside
 * the base-supported set and outside the mask stay unsupported. */
/* Local exclusive monitor (LDXR/STXR). Caller-owned so the pinned CPU ABI is unchanged;
 * no exclusives without it. Cleared by STXR and CLREX. */
struct ocnext_a64_exclusive { uint64_t address; uint8_t size, valid, reserved[6]; };
/* Address translation (AT S1E1R/W, S1E0R/W, S1E1RP/WP): the provider performs the stage-1 walk for
 * `va`, records PAR_EL1 itself, and returns 0 when it produced a PAR value (success or a faulting
 * translation, both are architectural results). Nonzero means unsupported: the core stops. */
typedef int (*ocnext_a64_at_fn)(void *context, uint64_t va, unsigned write, unsigned el0, unsigned pan_check);
#define OCNEXT_A64_CRYPTO_AES 1u
#define OCNEXT_A64_CRYPTO_PMULL 2u
#define OCNEXT_A64_CRYPTO_SHA1 4u
#define OCNEXT_A64_CRYPTO_SHA256 8u
struct ocnext_a64_hooks {
    ocnext_a64_hvc_fn hvc;
    void *hvc_context;
    ocnext_a64_hook_sysreg_fn sysreg;
    void *sysreg_context;
    uint64_t sctlr_ext_mask;
    uint64_t *sctlr_ext_value;
    struct ocnext_a64_exclusive *exclusive;
    /* Nonzero: trapped FP exceptions are not implemented, FPCR trap-enable bits are RAZ/WI. */
    uint32_t fp_traps_unimplemented;
    /* OCNEXT_A64_CRYPTO_* bits: Armv8 Cryptographic Extension classes this CPU model implements
     * (FEAT_AES/PMULL/SHA1/SHA256). 0 (default) keeps every crypto encoding a deterministic stop. */
    uint32_t crypto_extensions;
    ocnext_a64_at_fn at;
    void *at_context;
    /* Nonzero (research CPU profile): a SIMD&FP store whose source bytes are architecturally UNKNOWN
     * (never written since reset) writes the vector bank's deterministic unknown storage (0) to memory
     * instead of stopping. The register stays UNKNOWN; only the stored image is an assumption. 0
     * (default) keeps such a store a deterministic stop. Appended last: existing initialisers are
     * unaffected. */
    uint32_t unknown_vector_store_zero;
};
enum ocnext_a64_result ocnext_a64_step_hooks(struct ocnext_a64_cpu *cpu,
                                      const struct ocnext_a64_memory *memory,
                                      const struct ocnext_a64_hooks *hooks);
/* ABI4 budget limits dispatch attempts, including guest exception entries.
 * This bounds UDF/ERET loops that do not retire the faulting instruction.
 * Exhaustion is BUDGET, not fault or successful halt. Existing runtime
 * fault/halt is sticky until reset by the caller.
 */
enum ocnext_a64_result ocnext_a64_run(struct ocnext_a64_cpu *cpu,
                                     const struct ocnext_a64_memory *memory,
                                     uint64_t budget);
const char *ocnext_a64_fault_string(enum ocnext_a64_fault_code code);

#ifdef __cplusplus
}
#endif
#endif
