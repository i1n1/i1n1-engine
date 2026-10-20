#ifndef OCNEXT_MMU_CPU_H
#define OCNEXT_MMU_CPU_H

#include "ocnext/mmu.h"
#include "ocnext/ordering.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_MMU_CPU_ABI_VERSION 4u
#define OCNEXT_MMU_MAINTENANCE_ABI_VERSION 1u
enum ocnext_mmu_maintenance_profile { OCNEXT_MMU_MAINTENANCE_SERIAL_NORMAL_RAM=1 };
enum ocnext_mmu_feature_profile { OCNEXT_MMU_FEATURE_SERIAL_S1_PA48_ASID16=1 };
/* Caller-owned ABI1/64B evidence, serialized stateless Normal-RAM stage1.
 * Completion uses an actual host seq_cst fence and publishes a translation
 * epoch; every later dispatch must walk/fetch afresh. No hardware TLB, SMP,
 * DMA, MMIO, JIT or cache-maintenance capability is implied. */
struct ocnext_mmu_maintenance {
    uint64_t events, host_fences, translation_epoch;
    struct ocnext_a64_maintenance_request last;
    uint32_t abi_version, profile;
};

/* A single CPU, caller-owned page tables/bus, CPU-owned MMU register bank,
 * no TLB, IRQ or MMIO. Ordinary accesses use CPU.current_el. Prospective vector
 * and ERET fetches use a temporary MMU copy with destination EL and preserve
 * the original provider diagnostics/configuration. PAN is explicitly supplied
 * in mmu.config; this CPU profile does not model PSTATE.PAN.
 */
struct ocnext_mmu_cpu {
    struct ocnext_a64_cpu *cpu;
    struct ocnext_mmu *mmu;
    struct ocnext_a64_memory memory;
    struct ocnext_mmu_fault captured_abort;
    struct ocnext_a64_fault captured_cpu_fault;
    uint64_t captured_exception_count;
    uint8_t captured_el;
    uint8_t abort_pending;
    uint8_t configuration_rejected;
    struct ocnext_a64_mmu_registers rejected_mmu;
    struct ocnext_ordering ordering;
    struct ocnext_mmu_maintenance maintenance;
};

/* Configure only before execution, with opt-in EL1_SYNC profile. No allocation.
 * Import mmu.config as a fully known CPU register bank when the CPU bank is
 * wholly UNKNOWN. A configured bank must match initial config: SCTLR must be
 * known; M0 allows partial knowledge with unknown fields stored/configured0;
 * M1 needs all five known. No silent SCTLR RES1 normalization. Subsequently
 * CPU registers own translation; changes to mmu.config are not guest writes.
 * An error leaves output/CPU unchanged. Caller owns all objects/lifetimes.
 */
int ocnext_mmu_cpu_init(struct ocnext_mmu_cpu *, struct ocnext_a64_cpu *,
                       struct ocnext_mmu *);
/* Explicit initial-only provider certification, not automatic from a bus
 * pointer. Caller promises ordering.h's serialized Normal-RAM contract. init
 * leaves barriers unsupported until this capability is configured. */
int ocnext_mmu_cpu_configure_ordering(struct ocnext_mmu_cpu *,
                                     enum ocnext_ordering_profile);
/* Initial-only, explicit provider certifications. Maintenance additionally
 * requires configured serialized ordering. Features require a validated
 * adapter/walker and an UNKNOWN bank, never a flat-memory callback alone. */
int ocnext_mmu_cpu_configure_maintenance(struct ocnext_mmu_cpu *,
                                   enum ocnext_mmu_maintenance_profile);
int ocnext_mmu_cpu_configure_features(struct ocnext_mmu_cpu *,
                                   enum ocnext_mmu_feature_profile);
/* One dispatch attempt; an architectural memory fault remains observable and
 * sticky. Delivery is a separate explicit call, not automatic retry or NOP.
 * A captured abort is valid only for this precise CPU fault/EL/exception count.
 */
enum ocnext_a64_result ocnext_mmu_cpu_step(struct ocnext_mmu_cpu *);
/* Translation only (AT instructions): walks with the CPU's current registers but the given
 * privilege (el0 != 0 translates as EL0) and PAN consideration. Returns the walker result;
 * *fault is filled for OCNEXT_MMU_ABORT. No state of the adapter or CPU changes. */
enum ocnext_mmu_result ocnext_mmu_cpu_translate(struct ocnext_mmu_cpu *, uint64_t va,
                                               enum ocnext_a64_access access, unsigned el0, unsigned pan,
                                               struct ocnext_mmu_translation *out,
                                               struct ocnext_mmu_fault *fault);
/* Same dispatch with HVC/sysreg hooks (see ocnext_a64_step_hooks); NULL == step(). */
enum ocnext_a64_result ocnext_mmu_cpu_step_hooks(struct ocnext_mmu_cpu *,
                                               const struct ocnext_a64_hooks *);
enum ocnext_a64_result ocnext_mmu_cpu_deliver_abort(struct ocnext_mmu_cpu *);

#ifdef __cplusplus
}
#endif
#endif
