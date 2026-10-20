#ifndef OCNEXT_MMU_H
#define OCNEXT_MMU_H

#include "ocnext/a64.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_MMU_ABI_VERSION 2u
#define OCNEXT_MMU_MAX_TRANSFER 32u
#define OCNEXT_MMU_MAX_SPANS 2u

/* Base, non-secure EL1&0, no EL2/EL3/stage2/LPA2/MTE/HA/HD/HPD/EPAN.
 * 4K/16K/64K geometry, 25..48-bit VA, 32..48-bit PA. No TLB/cache or
 * device memory ordering is advertised. SCTLR.A alignment and active MTE
 * controls/Tagged Normal MAIR are rejected. CPU register ownership stays outside.
 */
struct ocnext_mmu_config {
    uint64_t tcr_el1, ttbr0_el1, ttbr1_el1, sctlr_el1, mair_el1;
    uint8_t current_el, pan;
    /* Nonzero: accesses to Device-attribute pages are passed to the bus (MMIO) instead of being
     * refused. The bus decides what exists; unmapped or refused device accesses still fail. */
    uint8_t allow_device;
    uint8_t reserved[5];
};

enum ocnext_mmu_result { OCNEXT_MMU_OK=0, OCNEXT_MMU_ABORT=1,
                         OCNEXT_MMU_UNSUPPORTED=2, OCNEXT_MMU_ARGUMENT=3 };
enum ocnext_mmu_fault_kind { OCNEXT_MMU_FAULT_NONE=0,
    OCNEXT_MMU_FAULT_ADDRESS_SIZE, OCNEXT_MMU_FAULT_TRANSLATION,
    OCNEXT_MMU_FAULT_ACCESS_FLAG, OCNEXT_MMU_FAULT_PERMISSION,
    OCNEXT_MMU_FAULT_TABLE_BUS, OCNEXT_MMU_FAULT_DATA_BUS,
    OCNEXT_MMU_FAULT_UNSUPPORTED, OCNEXT_MMU_FAULT_ARGUMENT };

struct ocnext_mmu_fault {
    enum ocnext_mmu_fault_kind kind;
    enum ocnext_a64_access access;
    uint64_t va, descriptor_address;
    uint32_t esr_el1;
    uint8_t level, far_valid, ttbr_region, syndrome_valid;
};

struct ocnext_mmu_translation {
    uint64_t pa, mapping_bytes;
    uint16_t asid;
    uint8_t level, granule_shift, attr_index, mair_attribute, shareability;
    uint8_t nonglobal, device, writable, user_accessible, pxn, uxn;
};

struct ocnext_mmu_span { uint64_t pa; size_t offset, bytes; };
/* The physical bus must be trusted, bounds checked and stable during one
 * transfer. RAM reads have no side effects. writev must validate ALL spans
 * before any mutation and atomically commit or return failure. No host pointer
 * is derived from guest PA by the walker. ABI2 raises the bounded Normal RAM
 * transfer from16 to32 bytes for one SIMD pair; two preflighted spans still
 * suffice for the minimum4KiB granule. Struct layouts/adapter ABI are unchanged.
 * Device transfers are unsupported. A pair store is one all-or-none writev,
 * a pair load stages all bytes before publishing either destination.
 * read/probe return 0 only for the whole range; access describes data/fetch.
 */
struct ocnext_mmu_bus {
    void *context;
    int (*read)(void *, uint64_t, uint8_t *, size_t);
    int (*probe)(void *, uint64_t, size_t, enum ocnext_a64_access);
    int (*writev)(void *, const struct ocnext_mmu_span *, size_t,
                  const uint8_t *, size_t);
};

struct ocnext_mmu {
    struct ocnext_mmu_config config;
    struct ocnext_mmu_bus bus;
    struct ocnext_mmu_fault fault;
};

enum ocnext_mmu_result ocnext_mmu_validate(const struct ocnext_mmu_config *);
enum ocnext_mmu_result ocnext_mmu_translate(struct ocnext_mmu *, uint64_t,
                    enum ocnext_a64_access, struct ocnext_mmu_translation *);
int ocnext_mmu_read(void *, uint64_t, uint8_t *, size_t, enum ocnext_a64_access);
int ocnext_mmu_write(void *, uint64_t, const uint8_t *, size_t);
/* Snapshot last precise translation/bus failure. It is an observation until a
 * caller explicitly delivers an architectural abort through the CPU API.
 * UNSUPPORTED/ARGUMENT have no valid syndrome and must not be guest aborts.
 */
const struct ocnext_mmu_fault *ocnext_mmu_last_fault(const struct ocnext_mmu *);

#ifdef __cplusplus
}
#endif
#endif
