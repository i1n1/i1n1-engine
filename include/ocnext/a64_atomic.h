#ifndef OCNEXT_A64_ATOMIC_H
#define OCNEXT_A64_ATOMIC_H
#include <stdint.h>
#include "ocnext/a64.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_A64_ATOMIC_ABI 1u
enum ocnext_a64_atomic_status {
    OCNEXT_A64_ATOMIC_OK = 0,
    OCNEXT_A64_ATOMIC_UNSUPPORTED = 1, /* caller reports a deterministic stop */
    OCNEXT_A64_ATOMIC_FAULT = 2        /* effect.fault_* describes the stop */
};

/* Register results are staged by the caller; the helper never writes GPRs,
 * PC or flags. reg==31 is a discarded result (XZR). count<=2. */
struct ocnext_a64_atomic_effect {
    uint64_t value[2];
    uint64_t fault_address;
    uint32_t fault_size;
    enum ocnext_a64_fault_code fault_code;
    enum ocnext_a64_access fault_access;
    uint8_t reg[2], width[2], count, reserved;
};

/* Families (single-core semantics, see docs/contracts/exclusives.md):
 *  - load/store exclusive LDXR/LDAXR/STXR/STLXR (B/H/W/X), LDXP/LDAXP/
 *    STXP/STLXP (W/X pairs), CLREX
 *  - ordered LDAR/STLR (B/H/W/X), RCpc LDAPR(B/H/W/X), LDAPUR and STLUR families
 *  - LSE LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN/SWP and
 *    CAS/CASP, every acquire/release variant, B/H/W/X sizes
 * decode returns nonzero for the whole encoding region owned here, including
 * encodings that execute then rejects as unsupported (never NOP).
 */
int ocnext_a64_atomic_decode(uint32_t opcode);
int ocnext_a64_atomic_is_clrex(uint32_t opcode);

/* Performs the guest memory side effects and exclusive-monitor updates for one
 * instruction. On UNSUPPORTED and FAULT no guest memory has been changed.
 * Rn==31 uses cpu->sp (the caller checks SP alignment first). */
enum ocnext_a64_atomic_status ocnext_a64_atomic_execute(
    struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
    uint32_t opcode, struct ocnext_a64_atomic_effect *effect);

/* Local exclusive monitor, stored in the CPU's idle fault record: while
 * cpu->fault.code == NONE, fault.address holds the monitored VA and
 * fault.access_size the monitored size (0 = Open access state). A real fault
 * overwrites the record (a faulted CPU never resumes) and exception entry
 * clears the monitor. No vector-bank bytes are used, so CPU size is unchanged.
 * A caller that snapshots/restores the whole CPU therefore snapshots the
 * monitor. */
void ocnext_a64_exclusive_clear(struct ocnext_a64_cpu *cpu);
/* Clears the monitor when [address,address+size) overlaps the monitored
 * range. Called for every plain guest store by the same PE. */
void ocnext_a64_exclusive_clear_overlap(struct ocnext_a64_cpu *cpu,
                                        uint64_t address, uint64_t size);
/* Diagnostic read: returns 1 and fills address/size when the monitor is in
 * the Exclusive Access state, else 0. */
int ocnext_a64_exclusive_state(const struct ocnext_a64_cpu *cpu,
                               uint64_t *address, unsigned *size);
#ifdef __cplusplus
}
#endif
#endif
