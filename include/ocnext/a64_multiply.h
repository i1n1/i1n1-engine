#ifndef OCNEXT_A64_MULTIPLY_H
#define OCNEXT_A64_MULTIPLY_H
#include <stdint.h>
#define OCNEXT_A64_MUL_ABI 1u
#define OCNEXT_A64_MUL_RN_KNOWN 1u
#define OCNEXT_A64_MUL_RM_KNOWN 2u
#define OCNEXT_A64_MUL_RA_KNOWN 4u
#define OCNEXT_A64_MUL_KNOWN_ALL 7u
#define OCNEXT_A64_MUL_NZCV_MASK UINT32_C(0xf0000000)
enum ocnext_a64_mul_status { OCNEXT_A64_MUL_OK=0,
    OCNEXT_A64_MUL_UNSUPPORTED=1, OCNEXT_A64_MUL_ARGUMENT=2 };
/* Native ABI1 request48/alignment8, not CPU/guest/wire state.
 * Each operand-known bit means the actual source read width is known.
 * Sources31 are ZR; high forms have fixed inactive Ra31. Supplied inactive/ZR
 * values and knowledge are ignored, not inferred architectural state.
 * Known physical aliases must agree at their common read width; unknown
 * aliases remain conservatively unsupported. All active operands are needed
 * even for Rd31. No flag is read: raw NZCV and its knowledge are preserved.
 * Unknown flags may be nonzero. No implicit known-zero flags are issued.
 * Native spans must be properly allocated, stable, serialized and disjoint.
 * Numeric span checks do not certify ownership or hostile-host isolation.
 */
struct ocnext_a64_mul_request {
    uint32_t abi_version, opcode;
    uint64_t rn_value, rm_value, ra_value;
    uint32_t nzcv;
    uint8_t operand_known, nzcv_known, reserved[10];
};
struct ocnext_a64_mul_effect {
    uint64_t result; /* Rd31: inactive canonical0, write_gpr0 */
    uint32_t nzcv, destination, abi_version;
    uint8_t width, rn_rm_width, write_gpr, nzcv_known, reserved[8];
};
/* Exact ten allocated variants only; all outside forms remain unsupported.
 * No NOT_ALLOCATED/guest exception classification is inferred.
 * prepare changes no CPU,PC,SP,retirement,flags or memory and preserves all
 * request/output bytes on failure. A successful effect publishes once.
 */
int ocnext_a64_mul_decode(uint32_t opcode);
enum ocnext_a64_mul_status ocnext_a64_mul_prepare(
    const struct ocnext_a64_mul_request *request,
    struct ocnext_a64_mul_effect *effect);
#endif
