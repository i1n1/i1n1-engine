#ifndef OCNEXT_PAC_QARMA5_H
#define OCNEXT_PAC_QARMA5_H

#include <stdint.h>

#define OCNEXT_PAC_QARMA5_ABI_VERSION 1u

#ifdef __cplusplus
extern "C" {
#endif

/* Pure Arm ComputePAC/QARMA5-64 primitive. key_hi is key[127:64],
 * key_lo is key[63:0]; modifier is the 64-bit tweak. All input values are
 * accepted and the returned value is the full 64-bit MAC, not a signed pointer.
 * No guest registers, key generation, Apple diversification or HVC service are
 * implemented. This research implementation has no constant-time guarantee.
 * Use synthetic keys only until a separate secret-key threat model is audited.
 */
uint64_t ocnext_pac_qarma5_mac(uint64_t data, uint64_t modifier,
                              uint64_t key_lo, uint64_t key_hi);

#ifdef __cplusplus
}
#endif

#endif
