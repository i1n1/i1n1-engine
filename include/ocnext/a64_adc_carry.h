#ifndef OCNEXT_A64_ADC_CARRY_H
#define OCNEXT_A64_ADC_CARRY_H
#include <stdint.h>
#define OCNEXT_A64_ADC_ABI 1u
#define OCNEXT_A64_ADC_RN_KNOWN 1u
#define OCNEXT_A64_ADC_RM_KNOWN 2u
#define OCNEXT_A64_ADC_FLAGS_N 8u
#define OCNEXT_A64_ADC_FLAGS_Z 4u
#define OCNEXT_A64_ADC_FLAGS_C 2u
#define OCNEXT_A64_ADC_FLAGS_V 1u
#define OCNEXT_A64_ADC_FLAGS_ALL 15u
#define OCNEXT_A64_ADC_NZCV_MASK UINT32_C(0xf0000000)
enum ocnext_a64_adc_status {
    OCNEXT_A64_ADC_OK = 0,
    OCNEXT_A64_ADC_UNSUPPORTED = 1,
    OCNEXT_A64_ADC_ARGUMENT = 2,
    OCNEXT_A64_ADC_NOT_ALLOCATED = 3
};
/* Host-private ABI1,32B/alignment8. No CPU/ONXT/Apple guest ABI change.
 * Values are complete native GPR storage; W reads ignore high32 bits.
 * operand_known means complete operand knowledge only when source != ZR.
 * Same encoded active source requires equal known values at the read width;
 * inconsistent known snapshots are an API argument error, not guest fault.
 * A zero/any stored value without a known bit is UNKNOWN, not zero.
 * nzcv stores only bits31:28; known nibble is independently N/Z/C/V.
 * Unknown stored flags may be nonzero and are preserved for nonS forms.
 * Request/effect must be properly allocated, stable, serialized and disjoint.
 * Numeric C pointer validation does not probe/certify ownership or lifetime.
 */
struct ocnext_a64_adc_request {
    uint32_t abi_version;
    uint32_t opcode;
    uint64_t rn_value;
    uint64_t rm_value;
    uint32_t nzcv;
    uint8_t operand_known;
    uint8_t nzcv_known;
    uint8_t reserved[2];
};
struct ocnext_a64_adc_effect {
    uint64_t result; /* inactive/discard result canonical0, not a known ZR write */
    uint32_t nzcv;
    uint32_t destination;
    uint32_t abi_version;
    uint8_t width;
    uint8_t write_gpr;
    uint8_t write_nzcv;
    uint8_t nzcv_known;
    uint8_t reserved[8];
};
/* Decode1 only for exact allocated ADC/ADCS/SBC/SBCS W/X, else0.
 * prepare returns an effect, never commits PC/retire/SP/register state.
 * NonOK preserves complete request and effect bytes. No automatic UDF entry.
 * Only an explicitly primary-proven narrow reserved set may return3;
 * excluded allocated FlagM/other instructions always unsupported.
 */
int ocnext_a64_adc_decode(uint32_t opcode);
enum ocnext_a64_adc_status ocnext_a64_adc_prepare(
    const struct ocnext_a64_adc_request *request,
    struct ocnext_a64_adc_effect *effect);
#endif
