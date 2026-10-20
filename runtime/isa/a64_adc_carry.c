#include "ocnext/a64_adc_carry.h"
#include <stddef.h>
#include <stdint.h>
_Static_assert(sizeof(struct ocnext_a64_adc_request) == 32, "request32");
_Static_assert(sizeof(struct ocnext_a64_adc_effect) == 32, "effect32");
_Static_assert(_Alignof(struct ocnext_a64_adc_request) == 8, "request alignment8");
_Static_assert(_Alignof(struct ocnext_a64_adc_effect) == 8, "effect alignment8");
_Static_assert(offsetof(struct ocnext_a64_adc_request, nzcv) == 24, "request flags24");
_Static_assert(offsetof(struct ocnext_a64_adc_effect, reserved) == 24, "effect reserved24");

static int span(const void *pointer, uintptr_t *start, uintptr_t *last)
{
    uintptr_t p = (uintptr_t)pointer;
    if (!pointer || (p & 7u) || p > UINTPTR_MAX - 31u) return 0;
    *start = p;
    *last = p + 31u;
    return 1;
}

int ocnext_a64_adc_decode(uint32_t opcode)
{
    return (opcode & UINT32_C(0x1fe0fc00)) == UINT32_C(0x1a000000);
}

/* Arm DDI0487H.a C4-583: these two literal words reach the Rotate-right-
 * into-flags table's sf0 and sf1/op0/S0 unallocated rows. This intentionally
 * narrow classification is not a major-class wildcard or guest UDF delivery.
 * Allocated FlagM/other nonwhitelist variants stay coverage unsupported.
 */
static enum ocnext_a64_adc_status outside(uint32_t opcode)
{
    if (opcode == UINT32_C(0x1a000400) || opcode == UINT32_C(0x9a000400))
        return OCNEXT_A64_ADC_NOT_ALLOCATED;
    return OCNEXT_A64_ADC_UNSUPPORTED;
}

enum ocnext_a64_adc_status ocnext_a64_adc_prepare(
    const struct ocnext_a64_adc_request *request,
    struct ocnext_a64_adc_effect *effect)
{
    uintptr_t rs, re, es, ee;
    uint64_t a, b, mask, interim, result;
    uint32_t flags;
    unsigned width, rn, rm, rd, carry, subtract, set_flags, first_carry, second_carry, i;
    struct ocnext_a64_adc_effect staged;
    if (!span(request, &rs, &re) || !span(effect, &es, &ee) || (rs <= ee && es <= re))
        return OCNEXT_A64_ADC_ARGUMENT;
    if (request->abi_version != OCNEXT_A64_ADC_ABI ||
        (request->operand_known & ~3u) || (request->nzcv_known & ~15u) ||
        (request->nzcv & ~OCNEXT_A64_ADC_NZCV_MASK) || request->reserved[0] || request->reserved[1])
        return OCNEXT_A64_ADC_ARGUMENT;
    if (!ocnext_a64_adc_decode(request->opcode)) return outside(request->opcode);
    rn = (request->opcode >> 5) & 31u;
    rm = (request->opcode >> 16) & 31u;
    rd = request->opcode & 31u;
    width = (request->opcode >> 31) ? 64u : 32u;
    mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    if (rn == rm && rn != 31 && request->operand_known == 3u &&
        ((request->rn_value ^ request->rm_value) & mask)) return OCNEXT_A64_ADC_ARGUMENT;
    if (!(request->nzcv_known & OCNEXT_A64_ADC_FLAGS_C) ||
        (rn != 31 && !(request->operand_known & OCNEXT_A64_ADC_RN_KNOWN)) ||
        (rm != 31 && !(request->operand_known & OCNEXT_A64_ADC_RM_KNOWN)))
        return OCNEXT_A64_ADC_UNSUPPORTED;
    a = rn == 31 ? 0 : request->rn_value & mask;
    b = rm == 31 ? 0 : request->rm_value & mask;
    carry = (request->nzcv >> 29) & 1u;
    subtract = (request->opcode >> 30) & 1u;
    set_flags = (request->opcode >> 29) & 1u;
    if (subtract) b = ~b & mask;
    /* N-bit addition in two unsigned steps. Masking makes32-bit wrap
     * visible even though the host type is64. No shift by64 or signed sum. */
    interim = (a + b) & mask;
    first_carry = interim < a;
    result = (interim + carry) & mask;
    second_carry = result < interim;
    flags = request->nzcv;
    if (set_flags) {
        unsigned negative = (unsigned)((result >> (width - 1u)) & 1u);
        unsigned overflow = (unsigned)(((~(a ^ b) & (a ^ result)) >> (width - 1u)) & 1u);
        flags = (negative << 31) | ((result == 0u) << 30) |
                ((first_carry | second_carry) << 29) | (overflow << 28);
    }
    staged.result = rd == 31 ? 0 : result;
    staged.nzcv = flags;
    staged.destination = rd;
    staged.abi_version = OCNEXT_A64_ADC_ABI;
    staged.width = (uint8_t)width;
    staged.write_gpr = (uint8_t)(rd != 31);
    staged.write_nzcv = (uint8_t)set_flags;
    staged.nzcv_known = set_flags ? OCNEXT_A64_ADC_FLAGS_ALL : request->nzcv_known;
    for (i = 0; i < sizeof(staged.reserved); ++i) staged.reserved[i] = 0;
    /* A single publication boundary: stable serialized native objects,
     * no fallible call and no guest memory/CPU activity after the first byte. */
    for (i = 0; i < sizeof(staged); ++i)
        ((uint8_t *)effect)[i] = ((const uint8_t *)&staged)[i];
    return OCNEXT_A64_ADC_OK;
}
