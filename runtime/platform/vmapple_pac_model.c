/* Independently authored transition model for the separately named
 * UTM_12_5_1 source profile. No upstream implementation text is included.
 * This numeric model neither handles guest HVCs nor issues Apple key state.
 */
#include "ocnext/vmapple_pac_model.h"

_Static_assert(sizeof(struct ocnext_vmapple_pac_model_state) == 128, "state128");
_Static_assert(sizeof(struct ocnext_vmapple_pac_model_request) == 80, "request80");
_Static_assert(sizeof(struct ocnext_vmapple_pac_model_effect) == 240, "effect240");
_Static_assert(_Alignof(struct ocnext_vmapple_pac_model_state) == 8, "state alignment8");
_Static_assert(_Alignof(struct ocnext_vmapple_pac_model_request) == 8, "request alignment8");
_Static_assert(_Alignof(struct ocnext_vmapple_pac_model_effect) == 8, "effect alignment8");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_state, key_halves) == 16, "halves16");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_state, apctl_value) == 112, "APCTL112");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_state, apctl_known_mask) == 120, "APCTL knowledge120");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_request, gpr) == 16, "input GPR16");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_request, esr) == 56, "ESR56");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_request, context_known_mask) == 64, "context64");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_request, reserved) == 76, "request reserved76");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_effect, gpr_write_mask) == 56, "GPR writes56");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_effect, after) == 64, "after64");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_effect, sync_intents) == 192, "intents192");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_effect, sync_count) == 224, "count224");
_Static_assert(offsetof(struct ocnext_vmapple_pac_model_effect, reserved) == 232, "effect reserved232");

struct model_span {
    uintptr_t first, last;
};

static int make_span(const void *object, size_t bytes, struct model_span *span)
{
    uintptr_t first = (uintptr_t)object;
    if (!object || (first & 7u) || !bytes || first > UINTPTR_MAX - (bytes - 1u))
        return 0;
    span->first = first;
    span->last = first + bytes - 1u;
    return 1;
}

static int spans_disjoint(const struct model_span *spans)
{
    unsigned i, j;
    for (i = 0; i != 3; ++i)
        for (j = i + 1; j != 3; ++j)
            if (spans[i].first <= spans[j].last && spans[j].first <= spans[i].last)
                return 0;
    return 1;
}

/* Explicit byte operations keep this bounded model free of libc imports.
 * Publication is one logical operation for a serialized native caller; it is
 * not a concurrent240-byte atomic store or a native-pointer sandbox.
 */
static void copy_bytes(void *destination, const void *source, size_t bytes)
{
    volatile unsigned char *out = destination;
    const unsigned char *in = source;
    size_t i;
    for (i = 0; i != bytes; ++i) out[i] = in[i];
}

static void clear_bytes(void *destination, size_t bytes)
{
    volatile unsigned char *out = destination;
    size_t i;
    for (i = 0; i != bytes; ++i) out[i] = 0;
}

static int canonical_state(const struct ocnext_vmapple_pac_model_state *state)
{
    unsigned i;
    if (state->abi_version != OCNEXT_VMAPPLE_PAC_MODEL_ABI_VERSION ||
        state->bytes != sizeof(*state) ||
        state->profile > OCNEXT_VMAPPLE_PAC_MODEL_PROFILE_UTM_12_5_1 ||
        (state->key_known_mask & ~OCNEXT_VMAPPLE_PAC_MODEL_KEYS_ALL) ||
        (state->apctl_value & ~state->apctl_known_mask)) return 0;
    for (i = 0; i != 12; ++i)
        if (!(state->key_known_mask & (1u << i)) && state->key_halves[i]) return 0;
    return 1;
}

static int canonical_request(const struct ocnext_vmapple_pac_model_request *request)
{
    unsigned i;
    if (request->abi_version != OCNEXT_VMAPPLE_PAC_MODEL_ABI_VERSION ||
        request->bytes != sizeof(*request) ||
        request->profile > OCNEXT_VMAPPLE_PAC_MODEL_PROFILE_UTM_12_5_1 ||
        (request->known_gpr_mask & ~OCNEXT_VMAPPLE_PAC_MODEL_GPR_ALL) ||
        (request->context_known_mask & ~OCNEXT_VMAPPLE_PAC_MODEL_ESR_KNOWN) ||
        request->hacr_bit4 > OCNEXT_VMAPPLE_PAC_MODEL_HACR_ENABLED ||
        (request->materialized_bank_mask & ~OCNEXT_VMAPPLE_PAC_MODEL_BANK_ALL) ||
        request->reserved) return 0;
    if (!(request->context_known_mask & OCNEXT_VMAPPLE_PAC_MODEL_ESR_KNOWN) && request->esr)
        return 0;
    for (i = 0; i != 5; ++i)
        if (!(request->known_gpr_mask & (1u << i)) && request->gpr[i]) return 0;
    return 1;
}

static void set_gpr(struct ocnext_vmapple_pac_model_effect *effect,
                    unsigned index, uint64_t value)
{
    effect->gpr[index] = value;
    effect->gpr_write_mask |= 1u << index;
    effect->known_gpr_mask |= 1u << index;
}

static void set_pair(struct ocnext_vmapple_pac_model_effect *effect,
                     unsigned first, uint64_t value)
{
    uint32_t bits = 3u << first;
    effect->after.key_halves[first] = value;
    effect->after.key_halves[first + 1u] = value + UINT64_C(1);
    effect->after.key_known_mask |= bits;
    effect->state_write_mask |= bits;
}

static int has_bank(const struct ocnext_vmapple_pac_model_request *request,
                    uint32_t banks)
{
    return (request->materialized_bank_mask & banks) == banks;
}

enum ocnext_vmapple_pac_model_code ocnext_vmapple_pac_model_prepare(
    const struct ocnext_vmapple_pac_model_state *state,
    const struct ocnext_vmapple_pac_model_request *request,
    struct ocnext_vmapple_pac_model_effect *output)
{
    /* These are literals from the declared historical source profile only.
     * Storage order is the public model ABI, not a physical register layout.
     */
    static const uint64_t initial[12] = {
        UINT64_C(0xfeedfacefeedfacf), UINT64_C(0xfeedfacefeedfad0),
        UINT64_C(0xfeedfacefeedfad5), UINT64_C(0xfeedfacefeedfad6),
        UINT64_C(0xfeedfacefeedfad1), UINT64_C(0xfeedfacefeedfad2),
        UINT64_C(0xfeedfacefeedfad7), UINT64_C(0xfeedfacefeedfad8),
        UINT64_C(0xfeedfacefeedfad9), UINT64_C(0xfeedfacefeedfada),
        UINT64_C(0xfeedfacefeedfad3), UINT64_C(0xfeedfacefeedfad4)
    };
    struct model_span spans[3];
    struct ocnext_vmapple_pac_model_effect staged;
    unsigned i, pair;
    uint32_t banks;
    uint64_t seed;

    /* Complete all native range/alias checks before the first typed input
     * read. Addressability and serialized lifetime remain caller obligations.
     */
    if (!make_span(state, sizeof(*state), &spans[0]) ||
        !make_span(request, sizeof(*request), &spans[1]) ||
        !make_span(output, sizeof(*output), &spans[2]) || !spans_disjoint(spans))
        return OCNEXT_VMAPPLE_PAC_MODEL_ARGUMENT;
    if (!canonical_state(state) || !canonical_request(request) ||
        state->profile != request->profile) return OCNEXT_VMAPPLE_PAC_MODEL_ARGUMENT;
    if (state->profile == OCNEXT_VMAPPLE_PAC_MODEL_PROFILE_NONE)
        return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
    if (!(request->context_known_mask & OCNEXT_VMAPPLE_PAC_MODEL_ESR_KNOWN))
        return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;

    clear_bytes(&staged, sizeof(staged));
    staged.abi_version = OCNEXT_VMAPPLE_PAC_MODEL_ABI_VERSION;
    staged.bytes = (uint32_t)sizeof(staged);
    staged.known_gpr_mask = request->known_gpr_mask;
    for (i = 0; i != 5; ++i) staged.gpr[i] = request->gpr[i];
    copy_bytes(&staged.after, state, sizeof(*state));

    /* A known route decline needs no unavailable X0 value. The raw syndrome
     * is64-bit exactly as in the versioned source; no extra IL/ISS filter is
     * invented. Recognition never uses X0's upper32 bits as a namespace gate.
     */
    if ((request->esr >> 26) != UINT64_C(0x16) ||
        (request->esr & UINT64_C(0xffff))) goto publish;
    if (!(request->known_gpr_mask & 1u)) return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
    if ((request->gpr[0] & UINT64_C(0xff000000)) != UINT64_C(0xc1000000))
        goto publish;
    staged.selector = (uint32_t)(request->gpr[0] & UINT64_C(0xffffff));
    staged.handled = 1;
    if (staged.selector > 6u) goto denied;
    if (request->hacr_bit4 == OCNEXT_VMAPPLE_PAC_MODEL_HACR_UNKNOWN)
        return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
    if (request->hacr_bit4 == OCNEXT_VMAPPLE_PAC_MODEL_HACR_DISABLED) goto denied;

    if (staged.selector == 0u) {
        if (!has_bank(request, OCNEXT_VMAPPLE_PAC_MODEL_BANK_ALL))
            return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
        for (i = 0; i != 12; ++i) staged.after.key_halves[i] = initial[i];
        staged.after.key_known_mask = OCNEXT_VMAPPLE_PAC_MODEL_KEYS_ALL;
        staged.after.apctl_value = UINT64_C(0x11);
        staged.after.apctl_known_mask = UINT64_MAX;
        staged.state_write_mask = OCNEXT_VMAPPLE_PAC_MODEL_STATE_ALL;
        for (i = 0; i != 3; ++i) staged.sync_intents[i] = OCNEXT_VMAPPLE_PAC_MODEL_SYNC_PAC;
        staged.sync_intents[3] = OCNEXT_VMAPPLE_PAC_MODEL_SYNC_KERN;
        staged.sync_count = 4;
    } else if (staged.selector == 1u) {
        set_gpr(&staged, 1, initial[0]);
        set_gpr(&staged, 2, initial[2]);
        set_gpr(&staged, 3, initial[10]);
        set_gpr(&staged, 4, initial[8]);
    } else if (staged.selector == 5u) {
        if (!has_bank(request, OCNEXT_VMAPPLE_PAC_MODEL_BANK_KERN) ||
            (request->known_gpr_mask & 6u) != 6u)
            return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
        if (request->gpr[1] <= UINT64_C(1)) {
            if (!has_bank(request, OCNEXT_VMAPPLE_PAC_MODEL_BANK_PAC))
                return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
            staged.after.apctl_value = (staged.after.apctl_value & ~UINT64_C(2)) |
                                      (request->gpr[1] << 1);
            staged.after.apctl_known_mask |= UINT64_C(2);
            staged.state_write_mask |= UINT32_C(1) << 12;
        }
        set_pair(&staged, 10, request->gpr[2]);
        staged.sync_intents[0] = OCNEXT_VMAPPLE_PAC_MODEL_SYNC_KERN;
        staged.sync_count = 1;
    } else {
        banks = staged.selector == 4u ? OCNEXT_VMAPPLE_PAC_MODEL_BANK_KERN :
                                      OCNEXT_VMAPPLE_PAC_MODEL_BANK_PAC;
        if (!has_bank(request, banks) || !(request->known_gpr_mask & 2u))
            return OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED;
        seed = request->gpr[1];
        pair = staged.selector == 2u ? 0u : staged.selector == 3u ? 2u :
               staged.selector == 4u ? 10u : 8u;
        set_pair(&staged, pair, seed);
        if (staged.selector == 2u || staged.selector == 3u)
            set_pair(&staged, pair + 4u, seed + UINT64_C(2));
        staged.sync_intents[0] = banks == OCNEXT_VMAPPLE_PAC_MODEL_BANK_KERN ?
            OCNEXT_VMAPPLE_PAC_MODEL_SYNC_KERN : OCNEXT_VMAPPLE_PAC_MODEL_SYNC_PAC;
        staged.sync_count = 1;
    }
    set_gpr(&staged, 0, 0);
    goto publish;

denied:
    set_gpr(&staged, 0, UINT64_C(0xffffffff));
publish:
    copy_bytes(output, &staged, sizeof(staged));
    return OCNEXT_VMAPPLE_PAC_MODEL_PREPARED;
}
