/* Original bounded implementation from Arm DDI0553B.y ComputePAC and the
 * QARMA paper, not imported from an upstream software implementation.
 * Provenance and independently observed synthetic fixtures are documented in
 * docs/implementation-pac-services.md. This is not an Apple PAC provider.
 */
#include "ocnext/pac_qarma5.h"

static const uint8_t permutation[16] =
    {13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15};
static const uint8_t tweak_permutation[16] =
    {4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9};
static const uint8_t sbox[16] =
    {11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10};
static const uint8_t inverse_sbox[16] =
    {5, 14, 13, 8, 10, 11, 1, 9, 2, 6, 15, 0, 4, 12, 7, 3};
static const uint64_t round_constant[5] = {
    UINT64_C(0), UINT64_C(0x13198a2e03707344),
    UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
    UINT64_C(0x452821e638d01377)
};

static uint64_t substitute(uint64_t value, int inverse)
{
    const uint8_t *box = inverse ? inverse_sbox : sbox;
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 16; ++i)
        result |= (uint64_t)box[(value >> (4u * i)) & 15u] << (4u * i);
    return result;
}

static uint64_t shuffle(uint64_t value, int inverse)
{
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        unsigned from = inverse ? i : permutation[i];
        unsigned to = inverse ? permutation[i] : i;
        result |= ((value >> (4u * from)) & 15u) << (4u * to);
    }
    return result;
}

static uint8_t rotate_cell(uint8_t value, unsigned amount)
{
    return (uint8_t)(((unsigned)value << amount |
                     (unsigned)value >> (4u - amount)) & 15u);
}

static uint64_t mix(uint64_t value)
{
    uint64_t result = 0;
    unsigned column;
    for (column = 0; column < 4; ++column) {
        uint8_t a = (uint8_t)((value >> (4u * column)) & 15u);
        uint8_t b = (uint8_t)((value >> (4u * (column + 4u))) & 15u);
        uint8_t c = (uint8_t)((value >> (4u * (column + 8u))) & 15u);
        uint8_t d = (uint8_t)((value >> (4u * (column + 12u))) & 15u);
        result |= (uint64_t)(rotate_cell(b, 1) ^ rotate_cell(c, 2) ^
                            rotate_cell(d, 1)) << (4u * column);
        result |= (uint64_t)(rotate_cell(a, 1) ^ rotate_cell(c, 1) ^
                            rotate_cell(d, 2)) << (4u * (column + 4u));
        result |= (uint64_t)(rotate_cell(a, 2) ^ rotate_cell(b, 1) ^
                            rotate_cell(d, 1)) << (4u * (column + 8u));
        result |= (uint64_t)(rotate_cell(a, 1) ^ rotate_cell(b, 2) ^
                            rotate_cell(c, 1)) << (4u * (column + 12u));
    }
    return result;
}

static uint64_t tweak(uint64_t value, int inverse)
{
    /* LFSR is applied to these output cells of the forward permutation. */
    const unsigned rotate_mask = 0xd894u;
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        unsigned from = inverse ? i : tweak_permutation[i];
        unsigned to = inverse ? tweak_permutation[i] : i;
        unsigned cell = (unsigned)((value >> (4u * from)) & 15u);
        if ((rotate_mask >> i) & 1u) {
            if (inverse)
                cell = ((cell << 1) & 15u) | ((cell ^ (cell >> 3)) & 1u);
            else
                cell = (cell >> 1) | (((cell ^ (cell >> 1)) & 1u) << 3);
        }
        result |= (uint64_t)cell << (4u * to);
    }
    return result;
}

uint64_t ocnext_pac_qarma5_mac(uint64_t data, uint64_t modifier,
                              uint64_t key_lo, uint64_t key_hi)
{
    const uint64_t alpha = UINT64_C(0xc0ac29b7c97c50dd);
    const uint64_t reflected_key = ((key_hi >> 1) | (key_hi << 63)) ^
                                    (key_hi >> 63);
    uint64_t state = data ^ key_hi;
    uint64_t current_tweak = modifier;
    unsigned round;

    for (round = 0; round < 5; ++round) {
        state ^= key_lo ^ current_tweak ^ round_constant[round];
        if (round != 0)
            state = mix(shuffle(state, 0));
        state = substitute(state, 0);
        current_tweak = tweak(current_tweak, 0);
    }
    state ^= reflected_key ^ current_tweak;
    state = substitute(mix(shuffle(state, 0)), 0);
    state = shuffle(mix(shuffle(state, 0)) ^ key_lo, 1);
    state = shuffle(mix(substitute(state, 1)), 1);
    state ^= key_hi ^ current_tweak;
    for (round = 0; round < 5; ++round) {
        state = substitute(state, 1);
        if (round != 4)
            state = shuffle(mix(state), 1);
        current_tweak = tweak(current_tweak, 1);
        state ^= round_constant[4u - round] ^ key_lo ^ current_tweak ^ alpha;
    }
    return state ^ reflected_key;
}
