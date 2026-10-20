#include "ocnext/generic_timer.h"

/* Pure, serialized ABI1 arithmetic. No native clock, CPU, interrupt or callback
 * is consulted. Byte transfers avoid alignment/effective-type assumptions and
 * retain the complete objects; native accessibility remains the caller's duty. */
struct gt_span {
    uintptr_t first;
    uintptr_t after;
};

static int gt_span(const void *p, size_t bytes, struct gt_span *out)
{
    uintptr_t first = (uintptr_t)p;
    if (first == 0 || (first & 7u) != 0 ||
        bytes > UINTPTR_MAX || first > UINTPTR_MAX - bytes) {
        return 0;
    }
    out->first = first;
    out->after = first + bytes;
    return 1;
}

static int gt_disjoint(const struct gt_span *a, const struct gt_span *b)
{
    return a->after <= b->first || b->after <= a->first;
}

static void gt_copy(void *to, const void *from, size_t bytes)
{
    volatile unsigned char *d = to;
    const volatile unsigned char *s = from;
    size_t i;
    for (i = 0; i < bytes; ++i) {
        d[i] = s[i];
    }
}

static void gt_zero(void *to, size_t bytes)
{
    volatile unsigned char *d = to;
    size_t i;
    for (i = 0; i < bytes; ++i) {
        d[i] = 0;
    }
}

static int gt_count(uint64_t ns, uint64_t hz, uint64_t *out)
{
    const uint64_t billion = UINT64_C(1000000000);
    uint64_t q = ns / billion;
    uint64_t r = ns % billion;
    uint64_t whole;
    uint64_t fraction;
    if (hz == 0 || hz > billion || q > UINT64_MAX / hz ||
        r > UINT64_MAX / hz) {
        return 0;
    }
    whole = q * hz;
    fraction = (r * hz) / billion;
    if (whole > UINT64_MAX - fraction) {
        return 0;
    }
    *out = whole + fraction;
    return 1;
}

static uint32_t gt_ctl(uint32_t writable, uint64_t count, uint64_t cval)
{
    uint32_t ctl = writable & 3u;
    if ((ctl & 1u) != 0 && count >= cval) {
        ctl |= 4u;
    }
    return ctl;
}

static uint32_t gt_levels(uint32_t physical, uint32_t virtual_ctl)
{
    uint32_t levels = 0;
    if ((physical & 7u) == 5u) {
        levels |= 1u;
    }
    if ((virtual_ctl & 7u) == 5u) {
        levels |= 2u;
    }
    return levels;
}

static void gt_refresh(struct ocnext_generic_timer_state_v1 *s)
{
    s->physical_ctl = gt_ctl(s->physical_ctl, s->physical_count,
                            s->physical_cval);
    s->virtual_ctl = gt_ctl(s->virtual_ctl,
                           s->physical_count - s->virtual_offset,
                           s->virtual_cval);
    s->output_levels = gt_levels(s->physical_ctl, s->virtual_ctl);
}

static int gt_state_valid(const struct ocnext_generic_timer_state_v1 *s)
{
    uint64_t count;
    size_t i;
    if (s->abi_version != OCNEXT_GENERIC_TIMER_ABI ||
        s->bytes != sizeof(*s) || s->frequency_hz == 0 ||
        s->frequency_hz > UINT64_C(1000000000) ||
        s->sample_known > 1u || s->reserved0 != 0 || s->reserved1 != 0 ||
        (s->physical_ctl & ~7u) != 0 || (s->virtual_ctl & ~7u) != 0 ||
        (s->output_levels & ~3u) != 0 || s->sample_count == UINT64_MAX ||
        s->next_sequence != s->sample_count + 1u) {
        return 0;
    }
    for (i = 0; i < 4; ++i) {
        if (s->reserved[i] != 0) {
            return 0;
        }
    }
    if (s->sample_known == 0) {
        return s->last_ns == 0 && s->physical_count == 0 &&
               s->sample_count == 0 && s->physical_cval == 0 &&
               s->virtual_cval == 0 && s->physical_ctl == 0 &&
               s->virtual_ctl == 0 && s->output_levels == 0;
    }
    if (s->sample_count == 0 ||
        !gt_count(s->last_ns, s->frequency_hz, &count) ||
        count != s->physical_count ||
        gt_ctl(s->physical_ctl, count, s->physical_cval) != s->physical_ctl ||
        gt_ctl(s->virtual_ctl, count - s->virtual_offset,
               s->virtual_cval) != s->virtual_ctl ||
        gt_levels(s->physical_ctl, s->virtual_ctl) != s->output_levels) {
        return 0;
    }
    return 1;
}

static uint64_t gt_tval_cval(uint64_t count, uint64_t value)
{
    uint64_t low = (uint32_t)value;
    /* Unsigned sign extension defines both addition and wrap modulo 2^64. */
    if ((low & UINT64_C(0x80000000)) != 0) {
        low |= UINT64_C(0xffffffff00000000);
    }
    return count + low;
}

enum ocnext_generic_timer_code ocnext_generic_timer_init_v1(
    struct ocnext_generic_timer_state_v1 *state,
    const struct ocnext_generic_timer_config_v1 *config)
{
    struct gt_span a;
    struct gt_span b;
    struct ocnext_generic_timer_config_v1 c;
    struct ocnext_generic_timer_state_v1 staged;
    if (!gt_span(state, sizeof(*state), &a) ||
        !gt_span(config, sizeof(*config), &b) || !gt_disjoint(&a, &b)) {
        return OCNEXT_TIMER_ARGUMENT;
    }
    gt_copy(&c, config, sizeof(c));
    if (c.abi_version != OCNEXT_GENERIC_TIMER_ABI || c.bytes != sizeof(c) ||
        c.flags != 0 || c.reserved != 0 || c.frequency_hz == 0 ||
        c.frequency_hz > UINT64_C(1000000000)) {
        return OCNEXT_TIMER_ARGUMENT;
    }
    gt_zero(&staged, sizeof(staged));
    staged.abi_version = OCNEXT_GENERIC_TIMER_ABI;
    staged.bytes = sizeof(staged);
    staged.frequency_hz = c.frequency_hz;
    staged.virtual_offset = c.virtual_offset;
    staged.next_sequence = 1;
    gt_copy(state, &staged, sizeof(staged));
    return OCNEXT_TIMER_OK;
}

enum ocnext_generic_timer_code ocnext_generic_timer_step_v1(
    struct ocnext_generic_timer_state_v1 *state,
    const struct ocnext_generic_timer_request_v1 *request,
    struct ocnext_generic_timer_effect_v1 *effect)
{
    struct gt_span a;
    struct gt_span b;
    struct gt_span c;
    struct ocnext_generic_timer_state_v1 staged;
    struct ocnext_generic_timer_request_v1 r;
    struct ocnext_generic_timer_effect_v1 e;
    uint32_t old_levels;
    uint64_t virtual_count;
    if (!gt_span(state, sizeof(*state), &a) ||
        !gt_span(request, sizeof(*request), &b) ||
        !gt_span(effect, sizeof(*effect), &c) ||
        !gt_disjoint(&a, &b) || !gt_disjoint(&a, &c) ||
        !gt_disjoint(&b, &c)) {
        return OCNEXT_TIMER_ARGUMENT;
    }
    gt_copy(&r, request, sizeof(r));
    if (r.abi_version != OCNEXT_GENERIC_TIMER_ABI || r.bytes != sizeof(r) ||
        r.flags != 0 || r.reserved != 0) {
        return OCNEXT_TIMER_ARGUMENT;
    }
    gt_copy(&staged, state, sizeof(staged));
    if (!gt_state_valid(&staged) || r.sequence != staged.next_sequence) {
        return OCNEXT_TIMER_STATE;
    }
    if (r.operation < OCNEXT_TIMER_READ_PHYSICAL_COUNT ||
        r.operation > OCNEXT_TIMER_POLL) {
        return OCNEXT_TIMER_UNSUPPORTED;
    }
    if (staged.next_sequence == UINT64_MAX ||
        staged.sample_count == UINT64_MAX) {
        return OCNEXT_TIMER_OVERFLOW;
    }
    if (staged.sample_known != 0 && r.now_ns < staged.last_ns) {
        return OCNEXT_TIMER_CLOCK;
    }
    old_levels = staged.output_levels;
    if (!gt_count(r.now_ns, staged.frequency_hz, &staged.physical_count)) {
        return OCNEXT_TIMER_OVERFLOW;
    }
    staged.sample_known = 1;
    staged.last_ns = r.now_ns;
    virtual_count = staged.physical_count - staged.virtual_offset;
    switch (r.operation) {
    case OCNEXT_TIMER_WRITE_PHYSICAL_CVAL:
        staged.physical_cval = r.value;
        break;
    case OCNEXT_TIMER_WRITE_VIRTUAL_CVAL:
        staged.virtual_cval = r.value;
        break;
    case OCNEXT_TIMER_WRITE_PHYSICAL_TVAL:
        staged.physical_cval = gt_tval_cval(staged.physical_count, r.value);
        break;
    case OCNEXT_TIMER_WRITE_VIRTUAL_TVAL:
        staged.virtual_cval = gt_tval_cval(virtual_count, r.value);
        break;
    case OCNEXT_TIMER_WRITE_PHYSICAL_CTL:
        staged.physical_ctl = (uint32_t)r.value & 3u;
        break;
    case OCNEXT_TIMER_WRITE_VIRTUAL_CTL:
        staged.virtual_ctl = (uint32_t)r.value & 3u;
        break;
    default:
        break;
    }
    gt_refresh(&staged);
    ++staged.sample_count;
    ++staged.next_sequence;
    gt_zero(&e, sizeof(e));
    e.abi_version = OCNEXT_GENERIC_TIMER_ABI;
    e.bytes = sizeof(e);
    e.operation = r.operation;
    e.sequence = r.sequence;
    e.physical_count = staged.physical_count;
    e.now_ns = r.now_ns;
    e.output_levels = staged.output_levels;
    e.levels_changed = old_levels ^ staged.output_levels;
    e.next_sequence = staged.next_sequence;
    switch (r.operation) {
    case OCNEXT_TIMER_READ_PHYSICAL_COUNT:
        e.value = staged.physical_count;
        e.value_known_mask = UINT64_MAX;
        break;
    case OCNEXT_TIMER_READ_VIRTUAL_COUNT:
        e.value = virtual_count;
        e.value_known_mask = UINT64_MAX;
        break;
    case OCNEXT_TIMER_READ_FREQUENCY:
        e.value = staged.frequency_hz;
        e.value_known_mask = UINT64_MAX;
        break;
    case OCNEXT_TIMER_READ_PHYSICAL_CTL:
        e.value = staged.physical_ctl;
        e.value_known_mask = (staged.physical_ctl & 1u) != 0 ?
                             UINT64_MAX : UINT64_MAX ^ UINT64_C(4);
        break;
    case OCNEXT_TIMER_READ_VIRTUAL_CTL:
        e.value = staged.virtual_ctl;
        e.value_known_mask = (staged.virtual_ctl & 1u) != 0 ?
                             UINT64_MAX : UINT64_MAX ^ UINT64_C(4);
        break;
    case OCNEXT_TIMER_READ_PHYSICAL_CVAL:
        e.value = staged.physical_cval;
        e.value_known_mask = UINT64_MAX;
        break;
    case OCNEXT_TIMER_READ_VIRTUAL_CVAL:
        e.value = staged.virtual_cval;
        e.value_known_mask = UINT64_MAX;
        break;
    case OCNEXT_TIMER_READ_PHYSICAL_TVAL:
    case OCNEXT_TIMER_READ_VIRTUAL_TVAL:
        /* Disabled storage follows the pinned source, while the entire
         * architectural read remains UNKNOWN under issued semantics v2. */
        e.value = (uint32_t)((r.operation == OCNEXT_TIMER_READ_PHYSICAL_TVAL ?
                              staged.physical_cval : staged.virtual_cval) -
                             (r.operation == OCNEXT_TIMER_READ_PHYSICAL_TVAL ?
                              staged.physical_count : virtual_count));
        e.value_known_mask =
            ((r.operation == OCNEXT_TIMER_READ_PHYSICAL_TVAL ?
               staged.physical_ctl : staged.virtual_ctl) & 1u) != 0 ?
            UINT64_MAX : UINT64_C(0);
        break;
    default:
        break;
    }
    /* Every possible failure has returned. These complete staged byte copies
     * are one logical publication under the caller's serialized lifetime. */
    gt_copy(state, &staged, sizeof(staged));
    gt_copy(effect, &e, sizeof(e));
    return OCNEXT_TIMER_OK;
}
