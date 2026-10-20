#include "ocnext/a64_fmov.h"

static int span(const void *p, size_t n, uintptr_t alignment)
{
    uintptr_t a = (uintptr_t)p;
    return p && !(a & (alignment - 1u)) && n <= UINTPTR_MAX - a;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x < y + bn && y < x + an;
}
static void copy_bytes(void *out, const void *in, size_t n)
{
    uint8_t *d = out;
    const uint8_t *s = in;
    while (n--) *d++ = *s++;
}
static int vector_valid(const struct ocnext_a64_vector_registers *v)
{
    unsigned r, i;
    if (v->abi_version != OCNEXT_A64_VECTOR_REGISTERS_ABI_VERSION) return 0;
    for (i = 0; i < sizeof(v->reserved); ++i) if (v->reserved[i]) return 0;
    for (r = 0; r < 32; ++r)
        for (i = 0; i < 16; ++i)
            if (!(v->known_bytes[r] & (1u << i)) && v->bytes[r][i]) return 0;
    return 1;
}
unsigned ocnext_a64_fmov_decode(uint32_t opcode)
{
    switch (opcode & UINT32_C(0xfffffc00)) {
    case UINT32_C(0x1e260000): return OCNEXT_A64_FMOV_W_FROM_S;
    case UINT32_C(0x1e270000): return OCNEXT_A64_FMOV_S_FROM_W;
    case UINT32_C(0x9e660000): return OCNEXT_A64_FMOV_X_FROM_D;
    case UINT32_C(0x9e670000): return OCNEXT_A64_FMOV_D_FROM_X;
    case UINT32_C(0x9eae0000): return OCNEXT_A64_FMOV_X_FROM_HIGH_D;
    case UINT32_C(0x9eaf0000): return OCNEXT_A64_FMOV_HIGH_D_FROM_X;
    default: return 0;
    }
}
/* DDI0487H.a C7.2.131 pp2312-2313. This is deliberately not a complete
 * allocation decoder. rmode3 conversions and feature-dependent half forms
 * remain outside, even when another architecture context could reject them. */
static int primary_reserved(uint32_t opcode)
{
    unsigned sf, type, rounding;
    if ((opcode & UINT32_C(0x7f26fc00)) != UINT32_C(0x1e260000)) return 0;
    sf = opcode >> 31;
    type = (opcode >> 22) & 3u;
    rounding = (opcode >> 19) & 3u;
    if (rounding == 0)
        return type == 2 || (type == 0 && sf) || (type == 1 && !sf);
    if (rounding == 1) return !(sf && type == 2);
    return rounding == 2;
}
enum ocnext_a64_fmov_result ocnext_a64_fmov_prepare(
    const struct ocnext_a64_vector_registers *v,
    const struct ocnext_a64_fp_registers *fp,
    const struct ocnext_a64_fmov_request *request,
    struct ocnext_a64_fmov_effect *out)
{
    struct ocnext_a64_fmov_effect next;
    struct ocnext_a64_fp_access_request access;
    struct ocnext_a64_fp_access_effect permission;
    enum ocnext_a64_fp_control_result status;
    unsigned form, rn, rd, i, first, bytes;
    uint64_t value;
    if (!span(v, sizeof(*v), 16) || !span(fp, sizeof(*fp), 8) ||
        !span(request, sizeof(*request), 8) || !span(out, sizeof(*out), 8) ||
        overlap(v, sizeof(*v), fp, sizeof(*fp)) ||
        overlap(v, sizeof(*v), request, sizeof(*request)) ||
        overlap(v, sizeof(*v), out, sizeof(*out)) ||
        overlap(fp, sizeof(*fp), request, sizeof(*request)) ||
        overlap(fp, sizeof(*fp), out, sizeof(*out)) ||
        overlap(request, sizeof(*request), out, sizeof(*out)))
        return OCNEXT_A64_FMOV_ARGUMENT;
    if (!vector_valid(v) || !ocnext_a64_fp_control_valid(fp) ||
        request->current_el > 1 || request->profile > OCNEXT_A64_FP_CONTROL_FPEN_ONLY ||
        request->reserved[0] || request->reserved[1]) return OCNEXT_A64_FMOV_ARGUMENT;
    form = ocnext_a64_fmov_decode(request->opcode);
    if (!form) return primary_reserved(request->opcode) ?
        OCNEXT_A64_FMOV_NOT_ALLOCATED : OCNEXT_A64_FMOV_UNSUPPORTED;
    if ((form & 1u) && request->gpr_value) return OCNEXT_A64_FMOV_ARGUMENT;
    rn = (request->opcode >> 5) & 31u;
    rd = request->opcode & 31u;
    for (i = 0; i < sizeof(next); ++i) ((uint8_t *)&next)[i] = 0;
    access.current_el = request->current_el;
    access.profile = request->profile;
    access.reserved = 0;
    status = ocnext_a64_fp_access_prepare(fp, &access, &permission);
    if (status != OCNEXT_A64_FP_CONTROL_OK) return status == OCNEXT_A64_FP_CONTROL_ARGUMENT ?
        OCNEXT_A64_FMOV_ARGUMENT : OCNEXT_A64_FMOV_UNSUPPORTED;
    if (permission.action == OCNEXT_A64_FP_ACCESS_EXCEPTION) {
        next.action = OCNEXT_A64_FMOV_EXCEPTION;
        next.esr = permission.esr;
    } else if (permission.action == OCNEXT_A64_FP_ACCESS_ALLOWED) {
        next.action = OCNEXT_A64_FMOV_RETIRE;
        if (form & 1u) {
            next.rd = (uint8_t)rd;
            /* X[31] discards. No unknown register value is read or fabricated.
             * The zero inactive value is not a known architectural source. */
            if (rd != 31) {
                first = form == OCNEXT_A64_FMOV_X_FROM_HIGH_D ? 8u : 0u;
                bytes = form == OCNEXT_A64_FMOV_W_FROM_S ? 4u : 8u;
                value = 0;
                for (i = 0; i < bytes; ++i) {
                    if (!(v->known_bytes[rn] & (1u << (first + i))))
                        return OCNEXT_A64_FMOV_UNSUPPORTED;
                    value |= (uint64_t)v->bytes[rn][first + i] << (i * 8u);
                }
                next.gpr_write = 1;
                next.gpr_value = value;
            }
        } else {
            value = rn == 31 ? 0 : request->gpr_value;
            next.vector_write = 1;
            next.vd = (uint8_t)rd;
            if (form == OCNEXT_A64_FMOV_HIGH_D_FROM_X) {
                for (i = 0; i < 8; ++i) next.vector_after[i] = v->bytes[rd][i];
                next.known_after = (uint16_t)((v->known_bytes[rd] & 255u) | UINT16_C(0xff00));
                first = 8; bytes = 8;
            } else {
                first = 0;
                bytes = form == OCNEXT_A64_FMOV_S_FROM_W ? 4u : 8u;
                next.known_after = UINT16_C(0xffff);
            }
            for (i = 0; i < bytes; ++i)
                next.vector_after[first + i] = (uint8_t)(value >> (i * 8u));
        }
    } else return OCNEXT_A64_FMOV_ARGUMENT;
    copy_bytes(out, &next, sizeof(next));
    return OCNEXT_A64_FMOV_OK;
}
