/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Advanced SIMD integer subset for the M-BOOT kernel path, textually included by
 * a64_more.inc. Every operand register must be fully KNOWN (a vector byte the CPU
 * model never wrote cannot be read); results are fully known. Q=0 operations
 * zero the upper 64 bits of the destination, as the architecture does.
 * Anything not decoded here is left to the caller (MORE_NONE) or stops.
 */

typedef struct { uint8_t b[16]; } v128;

static void vzero(v128 *v) { unsigned i; for (i = 0; i < 16; ++i) v->b[i] = 0; }
static void vbytes(uint8_t *dst, const uint8_t *src, unsigned n) { unsigned i; for (i = 0; i < n; ++i) dst[i] = src[i]; }

static int vec_get(const struct ocnext_a64_cpu *cpu, unsigned reg, unsigned bytes, v128 *out)
{
    uint16_t need = (uint16_t)(bytes == 16 ? 0xffffu : 0x00ffu);
    unsigned i;
    if ((cpu->vector.known_bytes[reg] & need) != need) return -1;
    for (i = 0; i < 16; ++i) out->b[i] = (i < bytes) ? cpu->vector.bytes[reg][i] : 0;
    return 0;
}

static uint64_t vl_get(const v128 *v, unsigned esz, unsigned idx)
{
    uint64_t r = 0;
    unsigned i;
    for (i = 0; i < esz; ++i) r |= (uint64_t)v->b[idx * esz + i] << (8 * i);
    return r;
}

static void vl_set(v128 *v, unsigned esz, unsigned idx, uint64_t val)
{
    unsigned i;
    for (i = 0; i < esz; ++i) v->b[idx * esz + i] = (uint8_t)(val >> (8 * i));
}

static void vec_put(struct transaction *tx, unsigned reg, const v128 *v)
{
    stage_vector_mask(tx, reg, v->b, OCNEXT_A64_VECTOR_KNOWN_ALL);
}

static int64_t vl_sext(uint64_t v, unsigned esz)
{
    return (int64_t)sign_extend(v, esz * 8);
}

static uint64_t vl_mask(unsigned esz)
{
    return esz >= 8 ? UINT64_MAX : (UINT64_C(1) << (esz * 8)) - 1;
}

/* Saturating helpers (esz <= 8). */
static uint64_t vl_uqadd(uint64_t a, uint64_t b, unsigned esz)
{
    uint64_t m = vl_mask(esz), sum = a + b;
    if (esz == 8) return sum < a ? m : sum;
    return sum > m ? m : sum;
}

static uint64_t vl_uqsub(uint64_t a, uint64_t b) { return a > b ? a - b : 0; }

static uint64_t vl_sqadd(uint64_t a, uint64_t b, unsigned esz, int sub)
{
    __int128 x = vl_sext(a, esz), y = vl_sext(b, esz), r = sub ? x - y : x + y;
    __int128 hi = ((__int128)1 << (esz * 8 - 1)) - 1, lo = -hi - 1;
    if (r > hi) r = hi;
    if (r < lo) r = lo;
    return (uint64_t)r & vl_mask(esz);
}

/* USHL/SSHL element shift: the shift amount is the signed low byte of b. */
static uint64_t vl_shl(uint64_t a, uint64_t b, unsigned esz, int is_signed)
{
    int sh = (int8_t)(b & 0xff);
    unsigned bits = esz * 8;
    if (sh >= 0) return sh >= (int)bits ? 0 : (a << sh) & vl_mask(esz);
    sh = -sh;
    if (is_signed) {
        int64_t s = vl_sext(a, esz);
        return (uint64_t)(sh >= (int)bits ? (s < 0 ? -1 : 0) : (s >> sh)) & vl_mask(esz);
    }
    return sh >= (int)bits ? 0 : (a & vl_mask(esz)) >> sh;
}

static int vec_exec(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory, uint32_t op,
                    struct transaction *tx, uint8_t *bytes, enum ocnext_a64_result *res)
{
    unsigned q = (op >> 30) & 1u, u = (op >> 29) & 1u, size = (op >> 22) & 3u;
    (void)bytes;
    unsigned rd = op & 31u, rn = (op >> 5) & 31u, rm = (op >> 16) & 31u;
    unsigned dbytes = q ? 16u : 8u;
    int st;

    /* --- classes we claim; cheap decode first so unrelated opcodes return fast --- */
    int three_same = (op & UINT32_C(0x9f200400)) == UINT32_C(0x0e200400);
    int two_misc = (op & UINT32_C(0x9f3e0c00)) == UINT32_C(0x0e200800);
    int across = (op & UINT32_C(0x9f3e0c00)) == UINT32_C(0x0e300800);
    int three_diff = (op & UINT32_C(0x9f200c00)) == UINT32_C(0x0e200000);
    int copy = (op & UINT32_C(0x9fe08400)) == UINT32_C(0x0e000400);
    int shift_imm = (op & UINT32_C(0x9f800400)) == UINT32_C(0x0f000400);
    int extract = (op & UINT32_C(0xbfe08400)) == UINT32_C(0x2e000000);
    int permute = (op & UINT32_C(0xbf208c00)) == UINT32_C(0x0e000800);
    int tbl = (op & UINT32_C(0xbfe08c00)) == UINT32_C(0x0e000000);
    int pairwise_scalar = (op & UINT32_C(0xdf3e0c00)) == UINT32_C(0x5e300800);
    int ldst_multi = (op & UINT32_C(0xbfbf0000)) == UINT32_C(0x0c000000) || (op & UINT32_C(0xbfa00000)) == UINT32_C(0x0c800000);
    int ldst_single = (op & UINT32_C(0xbf9f0000)) == UINT32_C(0x0d000000) || (op & UINT32_C(0xbf800000)) == UINT32_C(0x0d800000);
    if (!(three_same || two_misc || across || three_diff || copy || shift_imm || extract || permute ||
          pairwise_scalar || ldst_multi || ldst_single || tbl))
        return MORE_NONE;

    st = more_fp_access(cpu, memory, op, res);
    if (st != MORE_OK) return st;

    /* ---------------------------------------------------------------- three same */
    if (three_same) {
        unsigned opcode = (op >> 11) & 31u, esz = 1u << size, lanes, i;
        v128 a, b, d, r;
        if (vec_get(cpu, rn, dbytes, &a) || vec_get(cpu, rm, dbytes, &b)) return MORE_UNSUPPORTED;
        vzero(&r);
        if (opcode == 0x03) { /* logical, size selects the operation */
            unsigned kind = (u << 2) | size, i2;
            if (kind >= 5 && vec_get(cpu, rd, dbytes, &d)) return MORE_UNSUPPORTED;
            for (i2 = 0; i2 < dbytes; ++i2) {
                uint8_t x = a.b[i2], y = b.b[i2], o = kind >= 5 ? d.b[i2] : 0, z;
                switch (kind) {
                case 0: z = x & y; break;
                case 1: z = x & (uint8_t)~y; break;
                case 2: z = x | y; break;
                case 3: z = x | (uint8_t)~y; break;
                case 4: z = x ^ y; break;
                case 5: z = (uint8_t)((x & o) | (y & ~o)); break;                 /* BSL: d = (n & d) | (m & ~d) */
                case 6: z = (uint8_t)((o & ~y) | (x & y)); break;                 /* BIT: insert n where m is 1 */
                default: z = (uint8_t)((o & y) | (x & ~y)); break;                /* BIF: insert n where m is 0 */
                }
                r.b[i2] = z;
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (size == 3 && !q) return MORE_UNSUPPORTED; /* reserved 1D integer forms */
        /* Arm ARM "Advanced SIMD three same": SHADD/UHADD(0) SRHADD/URHADD(2) SHSUB/UHSUB(4)
         * SMAX/UMAX(0xc) SMIN/UMIN(0xd) SABD/UABD(0xe) have no 64-bit element form (size=3 is
         * unallocated for Q=1 too), so they must not reach the generic lane loop below. */
        if (size == 3 && ((UINT32_C(1) << opcode) & UINT32_C(0x7015))) return MORE_UNSUPPORTED;
        lanes = dbytes / esz;
        if (opcode == 0x17 && !u) { /* ADDP */
            v128 cat[2];
            cat[0] = a; cat[1] = b;
            for (i = 0; i < lanes; ++i) {
                unsigned src = (i * 2) / lanes, k = (i * 2) % lanes;
                vl_set(&r, esz, i, (vl_get(&cat[src], esz, k) + vl_get(&cat[src], esz, k + 1)) & vl_mask(esz));
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if ((opcode == 0x14 || opcode == 0x15) && size < 3) { /* SMAXP UMAXP SMINP UMINP */
            v128 cat[2];
            cat[0] = a; cat[1] = b;
            for (i = 0; i < lanes; ++i) {
                unsigned src = (i * 2) / lanes, k = (i * 2) % lanes;
                uint64_t x = vl_get(&cat[src], esz, k), y = vl_get(&cat[src], esz, k + 1), pick;
                int gt = u ? x > y : vl_sext(x, esz) > vl_sext(y, esz);
                pick = (opcode == 0x14) ? (gt ? x : y) : (gt ? y : x);
                vl_set(&r, esz, i, pick);
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (opcode == 0x12 || opcode == 0x13) { /* MLA/MLS, MUL (PMUL unsupported) */
            if (size == 3 || (opcode == 0x13 && u)) return MORE_UNSUPPORTED;
            if (opcode == 0x12 && vec_get(cpu, rd, dbytes, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < lanes; ++i) {
                uint64_t p = (vl_get(&a, esz, i) * vl_get(&b, esz, i)) & vl_mask(esz), acc = opcode == 0x12 ? vl_get(&d, esz, i) : 0;
                vl_set(&r, esz, i, opcode == 0x13 ? p : (u ? acc - p : acc + p));
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        for (i = 0; i < lanes; ++i) {
            uint64_t x = vl_get(&a, esz, i), y = vl_get(&b, esz, i), z, m = vl_mask(esz);
            int64_t sx = vl_sext(x, esz), sy = vl_sext(y, esz);
            switch (opcode) {
            case 0x00: /* SHADD/UHADD */
                z = (uint64_t)(u ? (__int128)(((unsigned __int128)x + y) >> 1) : (((__int128)sx + sy) >> 1)) & m; break;
            case 0x01: z = u ? vl_uqadd(x, y, esz) : vl_sqadd(x, y, esz, 0); break;
            case 0x02: /* SRHADD/URHADD */
                z = (uint64_t)(u ? (__int128)(((unsigned __int128)x + y + 1) >> 1) : (((__int128)sx + sy + 1) >> 1)) & m; break;
            case 0x04: /* SHSUB/UHSUB */
                z = (uint64_t)(u ? (((__int128)x - (__int128)y) >> 1) : (((__int128)sx - sy) >> 1)) & m; break;
            case 0x05: z = u ? vl_uqsub(x, y) : vl_sqadd(x, y, esz, 1); break;
            case 0x06: z = (u ? x > y : sx > sy) ? m : 0; break;
            case 0x07: z = (u ? x >= y : sx >= sy) ? m : 0; break;
            case 0x08: z = vl_shl(x, y, esz, !u); break;
            case 0x0c: z = (u ? x > y : sx > sy) ? x : y; break;
            case 0x0d: z = (u ? x < y : sx < sy) ? x : y; break;
            case 0x0e: z = (u ? (x > y ? x - y : y - x) : (uint64_t)(sx > sy ? sx - sy : sy - sx)) & m; break;
            case 0x10: z = (u ? x - y : x + y) & m; break;
            case 0x11: z = u ? (x == y ? m : 0) : ((x & y) ? m : 0); break;
            default: return MORE_UNSUPPORTED;
            }
            vl_set(&r, esz, i, z);
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- two-reg misc */
    if (two_misc) {
        unsigned opcode = (op >> 12) & 31u, esz = 1u << size, lanes, i;
        v128 a, r;
        vzero(&r);
        if (opcode == 0x12 && !u) { /* XTN / XTN2 */
            v128 d;
            unsigned dst_esz = esz, src_esz = esz * 2, n = 8u / dst_esz;
            if (size == 3) return MORE_UNSUPPORTED;
            if (vec_get(cpu, rn, 16, &a)) return MORE_UNSUPPORTED;
            if (q) { if (vec_get(cpu, rd, 16, &d)) return MORE_UNSUPPORTED; r = d; }
            for (i = 0; i < n; ++i) vl_set(&r, dst_esz, (q ? n : 0) + i, vl_get(&a, src_esz, i) & vl_mask(dst_esz));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (vec_get(cpu, rn, dbytes, &a)) return MORE_UNSUPPORTED;
        if (size == 3 && !q && opcode != 0x00 && opcode != 0x05) return MORE_UNSUPPORTED;
        lanes = dbytes / esz;
        if (opcode == 0x05 && !u && size == 0) { /* CNT */
            for (i = 0; i < dbytes; ++i) r.b[i] = (uint8_t)__builtin_popcount(a.b[i]);
        } else if (opcode == 0x05 && u && size == 0) { /* NOT */
            for (i = 0; i < dbytes; ++i) r.b[i] = (uint8_t)~a.b[i];
        } else if (opcode == 0x05 && u && size == 1) { /* RBIT */
            for (i = 0; i < dbytes; ++i) { uint8_t x = a.b[i], y = 0; unsigned k; for (k = 0; k < 8; ++k) if (x & (1u << k)) y |= (uint8_t)(0x80u >> k); r.b[i] = y; }
        } else if (opcode == 0x00 || opcode == 0x01) { /* REV64 / REV32 / REV16 */
            unsigned container = opcode == 0x01 ? (u ? 0 : 2) : (u ? 4 : 8); /* REV16=2 bytes (U0,op1) */
            unsigned k;
            if (opcode == 0x01 && u) return MORE_UNSUPPORTED;
            if (esz >= container) return MORE_UNSUPPORTED;
            for (i = 0; i < dbytes; i += container)
                for (k = 0; k < container; k += esz) {
                    unsigned j;
                    for (j = 0; j < esz; ++j) r.b[i + container - esz - k + j] = a.b[i + k + j];
                }
        } else if (opcode >= 0x08 && opcode <= 0x0b && !(opcode == 0x0b && 0)) {
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, esz, i), z, m = vl_mask(esz);
                int64_t sx = vl_sext(x, esz);
                switch ((u << 4) | opcode) {
                case 0x08: z = sx > 0 ? m : 0; break;         /* CMGT #0 */
                case 0x09: z = x == 0 ? m : 0; break;         /* CMEQ #0 */
                case 0x0a: z = sx < 0 ? m : 0; break;         /* CMLT #0 */
                case 0x0b: z = (uint64_t)(sx < 0 ? -sx : sx) & m; break; /* ABS */
                case 0x18: z = sx >= 0 ? m : 0; break;        /* CMGE #0 */
                case 0x19: z = sx <= 0 ? m : 0; break;        /* CMLE #0 */
                case 0x1b: z = (uint64_t)(-sx) & m; break;    /* NEG */
                default: return MORE_UNSUPPORTED;
                }
                vl_set(&r, esz, i, z);
            }
        } else {
            return MORE_UNSUPPORTED;
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- across lanes */
    if (across) {
        unsigned opcode = (op >> 12) & 31u, esz = 1u << size, lanes, i;
        v128 a, r;
        uint64_t acc;
        unsigned res_esz = esz;
        if (size == 3) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, dbytes, &a)) return MORE_UNSUPPORTED;
        lanes = dbytes / esz;
        if (esz == 4 && !q) return MORE_UNSUPPORTED; /* 2S reductions are reserved */
        if (opcode == 0x03) { /* SADDLV / UADDLV */
            uint64_t sum = 0;
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, esz, i);
                sum += u ? x : (uint64_t)vl_sext(x, esz);
            }
            res_esz = esz * 2;
            vzero(&r);
            vl_set(&r, res_esz, 0, sum & vl_mask(res_esz));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (!((u == 0 && (opcode == 0x1b || opcode == 0x0a || opcode == 0x1a)) || (u == 1 && (opcode == 0x0a || opcode == 0x1a))))
            return MORE_UNSUPPORTED;
        acc = vl_get(&a, esz, 0);
        for (i = 1; i < lanes; ++i) {
            uint64_t x = vl_get(&a, esz, i);
            switch ((u << 5) | opcode) {
            case 0x1b: acc = (acc + x) & vl_mask(esz); break;                                  /* ADDV */
            case 0x0a: acc = (vl_sext(x, esz) > vl_sext(acc, esz)) ? x : acc; break;           /* SMAXV */
            case 0x1a: acc = (vl_sext(x, esz) < vl_sext(acc, esz)) ? x : acc; break;           /* SMINV */
            case 0x2a: acc = x > acc ? x : acc; break;                                         /* UMAXV */
            default: acc = x < acc ? x : acc; break;                                           /* UMINV */
            }
        }
        vzero(&r);
        vl_set(&r, res_esz, 0, acc);
        vec_put(tx, rd, &r);
        return MORE_OK;
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- copy (DUP/INS/UMOV/SMOV) */
    if (copy) {
        unsigned imm5 = (op >> 16) & 31u, imm4 = (op >> 11) & 15u, o = (op >> 29) & 1u, esz, idx, ssz, sidx;
        v128 a, r;
        if (imm5 & 1u) { esz = 1; idx = imm5 >> 1; }
        else if (imm5 & 2u) { esz = 2; idx = imm5 >> 2; }
        else if (imm5 & 4u) { esz = 4; idx = imm5 >> 3; }
        else if (imm5 & 8u) { esz = 8; idx = imm5 >> 4; }
        else return MORE_UNSUPPORTED;
        if (o == 0 && imm4 == 0) { /* DUP (element) */
            if (esz == 8 && !q) return MORE_UNSUPPORTED;
            if (vec_get(cpu, rn, 16, &a)) return MORE_UNSUPPORTED;
            vzero(&r);
            for (unsigned i = 0; i < dbytes / esz; ++i) vl_set(&r, esz, i, vl_get(&a, esz, idx));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (o == 0 && imm4 == 1) { /* DUP (general) */
            uint64_t val = reg_read(cpu, rn, 64, 0) & vl_mask(esz);
            if (esz == 8 && !q) return MORE_UNSUPPORTED;
            vzero(&r);
            for (unsigned i = 0; i < dbytes / esz; ++i) vl_set(&r, esz, i, val);
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (o == 0 && imm4 == 3 && q) { /* INS (general) */
            if (vec_get(cpu, rd, 16, &r)) return MORE_UNSUPPORTED;
            vl_set(&r, esz, idx, reg_read(cpu, rn, 64, 0) & vl_mask(esz));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (o == 1 && q) { /* INS (element) */
            ssz = esz;
            sidx = (imm4 >> (__builtin_ctz(imm5))) ;
            if (vec_get(cpu, rn, 16, &a) || vec_get(cpu, rd, 16, &r)) return MORE_UNSUPPORTED;
            vl_set(&r, esz, idx, vl_get(&a, ssz, sidx));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (o == 0 && (imm4 == 7 || imm4 == 5)) { /* UMOV / SMOV */
            uint64_t val;
            unsigned w = q ? 64u : 32u;
            if (vec_get(cpu, rn, 16, &a)) return MORE_UNSUPPORTED;
            val = vl_get(&a, esz, idx);
            if (imm4 == 7) { if (esz == 8 ? !q : q) return MORE_UNSUPPORTED; }
            else { if (esz == 8 || (esz == 4 && !q)) return MORE_UNSUPPORTED; val = (uint64_t)vl_sext(val, esz); }
            stage_write(tx, rd, val, w, 0);
            return MORE_OK;
        }
        return MORE_UNSUPPORTED;
    }

    /* ---------------------------------------------------------------- shift by immediate */
    if (shift_imm) {
        unsigned immh = (op >> 19) & 15u, immb = (op >> 16) & 7u, opcode = (op >> 11) & 31u, esz, ebits, shift, lanes, i;
        v128 a, r;
        if (!immh) return MORE_UNSUPPORTED;
        esz = immh & 8u ? 8u : immh & 4u ? 4u : immh & 2u ? 2u : 1u;
        ebits = esz * 8;
        shift = ((immh << 3) | immb);
        vzero(&r);
        if (opcode == 0x14) { /* USHLL/SSHLL (UXTL/SXTL for shift 0) */
            unsigned src_esz = esz, dst_esz = esz * 2;
            if (immh & 8u) return MORE_UNSUPPORTED;
            if (vec_get(cpu, rn, 16, &a)) return MORE_UNSUPPORTED;
            shift = shift - ebits;
            lanes = 8u / src_esz;
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, src_esz, (q ? lanes : 0) + i);
                uint64_t w = u ? x : (uint64_t)vl_sext(x, src_esz);
                vl_set(&r, dst_esz, i, (w << shift) & vl_mask(dst_esz));
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (esz == 8 && !q) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, dbytes, &a)) return MORE_UNSUPPORTED;
        lanes = dbytes / esz;
        if (opcode == 0x00 || opcode == 0x02) { /* SSHR/USHR, SSRA/USRA */
            unsigned sh = 2 * ebits - shift;
            v128 d;
            if (opcode == 0x02 && vec_get(cpu, rd, dbytes, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, esz, i), z;
                if (u) z = sh >= 64 ? 0 : (x >> sh);
                else z = (uint64_t)(vl_sext(x, esz) >> (sh >= 64 ? 63 : sh)) & vl_mask(esz);
                if (opcode == 0x02) z = (vl_get(&d, esz, i) + z) & vl_mask(esz);
                vl_set(&r, esz, i, z & vl_mask(esz));
            }
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        if (opcode == 0x0a && !u) { /* SHL */
            unsigned sh = shift - ebits;
            for (i = 0; i < lanes; ++i) vl_set(&r, esz, i, (vl_get(&a, esz, i) << sh) & vl_mask(esz));
            vec_put(tx, rd, &r);
            return MORE_OK;
        }
        return MORE_UNSUPPORTED;
    }

    /* ---------------------------------------------------------------- three different (widening) */
    if (three_diff) {
        unsigned opcode = (op >> 12) & 15u, esz = 1u << size, dst = esz * 2, lanes, i;
        v128 a, b, r, d;
        if (size == 3) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, 16, &a) || vec_get(cpu, rm, 16, &b)) return MORE_UNSUPPORTED;
        lanes = 8u / esz;
        vzero(&r);
        if (opcode == 0x08 || opcode == 0x0c) { /* UMLAL/SMLAL (0x08), UMULL/SMULL (0x0c) */
            if (opcode == 0x08 && vec_get(cpu, rd, 16, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, esz, (q ? lanes : 0) + i), y = vl_get(&b, esz, (q ? lanes : 0) + i), p;
                p = u ? x * y : (uint64_t)(vl_sext(x, esz) * vl_sext(y, esz));
                if (opcode == 0x08) p += vl_get(&d, dst, i);
                vl_set(&r, dst, i, p & vl_mask(dst));
            }
        } else if (opcode == 0x00 || opcode == 0x02) { /* SADDL/UADDL, SSUBL/USUBL via 0x00/0x02 */
            for (i = 0; i < lanes; ++i) {
                uint64_t x = vl_get(&a, esz, (q ? lanes : 0) + i), y = vl_get(&b, esz, (q ? lanes : 0) + i);
                int64_t sx = vl_sext(x, esz), sy = vl_sext(y, esz);
                uint64_t z = u ? (opcode == 0 ? x + y : x - y) : (uint64_t)(opcode == 0 ? sx + sy : sx - sy);
                vl_set(&r, dst, i, z & vl_mask(dst));
            }
        } else {
            return MORE_UNSUPPORTED;
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- EXT */
    if (extract) {
        unsigned imm4 = (op >> 11) & 15u, i;
        v128 a, b, r;
        uint8_t cat[32];
        if (!q && (imm4 & 8u)) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, dbytes, &a) || vec_get(cpu, rm, dbytes, &b)) return MORE_UNSUPPORTED;
        vzero(&r);
        for (i = 0; i < dbytes; ++i) { cat[i] = a.b[i]; cat[dbytes + i] = b.b[i]; }
        for (i = 0; i < dbytes; ++i) r.b[i] = cat[imm4 + i];
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- permute (ZIP/UZP/TRN) */
    if (permute) {
        unsigned opcode = (op >> 12) & 7u, esz = 1u << size, lanes, i;
        v128 a, b, r;
        if (size == 3 && !q) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, dbytes, &a) || vec_get(cpu, rm, dbytes, &b)) return MORE_UNSUPPORTED;
        lanes = dbytes / esz;
        vzero(&r);
        switch (opcode) {
        case 1: case 5: /* UZP1/UZP2 */
            for (i = 0; i < lanes; ++i) {
                unsigned k = i * 2 + (opcode == 5), half = lanes;
                vl_set(&r, esz, i, k < half ? vl_get(&a, esz, k) : vl_get(&b, esz, k - half));
            }
            break;
        case 2: case 6: /* TRN1/TRN2 */
            for (i = 0; i < lanes; i += 2) {
                unsigned k = i + (opcode == 6);
                vl_set(&r, esz, i, vl_get(&a, esz, k));
                vl_set(&r, esz, i + 1, vl_get(&b, esz, k));
            }
            break;
        case 3: case 7: /* ZIP1/ZIP2 */
            for (i = 0; i < lanes; ++i) {
                unsigned base = (opcode == 7) ? lanes / 2 : 0, k = base + i / 2;
                vl_set(&r, esz, i, (i & 1) ? vl_get(&b, esz, k) : vl_get(&a, esz, k));
            }
            break;
        default: return MORE_UNSUPPORTED;
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- TBL / TBX */
    if (tbl) {
        unsigned len = ((op >> 13) & 3u) + 1u, is_tbx = (op >> 12) & 1u, i, k;
        v128 idx, table[4], r;
        if (vec_get(cpu, rm, dbytes, &idx)) return MORE_UNSUPPORTED;
        for (k = 0; k < len; ++k) if (vec_get(cpu, (rn + k) & 31u, 16, &table[k])) return MORE_UNSUPPORTED;
        if (is_tbx) { if (vec_get(cpu, rd, dbytes, &r)) return MORE_UNSUPPORTED; } else vzero(&r);
        for (i = 0; i < dbytes; ++i) {
            unsigned ix = idx.b[i];
            if (ix < 16u * len) r.b[i] = table[ix >> 4].b[ix & 15u];
            else if (!is_tbx) r.b[i] = 0;
        }
        if (!q) for (i = 8; i < 16; ++i) r.b[i] = 0;
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- scalar pairwise (ADDP Dd, Vn.2D) */
    if (pairwise_scalar) {
        unsigned opcode = (op >> 12) & 31u;
        v128 a, r;
        if (u || opcode != 0x1b || size != 3) return MORE_UNSUPPORTED;
        if (vec_get(cpu, rn, 16, &a)) return MORE_UNSUPPORTED;
        vzero(&r);
        vl_set(&r, 8, 0, vl_get(&a, 8, 0) + vl_get(&a, 8, 1));
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* ---------------------------------------------------------------- structure loads/stores */
    if (ldst_multi || ldst_single) {
        unsigned load = (op >> 22) & 1u, post = (op >> 23) & 1u, opcode, regs = 0, selem = 0, esz, i, k, ebytes;
        uint64_t base, address, total;
        enum ocnext_a64_result stopped;
        enum ocnext_a64_fault_code code;
        unsigned rt = op & 31u;
        v128 reg[4];
        {
            /* ocnext_a64_simd_mem_decode (a64_simd_ext.c) is the authority for allocated structure
             * loads/stores and is reached first; whatever it rejects is unallocated (for example
             * LD4R with S=1) and must not be executed by this older, laxer decode. */
            struct ocnext_a64_simd_mem_plan authority;
            if (!ocnext_a64_simd_mem_decode(op, &authority)) return MORE_UNSUPPORTED;
        }
        if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) { *res = stopped; return MORE_RESULT; }
        base = reg_read(cpu, rn, 64, 1);
        if (ldst_multi) {
            unsigned lsize = (op >> 10) & 3u; /* the structure-load size field is bits 11:10 */
            opcode = (op >> 12) & 15u;
            esz = 1u << lsize;
            switch (opcode) {
            case 0x7: regs = 1; selem = 1; break;
            case 0xa: regs = 2; selem = 1; break;
            case 0x6: regs = 3; selem = 1; break;
            case 0x2: regs = 4; selem = 1; break;
            case 0x8: regs = 2; selem = 2; break;
            case 0x4: regs = 3; selem = 3; break;
            case 0x0: regs = 4; selem = 4; break;
            default: return MORE_UNSUPPORTED;
            }
            if (lsize == 3 && !q && selem > 1) return MORE_UNSUPPORTED;
            total = (uint64_t)regs * dbytes;
            ebytes = esz;
            /* memory image */
            {
                uint8_t mem_img[64];
                unsigned lanes = dbytes / esz, r, e;
                address = base;
                if (!load) {
                    for (r = 0; r < regs; ++r)
                        if (vec_get(cpu, (rt + r) & 31u, dbytes, &reg[r])) return MORE_UNSUPPORTED;
                    if (selem == 1) {
                        for (r = 0; r < regs; ++r) vbytes(mem_img + r * dbytes, reg[r].b, dbytes);
                    } else {
                        for (e = 0; e < lanes; ++e)
                            for (k = 0; k < selem; ++k)
                                for (i = 0; i < esz; ++i) mem_img[(e * selem + k) * esz + i] = reg[k].b[e * esz + i];
                    }
                }
                {
                    unsigned done = 0;
                    while (done < total) { /* <=32-byte transfers (MMU transfer limit) */
                        unsigned chunk = total - done > 32 ? 32 : (unsigned)(total - done);
                        code = memory_transfer(cpu, memory, address + done, load ? mem_img + done : mem_img + done, chunk, esz, load);
                        if (code != OCNEXT_A64_FAULT_NONE) {
                            *res = fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, address + done, chunk, op);
                            return MORE_RESULT;
                        }
                        done += chunk;
                    }
                }
                if (load) {
                    for (r = 0; r < regs; ++r) vzero(&reg[r]);
                    if (selem == 1) {
                        for (r = 0; r < regs; ++r) vbytes(reg[r].b, mem_img + r * dbytes, dbytes);
                    } else {
                        for (e = 0; e < lanes; ++e)
                            for (k = 0; k < selem; ++k)
                                for (i = 0; i < esz; ++i) reg[k].b[e * esz + i] = mem_img[(e * selem + k) * esz + i];
                    }
                    for (r = 0; r < regs; ++r) vec_put(tx, (rt + r) & 31u, &reg[r]);
                }
            }
        } else {
            /* single structure: LD1..LD4 / ST1..ST4 (one lane) and LD1R..LD4R */
            unsigned r_bit = (op >> 21) & 1u, opc3 = (op >> 13) & 7u, s = (op >> 12) & 1u, sz = (op >> 10) & 3u, idx, rep = 0;
            selem = ((opc3 & 1u) << 1 | r_bit) + 1u;
            if (opc3 == 6 || opc3 == 7) { rep = 1; if (!load) return MORE_UNSUPPORTED; esz = 1u << sz; idx = 0; selem = ((opc3 & 1u) << 1 | r_bit) + 1u; }
            else if (opc3 >> 1 == 0) { esz = 1; idx = (q << 3) | (s << 2) | sz; }
            else if (opc3 >> 1 == 1) { esz = 2; if (sz & 1u) return MORE_UNSUPPORTED; idx = (q << 2) | (s << 1) | (sz >> 1); }
            else { /* opc3 4,5: 32-bit (sz=00) or 64-bit (sz=01,S=0) */
                if (sz == 0) { esz = 4; idx = (q << 1) | s; }
                else if (sz == 1 && !s) { esz = 8; idx = q; }
                else return MORE_UNSUPPORTED;
            }
            regs = selem;
            total = (uint64_t)selem * esz;
            address = base;
            ebytes = esz;
            {
                uint8_t mem_img[16];
                v128 cur;
                if (!load) {
                    for (k = 0; k < selem; ++k) {
                        if (vec_get(cpu, (rt + k) & 31u, 16, &cur)) return MORE_UNSUPPORTED;
                        for (i = 0; i < esz; ++i) mem_img[k * esz + i] = cur.b[idx * esz + i];
                    }
                }
                code = memory_transfer(cpu, memory, address, mem_img, (unsigned)total, esz, load);
                if (code != OCNEXT_A64_FAULT_NONE) {
                    *res = fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, address, (unsigned)total, op);
                    return MORE_RESULT;
                }
                if (load) {
                    for (k = 0; k < selem; ++k) {
                        unsigned dest = (rt + k) & 31u;
                        if (rep) {
                            vzero(&cur);
                            for (i = 0; i < dbytes / esz; ++i) for (unsigned j = 0; j < esz; ++j) cur.b[i * esz + j] = mem_img[k * esz + j];
                        } else {
                            if (vec_get(cpu, dest, 16, &cur)) return MORE_UNSUPPORTED;
                            for (i = 0; i < esz; ++i) cur.b[idx * esz + i] = mem_img[k * esz + i];
                        }
                        vec_put(tx, dest, &cur);
                    }
                }
            }
        }
        (void)ebytes;
        if (post) { /* post-index: Rm==31 means immediate = bytes transferred */
            stage_write(tx, rn, base + (rm == 31 ? total : reg_read(cpu, rm, 64, 0)), 64, 1);
        }
        return MORE_OK;
    }
    return MORE_NONE;
}
