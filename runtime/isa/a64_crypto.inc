/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Armv8 Cryptographic Extension subset reached by the real kernel (corecrypto) after the first
 * banner: AES (AESE/AESD/AESMC/AESIMC), SHA-1 (SHA1C/P/M/H/SU0/SU1) and SHA-256
 * (SHA256H/H2/SU0/SU1). Semantics are the Arm ARM pseudocode; every operand must be fully KNOWN
 * (vec_get), results are fully known. Textually included by a64_more.inc after a64_vec.inc.
 * Other crypto encodings (SHA-512, SHA-3, PMULL.1Q) are not decoded here and stay stops.
 */

static uint8_t cx_sbox[256], cx_inv_sbox[256];
static int cx_tables_ready;

static uint8_t cx_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

static uint8_t cx_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = cx_xtime(a);
        b >>= 1;
    }
    return r;
}

/* S-box = affine(inverse in GF(2^8)); generated, not copied, so the table is derivable from FIPS-197. */
static void cx_init_tables(void)
{
    unsigned x;
    if (cx_tables_ready) return;
    for (x = 0; x < 256; ++x) {
        uint8_t inv = 0, s, y;
        unsigned c;
        if (x) {
            for (c = 1; c < 256; ++c) if (cx_mul((uint8_t)x, (uint8_t)c) == 1) { inv = (uint8_t)c; break; }
        }
        y = inv;
        s = (uint8_t)(y ^ ((y << 1) | (y >> 7)) ^ ((y << 2) | (y >> 6)) ^ ((y << 3) | (y >> 5)) ^
                      ((y << 4) | (y >> 4)) ^ 0x63);
        cx_sbox[x] = s;
        cx_inv_sbox[s] = (uint8_t)x;
    }
    cx_tables_ready = 1;
}

static uint32_t cx_rol(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static uint32_t cx_ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static uint32_t cx_w(const v128 *v, unsigned i) { return (uint32_t)vl_get(v, 4, i); }
static void cx_setw(v128 *v, unsigned i, uint32_t x) { vl_set(v, 4, i, x); }

static uint32_t cx_choose(uint32_t x, uint32_t y, uint32_t z) { return ((y ^ z) & x) ^ z; }
static uint32_t cx_parity(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t cx_majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((x | y) & z); }

static void cx_aes_mix(const v128 *in, v128 *out, int inverse)
{
    unsigned c;
    for (c = 0; c < 4; ++c) {
        const uint8_t *s = &in->b[4 * c];
        uint8_t *d = &out->b[4 * c];
        if (!inverse) {
            d[0] = (uint8_t)(cx_mul(s[0], 2) ^ cx_mul(s[1], 3) ^ s[2] ^ s[3]);
            d[1] = (uint8_t)(s[0] ^ cx_mul(s[1], 2) ^ cx_mul(s[2], 3) ^ s[3]);
            d[2] = (uint8_t)(s[0] ^ s[1] ^ cx_mul(s[2], 2) ^ cx_mul(s[3], 3));
            d[3] = (uint8_t)(cx_mul(s[0], 3) ^ s[1] ^ s[2] ^ cx_mul(s[3], 2));
        } else {
            d[0] = (uint8_t)(cx_mul(s[0], 14) ^ cx_mul(s[1], 11) ^ cx_mul(s[2], 13) ^ cx_mul(s[3], 9));
            d[1] = (uint8_t)(cx_mul(s[0], 9) ^ cx_mul(s[1], 14) ^ cx_mul(s[2], 11) ^ cx_mul(s[3], 13));
            d[2] = (uint8_t)(cx_mul(s[0], 13) ^ cx_mul(s[1], 9) ^ cx_mul(s[2], 14) ^ cx_mul(s[3], 11));
            d[3] = (uint8_t)(cx_mul(s[0], 11) ^ cx_mul(s[1], 13) ^ cx_mul(s[2], 9) ^ cx_mul(s[3], 14));
        }
    }
}

static int crypto_exec(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
                       const struct ocnext_a64_hooks *hooks, uint32_t op,
                       struct transaction *tx, enum ocnext_a64_result *res)
{
    unsigned rd = op & 31u, rn = (op >> 5) & 31u, rm = (op >> 16) & 31u, i;
    int aes = (op & UINT32_C(0xfffc0c00)) == UINT32_C(0x4e280800);
    int sha3r = (op & UINT32_C(0xffe08c00)) == UINT32_C(0x5e000000);
    int sha2r = (op & UINT32_C(0xfffe0c00)) == UINT32_C(0x5e280800);
    int pmull = (op & UINT32_C(0xbfe0fc00)) == UINT32_C(0x0ee0e000); /* PMULL/PMULL2 Vd.1Q, Vn.1D/2D, Vm.1D/2D */
    unsigned opc;
    v128 d, n, m, r;
    int st;

    unsigned have = hooks ? hooks->crypto_extensions : 0u;

    if (pmull) {
        unsigned half = (op >> 30) & 1u, k;
        uint64_t a, b, lo = 0, hi = 0;
        if (!(have & OCNEXT_A64_CRYPTO_PMULL)) return MORE_NONE;
        st = more_fp_access(cpu, memory, op, res);
        if (st != MORE_OK) return st;
        /* Q=1 reads the upper 64-bit halves; the lower-half form only needs the low halves known. */
        if (vec_get(cpu, rn, half ? 16 : 8, &n) || vec_get(cpu, rm, half ? 16 : 8, &m)) return MORE_UNSUPPORTED;
        a = vl_get(&n, 8, half);
        b = vl_get(&m, 8, half);
        for (k = 0; k < 64; ++k) {
            if ((b >> k) & 1u) {
                lo ^= a << k;
                if (k) hi ^= a >> (64 - k);
            }
        }
        vzero(&r);
        vl_set(&r, 8, 0, lo);
        vl_set(&r, 8, 1, hi);
        vec_put(tx, rd, &r);
        return MORE_OK;
    }
    if (!(aes || sha3r || sha2r)) return MORE_NONE;
    if (aes && !(have & OCNEXT_A64_CRYPTO_AES)) return MORE_NONE;
    if (aes) {
        opc = (op >> 12) & 31u;
        if (opc < 4 || opc > 7) return MORE_NONE; /* reserved encodings are not claimed here */
    } else if (sha3r) {
        opc = (op >> 12) & 7u;
        if (opc == 7) return MORE_NONE;
    } else {
        opc = (op >> 12) & 31u;
        if (opc > 2) return MORE_NONE;
    }
    if (sha3r && !(have & (opc <= 3 ? OCNEXT_A64_CRYPTO_SHA1 : OCNEXT_A64_CRYPTO_SHA256))) return MORE_NONE;
    if (sha2r && !(have & (opc <= 1 ? OCNEXT_A64_CRYPTO_SHA1 : OCNEXT_A64_CRYPTO_SHA256))) return MORE_NONE;
    st = more_fp_access(cpu, memory, op, res);
    if (st != MORE_OK) return st;
    cx_init_tables();
    vzero(&r);

    if (aes) {
        if (vec_get(cpu, rn, 16, &n)) return MORE_UNSUPPORTED;
        if (opc < 6) { /* AESE / AESD: Vd ^ Vn, then (Inv)SubBytes + (Inv)ShiftRows */
            v128 s;
            if (vec_get(cpu, rd, 16, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < 16; ++i) s.b[i] = (uint8_t)(d.b[i] ^ n.b[i]);
            for (i = 0; i < 16; ++i) {
                if (opc == 4) r.b[i] = cx_sbox[s.b[(5 * i) & 15u]];        /* ShiftRows: out[i] = in[5i mod 16] */
                else r.b[(5 * i) & 15u] = cx_inv_sbox[s.b[i]];             /* InvShiftRows: out[5i mod 16] = in[i] */
            }
        } else { /* AESMC / AESIMC */
            cx_aes_mix(&n, &r, opc == 7);
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    if (sha2r) {
        if (vec_get(cpu, rn, 16, &n)) return MORE_UNSUPPORTED;
        if (opc == 0) { /* SHA1H Sd, Sn */
            cx_setw(&r, 0, cx_rol(cx_w(&n, 0), 30));
        } else if (opc == 1) { /* SHA1SU1 Vd.4S, Vn.4S */
            uint32_t t[4], x;
            if (vec_get(cpu, rd, 16, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < 4; ++i) t[i] = cx_w(&d, i) ^ (i < 3 ? cx_w(&n, i + 1) : 0);
            for (i = 0; i < 4; ++i) {
                x = cx_rol(t[i], 1);
                if (i == 3) x ^= cx_rol(t[0], 2);
                cx_setw(&r, i, x);
            }
        } else { /* SHA256SU0 Vd.4S, Vn.4S */
            uint32_t t[4];
            if (vec_get(cpu, rd, 16, &d)) return MORE_UNSUPPORTED;
            for (i = 0; i < 3; ++i) t[i] = cx_w(&d, i + 1);
            t[3] = cx_w(&n, 0);
            for (i = 0; i < 4; ++i)
                cx_setw(&r, i, cx_w(&d, i) + (cx_ror(t[i], 7) ^ cx_ror(t[i], 18) ^ (t[i] >> 3)));
        }
        vec_put(tx, rd, &r);
        return MORE_OK;
    }

    /* three-register SHA */
    if (vec_get(cpu, rd, 16, &d) || vec_get(cpu, rn, 16, &n)) return MORE_UNSUPPORTED;
    if (vec_get(cpu, rm, 16, &m)) return MORE_UNSUPPORTED;
    if (opc <= 2) { /* SHA1C / SHA1P / SHA1M Qd, Sn, Vm.4S */
        uint32_t x[4], y = cx_w(&n, 0), tt, nx[4];
        for (i = 0; i < 4; ++i) x[i] = cx_w(&d, i);
        for (i = 0; i < 4; ++i) {
            tt = opc == 0 ? cx_choose(x[1], x[2], x[3]) : opc == 1 ? cx_parity(x[1], x[2], x[3])
                                                                  : cx_majority(x[1], x[2], x[3]);
            y = y + cx_rol(x[0], 5) + tt + cx_w(&m, i);
            x[1] = cx_rol(x[1], 30);
            nx[0] = y; nx[1] = x[0]; nx[2] = x[1]; nx[3] = x[2];
            y = x[3];
            x[0] = nx[0]; x[1] = nx[1]; x[2] = nx[2]; x[3] = nx[3];
        }
        for (i = 0; i < 4; ++i) cx_setw(&r, i, x[i]);
    } else if (opc == 3) { /* SHA1SU0 Vd.4S, Vn.4S, Vm.4S */
        v128 t;
        for (i = 0; i < 8; ++i) { t.b[i] = d.b[8 + i]; t.b[8 + i] = n.b[i]; }
        for (i = 0; i < 16; ++i) r.b[i] = (uint8_t)(d.b[i] ^ t.b[i] ^ m.b[i]);
    } else if (opc == 4 || opc == 5) { /* SHA256H / SHA256H2 */
        uint32_t x[4], y[4], chs, maj, t, nx[4], ny[4];
        for (i = 0; i < 4; ++i) { x[i] = cx_w(opc == 4 ? &d : &n, i); y[i] = cx_w(opc == 4 ? &n : &d, i); }
        for (i = 0; i < 4; ++i) {
            chs = cx_choose(y[0], y[1], y[2]);
            maj = cx_majority(x[0], x[1], x[2]);
            t = y[3] + (cx_ror(y[0], 6) ^ cx_ror(y[0], 11) ^ cx_ror(y[0], 25)) + chs + cx_w(&m, i);
            x[3] = t + x[3];
            y[3] = t + (cx_ror(x[0], 2) ^ cx_ror(x[0], 13) ^ cx_ror(x[0], 22)) + maj;
            nx[0] = y[3]; nx[1] = x[0]; nx[2] = x[1]; nx[3] = x[2];
            ny[0] = x[3]; ny[1] = y[0]; ny[2] = y[1]; ny[3] = y[2];
            { unsigned k; for (k = 0; k < 4; ++k) { x[k] = nx[k]; y[k] = ny[k]; } }
        }
        for (i = 0; i < 4; ++i) cx_setw(&r, i, opc == 4 ? x[i] : y[i]);
    } else { /* opc == 6: SHA256SU1 Vd.4S, Vn.4S, Vm.4S */
        uint32_t t0[4], t1[4], e;
        for (i = 0; i < 3; ++i) t0[i] = cx_w(&n, i + 1);
        t0[3] = cx_w(&m, 0);
        for (i = 0; i < 4; ++i) {
            e = i < 2 ? cx_w(&m, 2 + i) : t1[i - 2];
            t1[i] = cx_w(&d, i) + t0[i] + (cx_ror(e, 17) ^ cx_ror(e, 19) ^ (e >> 10));
        }
        for (i = 0; i < 4; ++i) cx_setw(&r, i, t1[i]);
    }
    vec_put(tx, rd, &r);
    return MORE_OK;
}
