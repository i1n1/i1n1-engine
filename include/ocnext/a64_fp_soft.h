#ifndef OCNEXT_A64_FP_SOFT_H
#define OCNEXT_A64_FP_SOFT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Integer-only IEEE-754 binary32/binary64 arithmetic with the Arm FPSR
 * cumulative-exception contract (DDI0487 J1.3 FPRound/FPProcessNaNs family).
 * No host floating point, no libm, no fenv: usable in the freestanding EFI
 * build. Scope: FPCR.RMode=RN for arithmetic, FZ=0, AH=0, FIZ=0, no trapped
 * exceptions; FPCR.DN is honoured. Callers must reject other FPCR values.
 *
 * Values are raw IEEE bit patterns in the low 32 or 64 bits of a uint64_t.
 * `flags` accumulates FPSR cumulative bits at their architectural positions. */
#define OCNEXT_FP_IOC 0x01u
#define OCNEXT_FP_DZC 0x02u
#define OCNEXT_FP_OFC 0x04u
#define OCNEXT_FP_UFC 0x08u
#define OCNEXT_FP_IXC 0x10u
enum ocnext_fp_round { OCNEXT_FP_RN=0,OCNEXT_FP_RP=1,OCNEXT_FP_RM=2,OCNEXT_FP_RZ=3,OCNEXT_FP_RA=4 };
struct ocnext_fp_ctx { unsigned flags; unsigned dn; };

uint64_t ocnext_fp_add(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_sub(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_mul(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_div(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
/* Fused multiply-add: addend + n*m, one rounding (FMADD/FMLA family). */
uint64_t ocnext_fp_fma(unsigned bits,uint64_t addend,uint64_t n,uint64_t m,struct ocnext_fp_ctx *);
/* FMULX and the fused reciprocal / reciprocal-square-root Newton steps. */
uint64_t ocnext_fp_mulx(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_recps(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_rsqrts(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_sqrt(unsigned bits,uint64_t a,struct ocnext_fp_ctx *);
/* FMAX/FMIN (NaN propagating) and FMAXNM/FMINNM (quiet-NaN ignoring). */
uint64_t ocnext_fp_max(unsigned bits,uint64_t a,uint64_t b,int numeric,struct ocnext_fp_ctx *);
uint64_t ocnext_fp_min(unsigned bits,uint64_t a,uint64_t b,int numeric,struct ocnext_fp_ctx *);
/* FCMP/FCMPE: returns the NZCV nibble (N=8 Z=4 C=2 V=1). */
unsigned ocnext_fp_compare(unsigned bits,uint64_t a,uint64_t b,int signal_all_nans,struct ocnext_fp_ctx *);
/* Convert between binary32 (from/to == 32) and binary64 (== 64). */
uint64_t ocnext_fp_convert(unsigned from_bits,unsigned to_bits,uint64_t a,struct ocnext_fp_ctx *);
/* FRINT*: round to an integral value in the same format. */
uint64_t ocnext_fp_round_int(unsigned bits,uint64_t a,enum ocnext_fp_round mode,int exact,struct ocnext_fp_ctx *);
/* SCVTF/UCVTF: (-1)^neg * mag / 2^fbits, rounded to nearest even. */
uint64_t ocnext_fp_from_int(unsigned bits,uint64_t mag,int neg,unsigned fbits,struct ocnext_fp_ctx *);
/* FCVT{N,P,M,Z,A}{S,U}: float to int32/int64 with saturation. Returns the
 * result as an unsigned two's-complement value of `width` bits. */
uint64_t ocnext_fp_to_int(unsigned bits,uint64_t a,enum ocnext_fp_round mode,unsigned fbits,
                          int is_signed,unsigned width,struct ocnext_fp_ctx *);
#ifdef __cplusplus
}
#endif
#endif
