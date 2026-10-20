#ifndef OCNEXT_A64_SIMD_EXT_H
#define OCNEXT_A64_SIMD_EXT_H
#include "ocnext/a64.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Advanced SIMD / scalar-FP register-to-register extension (WS2 track).
 *
 * Pure function of the vector bank: no memory, no flags, no FPSR. Every
 * semantic follows DDI0487 (C7.2 instruction pages); nothing is a NOP or a
 * placeholder. Saturating, rounding-to-FPSR and floating-point arithmetic
 * forms are NOT in this subset: decode returns 0 for them and the caller
 * stops with UNSUPPORTED.
 *
 * Saturating forms (S/U QADD QSUB QSHL QRSHL QXTN QSHRN SQABS SQNEG SUQADD
 * USQADD SQDMULH SQRDMULH ...) are covered: when a lane actually saturates the
 * effect sets qc and the caller commits FPSR.QC only if FPSR is known, else it
 * stops (a saturation that cannot be recorded is never silently dropped).
 * Scalar FP arithmetic (FADD FSUB FMUL FDIV FSQRT FMAX* FMIN* FNMUL FCMP FCCMP
 * FCSEL FCVT FRINT* SCVTF UCVTF FCVT[NPMZA][SU]) on S/D uses a64_fp_soft.c and
 * needs a known FPCR with RMode=RN, FZ=0; exception flags go to FPSR like QC.
 * Covered (vector and, where architecturally defined, scalar D forms):
 *   DUP (element/general), INS (element/general), UMOV, SMOV, EXT,
 *   ZIP1/2 UZP1/2 TRN1/2, shift-by-immediate (SSHR USHR SSRA USRA SRSHR
 *   URSHR SRSRA URSRA SHL SLI SRI SHRN RSHRN SSHLL USHLL = SXTL UXTL),
 *   widening three-different (S/U ADDL ADDW SUBL SUBW ABAL ABDL MLAL MLSL
 *   MULL), three-same (HADD RHADD HSUB CMGT CMGE CMHI CMHS CMTST CMEQ SSHL
 *   USHL MAX MIN ABD ABA MLA MLS MUL PMUL MAXP MINP ADDP), two-register
 *   misc (REV64/32/16 CLS CLZ CNT NOT RBIT CM*-zero ABS NEG XTN SADDLP
 *   UADDLP SADALP UADALP SHLL), across-lanes (ADDV SADDLV UADDLV SMAXV
 *   UMAXV SMINV UMINV), by-element MUL/MLA/MLS/xMULL/xMLAL/xMLSL, scalar
 *   ADDP, and FMOV (register/immediate), FABS, FNEG on S/D.
 *
 * Byte-knowledge: every source byte actually consumed must be known; else
 * UNSUPPORTED (never a guess). Preserving forms (INS, XTN2, SHRN2, SLI/SRI,
 * accumulates) read the old Vd and publish known = old known | written. */
#define OCNEXT_A64_SIMD_EXT_ABI_VERSION 1u
enum ocnext_a64_simd_ext_result {
    OCNEXT_A64_SIMD_EXT_OK=0,OCNEXT_A64_SIMD_EXT_ARGUMENT=1,
    OCNEXT_A64_SIMD_EXT_UNSUPPORTED=2
};
struct ocnext_a64_simd_ext_request {
#ifdef __cplusplus
    alignas(16) uint32_t opcode;
#else
    _Alignas(16) uint32_t opcode;
#endif
    uint32_t reserved;
    uint64_t gpr_value; /* X[Rn] with Rn==31 resolved to zero (ZR) by the caller */
    uint64_t fpcr;      /* valid only when fpcr_known: floating-point arithmetic input */
    uint32_t nzcv;      /* cpu->nzcv (N=31 Z=30 C=29 V=28): FCSEL/FCCMP condition input */
    uint8_t fpcr_known,reserved2[3];
};
struct ocnext_a64_simd_ext_effect {
#ifdef __cplusplus
    alignas(16) uint8_t bytes[16];
#else
    _Alignas(16) uint8_t bytes[16];
#endif
    uint64_t gpr_value;
    uint32_t opcode;
    uint32_t nzcv;       /* new cpu->nzcv when nzcv_write */
    uint16_t known_bytes;
    uint8_t destination,vector_write,gpr_write,gpr_rd;
    uint8_t qc;          /* saturation occurred: caller must set FPSR.QC or stop */
    uint8_t fp_flags;    /* FPSR cumulative exception bits (IOC..IXC) to OR in, else stop if FPSR unknown */
    uint8_t nzcv_write;
    uint8_t reserved[7];
};
/* Nonzero only for an implemented, allocated encoding. */
unsigned ocnext_a64_simd_ext_decode(uint32_t opcode);
enum ocnext_a64_simd_ext_result ocnext_a64_simd_ext_prepare(
    const struct ocnext_a64_vector_registers *,const struct ocnext_a64_simd_ext_request *,
    struct ocnext_a64_simd_ext_effect *);

/* ---- Advanced SIMD structure / SIMD&FP register loads and stores ----
 * The module owns only encoding, lane (de)interleave and byte knowledge; the
 * CPU core performs address formation, alignment, FPEN, memory and writeback.
 * Covered: LD1..LD4 / ST1..ST4 (multiple structures, post-index), LD1..LD4 /
 * ST1..ST4 (single structure lane, post-index), LD1R..LD4R, LDR/STR
 * (SIMD&FP register offset B/H/S/D/Q) and LDR (SIMD&FP literal S/D/Q). */
enum ocnext_a64_simd_mem_form {
    OCNEXT_A64_SIMD_MEM_MULTI=1,OCNEXT_A64_SIMD_MEM_SINGLE=2,OCNEXT_A64_SIMD_MEM_REPLICATE=3,
    OCNEXT_A64_SIMD_MEM_LITERAL=4,OCNEXT_A64_SIMD_MEM_REGOFF=5
};
struct ocnext_a64_simd_mem_plan {
    uint32_t opcode;
    uint16_t bytes;      /* total bytes transferred */
    uint8_t form,load,rt,rn,rm;
    uint8_t nregs;       /* consecutive vector registers touched (mod 32) */
    uint8_t selem;       /* structure elements (1..4) */
    uint8_t esize;       /* element size in bytes */
    uint8_t q;           /* 64/128-bit register view for MULTI/REPLICATE */
    uint8_t lane;        /* SINGLE lane index */
    uint8_t wb;          /* 0 none, 1 post-index immediate (== bytes), 2 post-index Xm */
    uint8_t option,shift;/* REGOFF extend option and applied shift amount */
    int64_t literal;     /* LITERAL byte offset from the instruction PC */
};
struct ocnext_a64_simd_mem_dest {
    uint8_t bytes[16];
    uint16_t known_bytes;
    uint8_t reg,reserved;
};
/* Nonzero only for an implemented, allocated encoding. */
unsigned ocnext_a64_simd_mem_decode(uint32_t opcode,struct ocnext_a64_simd_mem_plan *);
/* REGOFF byte offset: Xm (or Wm for UXTW/SXTW) extended and shifted. */
uint64_t ocnext_a64_simd_mem_offset(const struct ocnext_a64_simd_mem_plan *,uint64_t xm);
/* Store: fill buf[plan->bytes] from the bank; UNSUPPORTED if a source byte
 * is not known. */
enum ocnext_a64_simd_ext_result ocnext_a64_simd_mem_gather(
    const struct ocnext_a64_vector_registers *,const struct ocnext_a64_simd_mem_plan *,uint8_t *buf);
/* Load: build the destination registers (count in *n, at most 4) from buf. */
enum ocnext_a64_simd_ext_result ocnext_a64_simd_mem_scatter(
    const struct ocnext_a64_vector_registers *,const struct ocnext_a64_simd_mem_plan *,
    const uint8_t *buf,struct ocnext_a64_simd_mem_dest out[4],unsigned *n);
#ifdef __cplusplus
}
#endif
#endif
