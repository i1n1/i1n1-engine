#include "ocnext/a64_simd_ext.h"
#include "ocnext/a64_simd_integer.h"
#include "ocnext/a64_fp_soft.h"

/* Advanced SIMD extension subset. See the header for scope. All arithmetic is
 * done on unpacked lanes in uint64_t with explicit masking, so no signed
 * overflow, no over-wide shift and no __int128 is involved. */

enum kind {
    K_NONE=0,K_COPY,K_EXT,K_PERM,K_SAME,K_DIFF,K_MISC,K_ACROSS,K_SHIFT,K_ELEM,
    K_PAIR,K_FPREG,K_FPIMM,K_TBL,K_MODIMM,K_FPDP2,K_FPDP1,K_FPCMP,K_FPCCMP,K_FPCSEL,K_FPINT,K_FPFMA,K_FPV
};
enum fpv_group { G3=1,G2,GE,GP,GA,GS };
enum same_op {
    S_SHADD=1,S_UHADD,S_SRHADD,S_URHADD,S_SHSUB,S_UHSUB,S_CMGT,S_CMHI,S_CMGE,S_CMHS,
    S_SSHL,S_USHL,S_SMAX,S_UMAX,S_SMIN,S_UMIN,S_SABD,S_UABD,S_SABA,S_UABA,S_ADD,S_SUB,
    S_CMTST,S_CMEQ,S_MLA,S_MLS,S_MUL,S_PMUL,S_SMAXP,S_UMAXP,S_SMINP,S_UMINP,S_ADDP,
    S_SQADD,S_UQADD,S_SQSUB,S_UQSUB,S_SQSHL,S_UQSHL,S_SRSHL,S_URSHL,S_SQRSHL,S_UQRSHL,
    S_SQDMULH,S_SQRDMULH
};
enum misc_op {
    M_REV64=1,M_REV32,M_REV16,M_SADDLP,M_UADDLP,M_SADALP,M_UADALP,M_CLS,M_CLZ,M_CNT,
    M_NOT,M_RBIT,M_CMGT0,M_CMGE0,M_CMEQ0,M_CMLE0,M_CMLT0,M_ABS,M_NEG,M_XTN,M_SHLL,
    M_SQABS,M_SQNEG,M_SUQADD,M_USQADD,M_SQXTN,M_UQXTN,M_SQXTUN
};
enum across_op {A_SADDLV=1,A_UADDLV,A_SMAXV,A_UMAXV,A_SMINV,A_UMINV,A_ADDV};
enum shift_op {
    H_SSHR=1,H_USHR,H_SSRA,H_USRA,H_SRSHR,H_URSHR,H_SRSRA,H_URSRA,H_SRI,H_SHL,H_SLI,
    H_SHRN,H_RSHRN,H_SSHLL,H_USHLL,
    H_SQSHL,H_UQSHL,H_SQSHLU,H_SQSHRN,H_UQSHRN,H_SQRSHRN,H_UQRSHRN,H_SQSHRUN,H_SQRSHRUN
};
enum diff_op {
    D_ADDL=1,D_ADDW,D_SUBL,D_SUBW,D_ABAL,D_ABDL,D_MLAL,D_MLSL,D_MULL,
    D_ADDHN,D_RADDHN,D_SUBHN,D_RSUBHN,D_PMULL,D_SQDMLAL,D_SQDMLSL,D_SQDMULL
};
enum copy_op {C_DUPE=1,C_DUPG,C_INSG,C_INSE,C_SMOV,C_UMOV};
enum elem_op {E_MUL=1,E_MLA,E_MLS,E_MULL,E_MLAL,E_MLSL,E_SQDMULH,E_SQRDMULH,E_SQDMLAL,E_SQDMLSL,E_SQDMULL};
enum fp_op {F_MOV=1,F_ABS,F_NEG};
enum fpv3_op {
    V3_FMAXNM=1,V3_FMINNM,V3_FMAXNMP,V3_FMINNMP,V3_FMLA,V3_FMLS,V3_FADD,V3_FSUB,V3_FADDP,V3_FABD,
    V3_FMULX,V3_FMUL,V3_FCMEQ,V3_FCMGE,V3_FCMGT,V3_FACGE,V3_FACGT,V3_FMAX,V3_FMIN,V3_FMAXP,V3_FMINP,
    V3_FRECPS,V3_FRSQRTS,V3_FDIV
};
enum fpv2_op {
    V2_FRINTN=1,V2_FRINTP,V2_FRINTM,V2_FRINTZ,V2_FRINTA,V2_FRINTX,V2_FRINTI,
    V2_FCVTNS,V2_FCVTPS,V2_FCVTMS,V2_FCVTZS,V2_FCVTAS,V2_SCVTF,
    V2_FCVTNU,V2_FCVTPU,V2_FCVTMU,V2_FCVTZU,V2_FCVTAU,V2_UCVTF,
    V2_FCMGT0,V2_FCMEQ0,V2_FCMLT0,V2_FCMGE0,V2_FCMLE0,V2_FABS,V2_FNEG,V2_FSQRT,V2_FCVTN,V2_FCVTL
};
enum fpve_op {VE_FMLA=1,VE_FMLS,VE_FMUL,VE_FMULX};
enum fpvp_op {VP_FADDP=1,VP_FMAXNMP,VP_FMINNMP,VP_FMAXP,VP_FMINP};
enum fpva_op {VA_FMAXNMV=1,VA_FMINNMV,VA_FMAXV,VA_FMINV};
enum modimm_op {I_ORR=1,I_BIC,I_MVNI,I_FMOV};

struct inst {
    uint32_t op;
    unsigned kind,sub,u,q,size,scalar,rd,rn,rm;
    unsigned eb;      /* element bits of the primary lane view */
    unsigned shift;   /* shift amount / EXT byte offset / FMOV type */
    unsigned idx,idx2;/* lane indexes for copy / element forms */
    unsigned part;    /* UZP/ZIP/TRN second variant */
};

static int span(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return p&&!(a&15u)&&n<=UINTPTR_MAX-a;}
static int overlap(const void *a,size_t n,const void *b,size_t m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m&&y<x+n;}
static uint64_t bmask(unsigned bits){return bits>=64?~UINT64_C(0):(UINT64_C(1)<<bits)-1u;}
static int64_t sxt(uint64_t v,unsigned bits)
{
    uint64_t m=bmask(bits),sign=UINT64_C(1)<<(bits-1u);
    v&=m;
    return (int64_t)((v^sign)-sign);
}
static uint64_t ushr(uint64_t v,unsigned s){return s>=64?0:v>>s;}
/* Arithmetic shift right of a two's-complement value, defined for s >= 64. */
static int64_t sar(int64_t v,unsigned s)
{
    uint64_t u=(uint64_t)v;
    if(s>=64)return v<0?-1:0;
    return (int64_t)(v<0?~(~u>>s):u>>s);
}
static unsigned clz_bits(uint64_t v,unsigned bits)
{
    unsigned n=0;
    v&=bmask(bits);
    while(n<bits&&!(v&(UINT64_C(1)<<(bits-1u-n))))++n;
    return n;
}
static void unpack(const uint8_t *r,unsigned eb,unsigned n,uint64_t *e)
{
    unsigned bytes=eb/8u;
    for(unsigned i=0;i<n;i++){
        uint64_t v=0;
        for(unsigned j=0;j<bytes;j++)v|=(uint64_t)r[i*bytes+j]<<(8u*j);
        e[i]=v;
    }
}
static void pack(uint8_t *r,unsigned eb,unsigned n,const uint64_t *e)
{
    unsigned bytes=eb/8u;
    for(unsigned i=0;i<n;i++)
        for(unsigned j=0;j<bytes;j++)r[i*bytes+j]=(uint8_t)(e[i]>>(8u*j));
}
static uint16_t rangemask(unsigned lo,unsigned n){return (uint16_t)(((1u<<n)-1u)<<lo);}

/* ---- decode ---- */
static int classify_copy(uint32_t op,struct inst *in)
{
    unsigned imm5=(op>>16)&31u,imm4=(op>>11)&15u,sz;
    if(!(imm5&15u))return 0;
    sz=(imm5&1u)?0u:(imm5&2u)?1u:(imm5&4u)?2u:3u;
    in->eb=8u<<sz;in->idx=imm5>>(sz+1u);in->size=sz;
    if(op&UINT32_C(0x20000000)){ /* INS (element) */
        if(!in->q)return 0;
        in->idx2=imm4>>sz;in->sub=C_INSE;return K_COPY;
    }
    switch(imm4){
    case 0: if(sz==3&&!in->q)return 0;in->sub=C_DUPE;return K_COPY;
    case 1: if(sz==3&&!in->q)return 0;in->sub=C_DUPG;return K_COPY;
    case 3: if(!in->q)return 0;in->sub=C_INSG;return K_COPY;
    case 5: if(in->q?sz>2:sz>1)return 0;in->sub=C_SMOV;return K_COPY;
    case 7: if(in->q?sz!=3:sz>2)return 0;in->sub=C_UMOV;return K_COPY;
    default: return 0;
    }
}
static int classify_fpv3(uint32_t op,struct inst *in);
static int classify_same(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>11)&31u,u=in->u,size=in->size,sub=0,big=0,satq=0;
    if(opc>=24)return classify_fpv3(op,in);
    switch(opc){
    case 0:  sub=u?S_UHADD:S_SHADD;break;
    case 1:  sub=u?S_UQADD:S_SQADD;big=1;satq=1;break;
    case 2:  sub=u?S_URHADD:S_SRHADD;break;
    case 4:  sub=u?S_UHSUB:S_SHSUB;break;
    case 5:  sub=u?S_UQSUB:S_SQSUB;big=1;satq=1;break;
    case 6:  sub=u?S_CMHI:S_CMGT;big=1;break;
    case 7:  sub=u?S_CMHS:S_CMGE;big=1;break;
    case 8:  sub=u?S_USHL:S_SSHL;big=1;break;
    case 9:  sub=u?S_UQSHL:S_SQSHL;big=1;satq=1;break;
    case 10: sub=u?S_URSHL:S_SRSHL;big=1;break;
    case 11: sub=u?S_UQRSHL:S_SQRSHL;big=1;satq=1;break;
    case 12: sub=u?S_UMAX:S_SMAX;break;
    case 13: sub=u?S_UMIN:S_SMIN;break;
    case 14: sub=u?S_UABD:S_SABD;break;
    case 15: sub=u?S_UABA:S_SABA;break;
    case 16: if(!in->scalar)return 0; /* vector ADD/SUB decode in simd_integer */
             sub=u?S_SUB:S_ADD;big=1;break;
    case 17: sub=u?S_CMEQ:S_CMTST;big=1;break;
    case 18: sub=u?S_MLS:S_MLA;break;
    case 19: if(u&&size)return 0;sub=u?S_PMUL:S_MUL;break;
    case 20: sub=u?S_UMAXP:S_SMAXP;break;
    case 21: sub=u?S_UMINP:S_SMINP;break;
    case 22: if(size!=1&&size!=2)return 0;sub=u?S_SQRDMULH:S_SQDMULH;satq=1;break;
    case 23: if(u)return 0;sub=S_ADDP;break;
    default: return 0;
    }
    if(in->scalar){
        if(satq){if(sub==S_SQDMULH||sub==S_SQRDMULH){if(size!=1&&size!=2)return 0;}}
        else if(!big||size!=3)return 0;
    }else{
        if(sub==S_PMUL&&size!=0)return 0;
        if(size==3&&(!in->q||!(big||sub==S_ADDP)))return 0;
    }
    in->sub=sub;in->eb=8u<<size;return K_SAME;
}
static int classify_diff(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>12)&15u,sub=0,size=in->size;
    if(in->scalar){
        /* scalar: only the saturating doubling multiplies, S<-H and D<-S */
        if(size!=1&&size!=2)return 0;
        if(opc==9)sub=D_SQDMLAL;else if(opc==11)sub=D_SQDMLSL;else if(opc==13)sub=D_SQDMULL;else return 0;
        if(in->u)return 0;
        in->sub=sub;in->eb=8u<<size;return K_DIFF;
    }
    if(size==3)return 0;
    switch(opc){
    case 0: sub=D_ADDL;break;
    case 1: sub=D_ADDW;break;
    case 2: sub=D_SUBL;break;
    case 3: sub=D_SUBW;break;
    case 4: sub=in->u?D_RADDHN:D_ADDHN;break;
    case 5: sub=D_ABAL;break;
    case 6: sub=in->u?D_RSUBHN:D_SUBHN;break;
    case 7: sub=D_ABDL;break;
    case 8: sub=D_MLAL;break;
    case 9: if(in->u||size==0)return 0;sub=D_SQDMLAL;break;
    case 10: sub=D_MLSL;break;
    case 11: if(in->u||size==0)return 0;sub=D_SQDMLSL;break;
    case 12: sub=D_MULL;break;
    case 13: if(in->u||size==0)return 0;sub=D_SQDMULL;break;
    case 14: if(in->u||size!=0)return 0;sub=D_PMULL;break;
    default: return 0;
    }
    in->sub=sub;in->eb=8u<<size;return K_DIFF;
}
/* ---- vector / scalar-SIMD floating point (S and D only) ---- */
static int classify_fpv3(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>11)&31u,u=in->u,a=(op>>23)&1u,sz=(op>>22)&1u,sub=0;
    switch(opc){
    case 24: sub=u?(a?V3_FMINNMP:V3_FMAXNMP):(a?V3_FMINNM:V3_FMAXNM);break;
    case 25: if(u)return 0;sub=a?V3_FMLS:V3_FMLA;break;
    case 26: sub=u?(a?V3_FABD:V3_FADDP):(a?V3_FSUB:V3_FADD);break;
    case 27: if(a)return 0;sub=u?V3_FMUL:V3_FMULX;break;
    case 28: if(!u){if(a)return 0;sub=V3_FCMEQ;}else sub=a?V3_FCMGT:V3_FCMGE;break;
    case 29: if(!u)return 0;sub=a?V3_FACGT:V3_FACGE;break;
    case 30: sub=u?(a?V3_FMINP:V3_FMAXP):(a?V3_FMIN:V3_FMAX);break;
    case 31: if(u){if(a)return 0;sub=V3_FDIV;}else sub=a?V3_FRSQRTS:V3_FRECPS;break;
    default: return 0;
    }
    if(in->scalar){
        if(!(sub==V3_FMULX||sub==V3_FCMEQ||sub==V3_FCMGE||sub==V3_FCMGT||sub==V3_FACGE||sub==V3_FACGT||
             sub==V3_FRECPS||sub==V3_FRSQRTS||sub==V3_FABD))return 0;
    }else if(sz&&!in->q)return 0;
    in->eb=sz?64u:32u;in->sub=sub;in->idx2=G3;return K_FPV;
}
static int classify_fpv2(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>12)&31u,u=in->u,a=(op>>23)&1u,sz=(op>>22)&1u,sub=0;
    switch(opc){
    case 12: if(!a)return 0;sub=u?V2_FCMGE0:V2_FCMGT0;break;
    case 13: if(!a)return 0;sub=u?V2_FCMLE0:V2_FCMEQ0;break;
    case 14: if(!a||u)return 0;sub=V2_FCMLT0;break;
    case 15: if(!a||in->scalar)return 0;sub=u?V2_FNEG:V2_FABS;break;
    case 22: if(u||a||!sz||in->scalar)return 0;sub=V2_FCVTN;break;
    case 23: if(u||a||!sz||in->scalar)return 0;sub=V2_FCVTL;break;
    case 24: if(in->scalar)return 0;
             if(u){if(a)return 0;sub=V2_FRINTA;}else sub=a?V2_FRINTP:V2_FRINTN;break;
    case 25: if(in->scalar)return 0;
             if(u)sub=a?V2_FRINTI:V2_FRINTX;else sub=a?V2_FRINTZ:V2_FRINTM;break;
    case 26: sub=u?(a?V2_FCVTPU:V2_FCVTNU):(a?V2_FCVTPS:V2_FCVTNS);break;
    case 27: sub=u?(a?V2_FCVTZU:V2_FCVTMU):(a?V2_FCVTZS:V2_FCVTMS);break;
    case 28: if(a)return 0;sub=u?V2_FCVTAU:V2_FCVTAS;break;
    case 29: if(a)return 0;sub=u?V2_UCVTF:V2_SCVTF;break;
    case 31: if(!a||!u||in->scalar)return 0;sub=V2_FSQRT;break;
    default: return 0;
    }
    if(!in->scalar&&sz&&!in->q&&sub!=V2_FCVTN&&sub!=V2_FCVTL)return 0;
    in->eb=sz?64u:32u;in->sub=sub;in->idx2=G2;return K_FPV;
}
static int classify_misc(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>12)&31u,u=in->u,size=in->size,sub=0;
    if((opc>=12&&opc<=15)||opc==22||opc==23||opc>=24)return classify_fpv2(op,in);
    in->eb=8u<<size;
    if(in->scalar){
        switch(opc){
        case 3: sub=u?M_USQADD:M_SUQADD;break;
        case 7: sub=u?M_SQNEG:M_SQABS;break;
        case 18: if(!u||size==3)return 0;sub=M_SQXTUN;break;
        case 20: if(size==3)return 0;sub=u?M_UQXTN:M_SQXTN;break;
        default: break;
        }
        if(sub){in->sub=sub;return K_MISC;}
        if(size!=3)return 0;
        switch(opc){
        case 8: sub=u?M_CMGE0:M_CMGT0;break;
        case 9: sub=u?M_CMLE0:M_CMEQ0;break;
        case 10: if(u)return 0;sub=M_CMLT0;break;
        case 11: sub=u?M_NEG:M_ABS;break;
        default: return 0;
        }
        in->sub=sub;return K_MISC;
    }
    switch(opc){
    case 0: if(u){if(size>1)return 0;sub=M_REV32;}else{if(size>2)return 0;sub=M_REV64;}break;
    case 1: if(u||size)return 0;sub=M_REV16;break;
    case 2: if(size==3)return 0;sub=u?M_UADDLP:M_SADDLP;break;
    case 3: sub=u?M_USQADD:M_SUQADD;break;
    case 7: sub=u?M_SQNEG:M_SQABS;break;
    case 6: if(size==3)return 0;sub=u?M_UADALP:M_SADALP;break;
    case 4: if(size==3)return 0;sub=u?M_CLZ:M_CLS;break;
    case 5: if(!u){if(size)return 0;sub=M_CNT;}
            else if(size==0)sub=M_NOT;else if(size==1){sub=M_RBIT;in->eb=8;}else return 0; /* RBIT: size 01 selects bytes */
            break;
    case 8: sub=u?M_CMGE0:M_CMGT0;break;
    case 9: sub=u?M_CMLE0:M_CMEQ0;break;
    case 10: if(u)return 0;sub=M_CMLT0;break;
    case 11: sub=u?M_NEG:M_ABS;break;
    case 18: if(size==3)return 0;sub=u?M_SQXTUN:M_XTN;break;
    case 20: if(size==3)return 0;sub=u?M_UQXTN:M_SQXTN;break;
    case 19: if(!u||size==3)return 0;sub=M_SHLL;break;
    default: return 0;
    }
    if(size==3&&!in->q&&(sub==M_CMGT0||sub==M_CMGE0||sub==M_CMEQ0||sub==M_CMLE0||sub==M_CMLT0||sub==M_ABS||sub==M_NEG||
       sub==M_SUQADD||sub==M_USQADD||sub==M_SQABS||sub==M_SQNEG))return 0;
    in->sub=sub;return K_MISC;
}
static int classify_across(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>12)&31u,sub=0;
    if(opc==12||opc==15){ /* FMAXNMV/FMINNMV/FMAXV/FMINV: 4S only */
        unsigned a=(op>>23)&1u,sz=(op>>22)&1u;
        if(!in->u||sz||!in->q)return 0;
        sub=opc==12?(a?VA_FMINNMV:VA_FMAXNMV):(a?VA_FMINV:VA_FMAXV);
        in->eb=32;in->sub=sub;in->idx2=GA;return K_FPV;
    }
    if(in->size==3||(in->size==2&&!in->q))return 0;
    switch(opc){
    case 3: sub=in->u?A_UADDLV:A_SADDLV;break;
    case 10: sub=in->u?A_UMAXV:A_SMAXV;break;
    case 26: sub=in->u?A_UMINV:A_SMINV;break;
    case 27: if(in->u)return 0;sub=A_ADDV;break;
    default: return 0;
    }
    in->sub=sub;in->eb=8u<<in->size;return K_ACROSS;
}
static int classify_shift(uint32_t op,struct inst *in)
{
    unsigned immh=(op>>19)&15u,immhb=(op>>16)&127u,opc=(op>>11)&31u,u=in->u,sub=0,eb,top,narrow=0,left=0;
    if(!immh)return 0;
    if(opc==28||opc==31){ /* SCVTF/UCVTF and FCVTZS/FCVTZU (fixed-point), S and D */
        unsigned t=immh&8u?3u:immh&4u?2u:0u;
        if(!t)return 0; /* half precision not modelled */
        if(t==3&&!in->q&&!in->scalar)return 0;
        in->eb=8u<<t;in->shift=2u*in->eb-immhb;
        in->sub=opc==28?(u?V2_UCVTF:V2_SCVTF):(u?V2_FCVTZU:V2_FCVTZS);
        in->idx2=GS;return K_FPV;
    }
    top=immh&8u?3u:immh&4u?2u:immh&2u?1u:0u;
    eb=8u<<top;in->eb=eb;
    switch(opc){
    case 0: sub=u?H_USHR:H_SSHR;break;
    case 2: sub=u?H_USRA:H_SSRA;break;
    case 4: sub=u?H_URSHR:H_SRSHR;break;
    case 6: sub=u?H_URSRA:H_SRSRA;break;
    case 8: if(!u)return 0;sub=H_SRI;break;
    case 10: sub=u?H_SLI:H_SHL;left=1;break;
    case 12: if(!u)return 0;sub=H_SQSHLU;left=1;break;
    case 14: sub=u?H_UQSHL:H_SQSHL;left=1;break;
    case 16: sub=u?H_SQSHRUN:H_SHRN;narrow=1;break;
    case 17: sub=u?H_SQRSHRUN:H_RSHRN;narrow=1;break;
    case 18: sub=u?H_UQSHRN:H_SQSHRN;narrow=1;break;
    case 19: sub=u?H_UQRSHRN:H_SQRSHRN;narrow=1;break;
    case 20: if(in->scalar)return 0;sub=u?H_USHLL:H_SSHLL;break;
    default: return 0;
    }
    if(in->scalar){
        /* scalar: 64-bit forms of the plain shifts; any size for saturating left
         * shifts; narrowing forms read a 2*eb scalar. SHRN/RSHRN have no scalar form. */
        if(sub==H_SHRN||sub==H_RSHRN)return 0;
        if(narrow){if(top==3)return 0;}
        else if(!(sub==H_SQSHL||sub==H_UQSHL||sub==H_SQSHLU)&&top!=3)return 0;
    }else{
        if(top==3&&(!in->q||narrow||sub==H_SSHLL||sub==H_USHLL))return 0;
    }
    in->shift=(left||sub==H_SSHLL||sub==H_USHLL)?immhb-eb:2u*eb-immhb;
    in->sub=sub;return K_SHIFT;
}
/* Modified-immediate forms not handled by a64_simd_integer (MOVI): ORR, BIC,
 * MVNI and vector FMOV. cmode<3:1>==111 with op==1 is the 64-bit byte mask
 * MOVI (simd_integer) or FMOV 2D (cmode 1111). */
static int classify_modimm(uint32_t op,struct inst *in)
{
    unsigned cmode=(op>>12)&15u,o=in->u;
    if((op&UINT32_C(0x00f80800))!=0)return 0; /* immh==0, bit23==0, o2==0 (half FMOV excluded) */
    if(!o){
        if((cmode&9u)==1u||(cmode&13u)==9u){in->sub=I_ORR;}
        else if(cmode==15){in->sub=I_FMOV;}
        else return 0;
    }else{
        if((cmode&9u)==1u||(cmode&13u)==9u)in->sub=I_BIC;
        else if(cmode<8u&&!(cmode&1u))in->sub=I_MVNI;
        else if((cmode&13u)==8u)in->sub=I_MVNI;
        else if((cmode&14u)==12u)in->sub=I_MVNI;
        else if(cmode==15){if(!in->q)return 0;in->sub=I_FMOV;}
        else return 0;
    }
    return K_MODIMM;
}
static int classify_elem(uint32_t op,struct inst *in)
{
    unsigned opc=(op>>12)&15u,size=in->size,l=(op>>21)&1u,m=(op>>20)&1u,h=(op>>11)&1u,sub=0;
    if(size>=2&&(opc==1||opc==5||opc==9)){ /* FMLA FMLS FMUL FMULX by element */
        unsigned sz=size&1u;
        if(opc==9)sub=in->u?VE_FMULX:VE_FMUL;else{if(in->u)return 0;sub=opc==1?VE_FMLA:VE_FMLS;}
        if(sz){if(l)return 0;in->idx=h;}else in->idx=h<<1|l;
        if(sz&&!in->q&&!in->scalar)return 0;
        in->rm=(m<<4)|((op>>16)&15u);
        in->eb=sz?64u:32u;in->sub=sub;in->idx2=GE;return K_FPV;
    }
    if(size!=1&&size!=2)return 0;
    switch(opc){
    case 8: if(in->u)return 0;sub=E_MUL;break;
    case 0: if(!in->u)return 0;sub=E_MLA;break;
    case 4: if(!in->u)return 0;sub=E_MLS;break;
    case 12: if(in->u)return 0;sub=E_SQDMULH;break;
    case 13: if(in->u)return 0;sub=E_SQRDMULH;break;
    case 3: if(in->u)return 0;sub=E_SQDMLAL;break;
    case 7: if(in->u)return 0;sub=E_SQDMLSL;break;
    case 11: if(in->u)return 0;sub=E_SQDMULL;break;
    case 10: sub=E_MULL;break;
    case 2: sub=E_MLAL;break;
    case 6: sub=E_MLSL;break;
    default: return 0;
    }
    if(in->scalar&&!(sub==E_SQDMULH||sub==E_SQRDMULH||sub==E_SQDMLAL||sub==E_SQDMLSL||sub==E_SQDMULL))return 0;
    in->eb=8u<<size;
    if(size==1){in->idx=h<<2|l<<1|m;in->rm=(op>>16)&15u;}
    else{in->idx=h<<1|l;in->rm=(m<<4)|((op>>16)&15u);}
    in->sub=sub;return K_ELEM;
}
static int classify(uint32_t op,struct inst *in)
{
    unsigned k=0;
    in->op=op;in->q=(op>>30)&1u;in->u=(op>>29)&1u;in->size=(op>>22)&3u;
    in->rd=op&31u;in->rn=(op>>5)&31u;in->rm=(op>>16)&31u;
    in->scalar=0;in->sub=in->eb=in->shift=in->idx=in->idx2=in->part=0;
    /* scalar floating point: FMOV (register), FABS, FNEG, FMOV (immediate) */
    if((op&UINT32_C(0xffbffc00))==UINT32_C(0x1e204000)||(op&UINT32_C(0xffbffc00))==UINT32_C(0x1e20c000)||
       (op&UINT32_C(0xffbffc00))==UINT32_C(0x1e214000)){
        in->shift=(op>>22)&1u;in->eb=in->shift?64u:32u;
        in->sub=(op&UINT32_C(0xffbffc00))==UINT32_C(0x1e204000)?F_MOV:
                (op&UINT32_C(0xffbffc00))==UINT32_C(0x1e20c000)?F_ABS:F_NEG;
        return K_FPREG;
    }
    if((op&UINT32_C(0xff201fe0))==UINT32_C(0x1e201000)&&((op>>22)&3u)<2u){
        in->shift=(op>>22)&1u;in->eb=in->shift?64u:32u;in->idx=(op>>13)&255u;return K_FPIMM;
    }
    {   /* scalar floating point data processing, S and D only (type 00 / 01) */
        unsigned type=(op>>22)&3u;
        if(type<2u){
            in->eb=type?64u:32u;in->shift=type;
            if((op&UINT32_C(0xff200c00))==UINT32_C(0x1e200800)){ /* two source */
                unsigned opc=(op>>12)&15u;
                if(opc<=8u){in->sub=opc;return K_FPDP2;}
                return 0;
            }
            if((op&UINT32_C(0xff207c00))==UINT32_C(0x1e204000)){ /* one source */
                unsigned opc=(op>>15)&63u;
                switch(opc){
                case 3: in->sub=100;return K_FPDP1;                 /* FSQRT */
                case 4: if(type!=1u)return 0;in->sub=101;return K_FPDP1;  /* FCVT Sd,Dn */
                case 5: if(type!=0u)return 0;in->sub=102;return K_FPDP1;  /* FCVT Dd,Sn */
                case 8: case 9: case 10: case 11: case 12: case 14: case 15:
                    in->sub=opc;return K_FPDP1;                     /* FRINT* */
                default: return 0;
                }
            }
            if((op&UINT32_C(0xff20fc07))==UINT32_C(0x1e202000)){ /* FCMP / FCMPE */
                unsigned o2=(op>>3)&3u;
                if((o2&1u)&&in->rm)return 0;
                in->sub=o2;return K_FPCMP;
            }
            if((op&UINT32_C(0xff200c00))==UINT32_C(0x1e200400)){in->sub=(op>>4)&1u;return K_FPCCMP;}
            if((op&UINT32_C(0xff200c00))==UINT32_C(0x1e200c00))return K_FPCSEL;
        }
        if(type<2u&&(op&UINT32_C(0xff000000))==UINT32_C(0x1f000000)){ /* FMADD FMSUB FNMADD FNMSUB */
            in->sub=((op>>20)&2u)|((op>>15)&1u);in->idx=(op>>10)&31u;return K_FPFMA;
        }
        /* FP <-> integer, and fixed-point (sf 0 0 11110 type ...) */
        if(type<2u&&(op&UINT32_C(0x7f200000))==UINT32_C(0x1e000000)){ /* fixed point */
            unsigned rmode=(op>>19)&3u,opc=(op>>16)&7u,scale=(op>>10)&63u,sf=op>>31;
            if(!sf&&scale<32u)return 0;
            if(rmode==0&&(opc==2u||opc==3u)){in->sub=opc;in->idx=64u-scale;in->idx2=1;return K_FPINT;}
            if(rmode==3&&(opc==0u||opc==1u)){in->sub=opc;in->idx=64u-scale;in->idx2=1;return K_FPINT;}
            return 0;
        }
        if(type<2u&&(op&UINT32_C(0x7f20fc00))==UINT32_C(0x1e200000)){ /* integer conversions */
            unsigned rmode=(op>>19)&3u,opc=(op>>16)&7u;
            if(opc==6u||opc==7u)return 0; /* FMOV general: a64_fmov */
            if(opc>=4u&&(rmode!=0||opc>5u))return 0;
            if((opc==2u||opc==3u)&&rmode!=0)return 0;
            in->sub=opc;in->idx=0;in->idx2=0;return K_FPINT;
        }
    }
    if((op&UINT32_C(0xdf800400))==UINT32_C(0x5f000400)&&((op>>19)&15u)){
        in->scalar=1;in->q=0;return classify_shift(op,in);
    }
    if((op&UINT32_C(0xdf000400))==UINT32_C(0x5f000000)){ /* scalar by element */
        in->scalar=1;in->q=0;return classify_elem(op,in);
    }
    if((op&UINT32_C(0xdf200c00))==UINT32_C(0x5e200000)){ /* scalar three different */
        in->scalar=1;in->q=0;return classify_diff(op,in);
    }
    if((op&UINT32_C(0xdf000000))==UINT32_C(0x5e000000)){
        in->scalar=1;in->q=0;
        if((op&UINT32_C(0xdfe0fc00))==UINT32_C(0x5e000400)&&!in->u){
            /* DUP (element) scalar: only imm4==0 */
            in->q=1;
            k=classify_copy(op,in);
            if(k&&in->sub==C_DUPE){in->scalar=1;in->q=0;return K_COPY;}
            return 0;
        }
        if((op&UINT32_C(0xdf3e0c00))==UINT32_C(0x5e300800)){
            if(!in->u&&in->size==3&&((op>>12)&31u)==27){in->sub=1;in->eb=64;return K_PAIR;}
            if(in->u){
                unsigned opc=(op>>12)&31u,a=(op>>23)&1u,sz=(op>>22)&1u;
                if(opc==13&&!a){in->sub=VP_FADDP;}
                else if(opc==12){in->sub=a?VP_FMINNMP:VP_FMAXNMP;}
                else if(opc==15){in->sub=a?VP_FMINP:VP_FMAXP;}
                else return 0;
                in->eb=sz?64u:32u;in->idx2=GP;return K_FPV;
            }
            return 0;
        }
        if((op&UINT32_C(0xdf200400))==UINT32_C(0x5e200400))return classify_same(op,in);
        if((op&UINT32_C(0xdf3e0c00))==UINT32_C(0x5e200800))return classify_misc(op,in);
        return 0;
    }
    if((op&UINT32_C(0x80000000)))return 0;
    if((op&UINT32_C(0x1f000000))==UINT32_C(0x0e000000)){
        if(op&UINT32_C(0x200000)){
            if(op&UINT32_C(0x400))return classify_same(op,in);
            if(!(op&UINT32_C(0x800))&&!(op&UINT32_C(0x400)))return classify_diff(op,in);
            if((op&UINT32_C(0xc00))==UINT32_C(0x800)){
                if(((op>>17)&31u)==16u)return classify_misc(op,in);
                if(((op>>17)&31u)==24u)return classify_across(op,in);
            }
            return 0;
        }
        if(op&UINT32_C(0x8000))return 0;
        if(op&UINT32_C(0x400)){
            if(((op>>21)&7u)==0)return classify_copy(op,in);
            return 0;
        }
        if(!in->u&&in->size==0&&!(op&UINT32_C(0xc00))){ /* TBL/TBX: 0 Q 001110 00 0 Rm 0 len op 00 */
            in->sub=(op>>12)&1u;in->shift=((op>>13)&3u)+1u;return K_TBL;
        }
        if(in->u){ /* EXT: 0 Q 101110 00 0 Rm 0 imm4 0 */
            if(in->size!=0)return 0;
            if(!in->q&&(op&UINT32_C(0x4000)))return 0; /* imm4<3> */
            in->shift=(op>>11)&15u;return K_EXT;
        }
        if((op&UINT32_C(0xc00))==UINT32_C(0x800)){ /* permute */
            unsigned opc=(op>>12)&7u;
            if(in->size==3&&!in->q)return 0;
            switch(opc){
            case 1: case 2: case 3: in->sub=opc;in->part=0;break; /* UZP1 TRN1 ZIP1 */
            case 5: case 6: case 7: in->sub=opc-4u;in->part=1;break;
            default: return 0;
            }
            in->eb=8u<<in->size;return K_PERM;
        }
        return 0;
    }
    if((op&UINT32_C(0x1f000000))==UINT32_C(0x0f000000)){
        if(op&UINT32_C(0x400)){
            if(op&UINT32_C(0x800000))return 0;
            if(!((op>>19)&15u))return classify_modimm(op,in);
            return classify_shift(op,in);
        }
        return classify_elem(op,in);
    }
    return 0;
}
unsigned ocnext_a64_simd_ext_decode(uint32_t op)
{
    struct inst in;
    return (unsigned)classify(op,&in);
}

/* ---- execute ---- */
struct run {
    const struct ocnext_a64_vector_registers *b;
    const struct inst *in;
    uint8_t d[16];
    uint16_t known;
    int qc;
};
static int need(const struct run *r,unsigned reg,unsigned lo,unsigned n)
{
    uint16_t m=rangemask(lo,n);
    return (r->b->known_bytes[reg]&m)==m;
}
/* The destination image starts as zeros (everything known) unless the
 * instruction preserves old Vd bytes. */
static void init_zero(struct run *r){for(unsigned i=0;i<16;i++)r->d[i]=0;r->known=0xffffu;}
static void init_preserve(struct run *r,unsigned reg)
{
    for(unsigned i=0;i<16;i++)r->d[i]=r->b->bytes[reg][i];
    r->known=r->b->known_bytes[reg];
}
#define NEED(r,reg,lo,n) do{if(!need((r),(reg),(lo),(n)))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;}while(0)
typedef enum ocnext_a64_simd_ext_result res_t;

/* ---- saturating helpers (explicit 64-bit overflow handling, no __int128) ---- */
static int64_t smin_b(unsigned eb){return eb>=64?INT64_MIN:-(int64_t)(UINT64_C(1)<<(eb-1u));}
static int64_t smax_b(unsigned eb){return eb>=64?INT64_MAX:(int64_t)((UINT64_C(1)<<(eb-1u))-1u);}
static uint64_t clamp_s(int64_t v,unsigned eb,int *q)
{
    if(v>smax_b(eb)){*q=1;return (uint64_t)smax_b(eb)&bmask(eb);}
    if(v<smin_b(eb)){*q=1;return (uint64_t)smin_b(eb)&bmask(eb);}
    return (uint64_t)v&bmask(eb);
}
static uint64_t clamp_su(int64_t v,unsigned eb,int *q)
{
    if(v<0){*q=1;return 0;}
    if(eb<64&&(uint64_t)v>bmask(eb)){*q=1;return bmask(eb);}
    return (uint64_t)v;
}
static uint64_t clamp_u(uint64_t v,unsigned eb,int *q)
{
    if(eb<64&&v>bmask(eb)){*q=1;return bmask(eb);}
    return v;
}
static uint64_t sat64(int64_t sign_of,int *q){*q=1;return sign_of<0?(uint64_t)INT64_MIN:(uint64_t)INT64_MAX;}
static uint64_t sq_add(int64_t a,int64_t b,unsigned eb,int *q)
{
    uint64_t sum;
    if(eb<64)return clamp_s(a+b,eb,q);
    sum=(uint64_t)a+(uint64_t)b;
    if(((uint64_t)a^sum)&((uint64_t)b^sum)&(UINT64_C(1)<<63))return sat64(a,q);
    return sum;
}
static uint64_t sq_sub(int64_t a,int64_t b,unsigned eb,int *q)
{
    uint64_t d;
    if(eb<64)return clamp_s(a-b,eb,q);
    d=(uint64_t)a-(uint64_t)b;
    if(((uint64_t)a^(uint64_t)b)&((uint64_t)a^d)&(UINT64_C(1)<<63))return sat64(a,q);
    return d;
}
static uint64_t uq_add(uint64_t a,uint64_t b,unsigned eb,int *q)
{
    uint64_t sum=a+b;
    if(eb<64)return clamp_u(sum,eb,q);
    if(sum<a){*q=1;return ~UINT64_C(0);}
    return sum;
}
static uint64_t uq_sub(uint64_t a,uint64_t b,int *q){if(a<b){*q=1;return 0;}return a-b;}
/* SUQADD lane: signed a + unsigned b, signed saturation */
static uint64_t suq_add(int64_t a,uint64_t b,unsigned eb,int *q)
{
    if(eb<64)return clamp_s(a+(int64_t)b,eb,q);
    if(a>=0){uint64_t sum=(uint64_t)a+b;if(sum<b||sum>(uint64_t)INT64_MAX){*q=1;return (uint64_t)INT64_MAX;}return sum;}
    {
        uint64_t mag=(uint64_t)0-(uint64_t)a; /* 1..2^63 */
        if(b>=mag){uint64_t t=b-mag;if(t>(uint64_t)INT64_MAX){*q=1;return (uint64_t)INT64_MAX;}return t;}
        return (uint64_t)0-(mag-b);
    }
}
/* USQADD lane: unsigned a + signed b, unsigned saturation */
static uint64_t usq_add(uint64_t a,int64_t b,unsigned eb,int *q)
{
    if(eb<64){int64_t v=(int64_t)a+b;return clamp_su(v,eb,q);}
    if(b>=0){uint64_t sum=a+(uint64_t)b;if(sum<a){*q=1;return ~UINT64_C(0);}return sum;}
    {
        uint64_t mag=(uint64_t)0-(uint64_t)b;
        if(a>=mag)return a-mag;
        *q=1;return 0;
    }
}
static uint64_t sq_shl(int64_t s,unsigned amt,unsigned eb,int *q)
{
    int64_t v;
    if(s==0)return 0;
    if(amt>=eb){*q=1;return (s<0?(uint64_t)smin_b(eb):(uint64_t)smax_b(eb))&bmask(eb);}
    v=(int64_t)((uint64_t)s<<amt);
    if(eb<64)return clamp_s(v,eb,q);
    if(sar(v,amt)!=s)return sat64(s,q);
    return (uint64_t)v;
}
static uint64_t uq_shl(uint64_t x,unsigned amt,unsigned eb,int *q)
{
    uint64_t v;
    if(x==0)return 0;
    if(amt>=eb){*q=1;return bmask(eb);}
    v=x<<amt;
    if(eb<64)return clamp_u(v,eb,q);
    if((v>>amt)!=x){*q=1;return ~UINT64_C(0);}
    return v;
}
static uint64_t rshift_s(int64_t s,unsigned k,int round)
{
    int64_t r=sar(s,k);
    if(round)r+=sar(s,k-1u)&1;
    return (uint64_t)r;
}
static uint64_t rshift_u(uint64_t x,unsigned k,int round)
{
    uint64_t r=ushr(x,k);
    if(round)r+=ushr(x,k-1u)&1u;
    return r;
}
/* SQDMULH / SQRDMULH lane (eb 16 or 32) */
static uint64_t sq_dmulh(int64_t a,int64_t b,unsigned eb,int round,int *q)
{
    int64_t v;
    if(a==smin_b(eb)&&b==smin_b(eb)){*q=1;return (uint64_t)smax_b(eb)&bmask(eb);}
    v=2*(a*b);
    if(round)v+=(int64_t)(UINT64_C(1)<<(eb-1u));
    return (uint64_t)sar(v,eb)&bmask(eb);
}

static res_t run_copy(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned eb=in->eb,bytes=eb/8u,ds=in->q?16u:8u;
    switch(in->sub){
    case C_DUPE:{
        uint64_t v=0;
        NEED(r,in->rn,in->idx*bytes,bytes);
        init_zero(r);
        for(unsigned j=0;j<bytes;j++)v|=(uint64_t)r->b->bytes[in->rn][in->idx*bytes+j]<<(8u*j);
        if(in->scalar)ds=bytes;
        for(unsigned i=0;i<ds/bytes;i++)for(unsigned j=0;j<bytes;j++)r->d[i*bytes+j]=(uint8_t)(v>>(8u*j));
        return OCNEXT_A64_SIMD_EXT_OK;}
    case C_DUPG:
        init_zero(r);
        for(unsigned i=0;i<ds/bytes;i++)for(unsigned j=0;j<bytes;j++)r->d[i*bytes+j]=(uint8_t)(rq->gpr_value>>(8u*j));
        return OCNEXT_A64_SIMD_EXT_OK;
    case C_INSG:
        init_preserve(r,in->rd);
        for(unsigned j=0;j<bytes;j++)r->d[in->idx*bytes+j]=(uint8_t)(rq->gpr_value>>(8u*j));
        r->known|=rangemask(in->idx*bytes,bytes);
        return OCNEXT_A64_SIMD_EXT_OK;
    case C_INSE:
        NEED(r,in->rn,in->idx2*bytes,bytes);
        init_preserve(r,in->rd);
        for(unsigned j=0;j<bytes;j++)r->d[in->idx*bytes+j]=r->b->bytes[in->rn][in->idx2*bytes+j];
        r->known|=rangemask(in->idx*bytes,bytes);
        return OCNEXT_A64_SIMD_EXT_OK;
    case C_SMOV: case C_UMOV:{
        uint64_t v=0;
        NEED(r,in->rn,in->idx*bytes,bytes);
        for(unsigned j=0;j<bytes;j++)v|=(uint64_t)r->b->bytes[in->rn][in->idx*bytes+j]<<(8u*j);
        if(in->sub==C_SMOV)v=(uint64_t)sxt(v,eb);
        if(!in->q)v&=bmask(32);
        fx->gpr_write=1;fx->gpr_rd=(uint8_t)in->rd;fx->gpr_value=v;
        return OCNEXT_A64_SIMD_EXT_OK;}
    }
    return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
}
static res_t run_ext(struct run *r)
{
    const struct inst *in=r->in;unsigned ds=in->q?16u:8u,pos=in->shift;uint8_t cat[32];
    NEED(r,in->rn,0,ds);NEED(r,in->rm,0,ds);
    for(unsigned i=0;i<ds;i++){cat[i]=r->b->bytes[in->rn][i];cat[ds+i]=r->b->bytes[in->rm][i];}
    init_zero(r);
    for(unsigned i=0;i<ds;i++)r->d[i]=cat[pos+i];
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_perm(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,ds=in->q?16u:8u,n=ds*8u/eb;uint64_t a[16],b[16],o[16];
    NEED(r,in->rn,0,ds);NEED(r,in->rm,0,ds);
    unpack(r->b->bytes[in->rn],eb,n,a);unpack(r->b->bytes[in->rm],eb,n,b);
    switch(in->sub){
    case 1: /* UZP */
        for(unsigned i=0;i<n/2;i++){o[i]=a[2*i+in->part];o[n/2+i]=b[2*i+in->part];}
        break;
    case 2: /* TRN */
        for(unsigned i=0;i<n/2;i++){o[2*i]=a[2*i+in->part];o[2*i+1]=b[2*i+in->part];}
        break;
    default: /* ZIP */
        for(unsigned i=0;i<n/2;i++){o[2*i]=a[in->part*(n/2)+i];o[2*i+1]=b[in->part*(n/2)+i];}
    }
    init_zero(r);pack(r->d,eb,n,o);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static uint64_t pmul8(uint64_t a,uint64_t b)
{
    uint64_t x=0;
    for(unsigned i=0;i<8;i++)if((b>>i)&1u)x^=a<<i;
    return x&0xffu;
}
static res_t run_same(struct run *r)
{
    const struct inst *in=r->in;
    unsigned eb=in->eb,ds=in->scalar?eb/8u:in->q?16u:8u,n=in->scalar?1u:ds*8u/eb,sub=in->sub;
    uint64_t a[16],b[16],d[16],o[16],m=bmask(eb);
    NEED(r,in->rn,0,ds);NEED(r,in->rm,0,ds);
    if(sub==S_SABA||sub==S_UABA||sub==S_MLA||sub==S_MLS)NEED(r,in->rd,0,ds);
    unpack(r->b->bytes[in->rn],eb,n,a);unpack(r->b->bytes[in->rm],eb,n,b);
    unpack(r->b->bytes[in->rd],eb,n,d);
    if(sub==S_ADDP||sub==S_SMAXP||sub==S_UMAXP||sub==S_SMINP||sub==S_UMINP){
        uint64_t cat[32];
        for(unsigned i=0;i<n;i++){cat[i]=a[i];cat[n+i]=b[i];}
        for(unsigned i=0;i<n;i++){
            uint64_t x=cat[2*i],y=cat[2*i+1];int64_t sx_=sxt(x,eb),sy=sxt(y,eb);
            switch(sub){
            case S_ADDP:o[i]=(x+y)&m;break;
            case S_SMAXP:o[i]=(uint64_t)(sx_>sy?sx_:sy)&m;break;
            case S_SMINP:o[i]=(uint64_t)(sx_<sy?sx_:sy)&m;break;
            case S_UMAXP:o[i]=x>y?x:y;break;
            default:o[i]=x<y?x:y;
            }
        }
    }else for(unsigned i=0;i<n;i++){
        uint64_t x=a[i],y=b[i],z;int64_t sx_=sxt(x,eb),sy=sxt(y,eb);
        switch(sub){
        case S_SHADD: z=(uint64_t)sar(sx_+sy,1);break;
        case S_UHADD: z=(x+y)>>1;break;
        case S_SRHADD: z=(uint64_t)sar(sx_+sy+1,1);break;
        case S_URHADD: z=(x+y+1)>>1;break;
        case S_SHSUB: z=(uint64_t)sar(sx_-sy,1);break;
        case S_UHSUB: z=(uint64_t)sar((int64_t)x-(int64_t)y,1);break;
        case S_CMGT: z=sx_>sy?m:0;break;
        case S_CMHI: z=x>y?m:0;break;
        case S_CMGE: z=sx_>=sy?m:0;break;
        case S_CMHS: z=x>=y?m:0;break;
        case S_CMTST: z=(x&y)?m:0;break;
        case S_CMEQ: z=x==y?m:0;break;
        case S_SSHL:{
            int amt=(int8_t)(y&0xffu);
            if(amt>=0)z=(unsigned)amt>=eb?0:(x<<amt)&m;
            else z=(uint64_t)sar(sx_,(unsigned)-amt)&m;
            break;}
        case S_USHL:{
            int amt=(int8_t)(y&0xffu);
            if(amt>=0)z=(unsigned)amt>=eb?0:(x<<amt)&m;
            else z=ushr(x,(unsigned)-amt);
            break;}
        case S_SMAX: z=(uint64_t)(sx_>sy?sx_:sy);break;
        case S_UMAX: z=x>y?x:y;break;
        case S_SMIN: z=(uint64_t)(sx_<sy?sx_:sy);break;
        case S_UMIN: z=x<y?x:y;break;
        case S_SABD: z=(uint64_t)(sx_>sy?sx_-sy:sy-sx_);break;
        case S_UABD: z=x>y?x-y:y-x;break;
        case S_SABA: z=d[i]+(uint64_t)(sx_>sy?sx_-sy:sy-sx_);break;
        case S_UABA: z=d[i]+(x>y?x-y:y-x);break;
        case S_ADD: z=x+y;break;
        case S_SUB: z=x-y;break;
        case S_MLA: z=d[i]+x*y;break;
        case S_MLS: z=d[i]-x*y;break;
        case S_MUL: z=x*y;break;
        case S_PMUL: z=pmul8(x,y);break;
        case S_SQADD: z=sq_add(sx_,sy,eb,&r->qc);break;
        case S_UQADD: z=uq_add(x,y,eb,&r->qc);break;
        case S_SQSUB: z=sq_sub(sx_,sy,eb,&r->qc);break;
        case S_UQSUB: z=uq_sub(x,y,&r->qc);break;
        case S_SQSHL: case S_SQRSHL:{
            int amt=(int8_t)(y&0xffu);
            if(amt>=0)z=sq_shl(sx_,(unsigned)amt,eb,&r->qc);
            else z=rshift_s(sx_,(unsigned)-amt,sub==S_SQRSHL);
            break;}
        case S_UQSHL: case S_UQRSHL:{
            int amt=(int8_t)(y&0xffu);
            if(amt>=0)z=uq_shl(x,(unsigned)amt,eb,&r->qc);
            else z=rshift_u(x,(unsigned)-amt,sub==S_UQRSHL);
            break;}
        case S_SRSHL:{
            int amt=(int8_t)(y&0xffu);
            z=amt>=0?((unsigned)amt>=64u?0:x<<amt):rshift_s(sx_,(unsigned)-amt,1);
            break;}
        case S_URSHL:{
            int amt=(int8_t)(y&0xffu);
            z=amt>=0?((unsigned)amt>=64u?0:x<<amt):rshift_u(x,(unsigned)-amt,1);
            break;}
        case S_SQDMULH: z=sq_dmulh(sx_,sy,eb,0,&r->qc);break;
        case S_SQRDMULH: z=sq_dmulh(sx_,sy,eb,1,&r->qc);break;
        default: return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
        }
        o[i]=z&m;
    }
    init_zero(r);pack(r->d,eb,n,o);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_misc(struct run *r)
{
    const struct inst *in=r->in;
    unsigned eb=in->eb,ds=in->scalar?eb/8u:in->q?16u:8u,n=in->scalar?1u:ds*8u/eb,sub=in->sub;
    uint64_t a[16],o[16],m=bmask(eb);
    if(sub==M_XTN||sub==M_SQXTN||sub==M_UQXTN||sub==M_SQXTUN){
        unsigned deb=eb,seb=eb*2u,sn=in->scalar?1u:128u/seb,dn=in->scalar?1u:64u/deb;uint64_t s[16];
        NEED(r,in->rn,0,in->scalar?seb/8u:16u);
        unpack(r->b->bytes[in->rn],seb,sn,s);
        for(unsigned i=0;i<dn;i++){
            int64_t sv=sxt(s[i],seb);
            switch(sub){
            case M_SQXTN: o[i]=clamp_s(sv,deb,&r->qc);break;
            case M_UQXTN: o[i]=clamp_u(s[i],deb,&r->qc);break;
            case M_SQXTUN: o[i]=clamp_su(sv,deb,&r->qc);break;
            default: o[i]=s[i]&bmask(deb);
            }
        }
        if(in->q&&!in->scalar){init_preserve(r,in->rd);pack(r->d+8,deb,dn,o);r->known=(uint16_t)((r->known&0x00ffu)|0xff00u);}
        else{init_zero(r);pack(r->d,deb,dn,o);}
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(sub==M_SHLL){
        unsigned off=in->q?8u:0u,wn=64u/eb;uint64_t w[16];
        NEED(r,in->rn,off,8);
        unpack(r->b->bytes[in->rn]+off,eb,wn,a);
        for(unsigned i=0;i<wn;i++)w[i]=(a[i]<<eb)&bmask(2u*eb);
        init_zero(r);pack(r->d,2u*eb,wn,w);
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    NEED(r,in->rn,0,ds);
    if(sub==M_SADALP||sub==M_UADALP||sub==M_SUQADD||sub==M_USQADD)NEED(r,in->rd,0,ds);
    if(sub==M_SADDLP||sub==M_UADDLP||sub==M_SADALP||sub==M_UADALP){
        unsigned wb=2u*eb,wn=n/2;uint64_t acc[16];
        unpack(r->b->bytes[in->rn],eb,n,a);unpack(r->b->bytes[in->rd],wb,wn,acc);
        for(unsigned i=0;i<wn;i++){
            uint64_t x,y;
            if(sub==M_SADDLP||sub==M_SADALP){x=(uint64_t)sxt(a[2*i],eb);y=(uint64_t)sxt(a[2*i+1],eb);}
            else{x=a[2*i];y=a[2*i+1];}
            o[i]=(x+y+((sub==M_SADALP||sub==M_UADALP)?acc[i]:0))&bmask(wb);
        }
        init_zero(r);pack(r->d,wb,wn,o);
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(sub==M_REV64||sub==M_REV32||sub==M_REV16){
        unsigned g=sub==M_REV64?8u:sub==M_REV32?4u:2u,per=g*8u/eb;
        unpack(r->b->bytes[in->rn],eb,n,a);
        for(unsigned i=0;i<n;i++)o[i]=a[(i/per)*per+(per-1u-(i%per))];
        init_zero(r);pack(r->d,eb,n,o);
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    unpack(r->b->bytes[in->rn],eb,n,a);
    if(sub==M_SQABS||sub==M_SQNEG||sub==M_SUQADD||sub==M_USQADD){
        uint64_t dv[16];
        unpack(r->b->bytes[in->rd],eb,n,dv);
        for(unsigned i=0;i<n;i++){
            uint64_t x=a[i],z;int64_t s=sxt(x,eb);
            if(sub==M_SUQADD)z=suq_add(sxt(dv[i],eb),x,eb,&r->qc);   /* SInt(Vd) + UInt(Vn) */
            else if(sub==M_USQADD)z=usq_add(dv[i],s,eb,&r->qc);        /* UInt(Vd) + SInt(Vn) */
            else if(s==smin_b(eb)){r->qc=1;z=(uint64_t)smax_b(eb);}
            else if(sub==M_SQNEG)z=(uint64_t)0-(uint64_t)s;
            else z=s<0?(uint64_t)0-(uint64_t)s:x;
            o[i]=z&m;
        }
        init_zero(r);pack(r->d,eb,n,o);
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    for(unsigned i=0;i<n;i++){
        uint64_t x=a[i],z;int64_t s=sxt(x,eb);
        switch(sub){
        case M_CLS:{uint64_t y=((uint64_t)s^(uint64_t)sar(s,1))&m;z=clz_bits(y,eb)-1u;break;}
        case M_CLZ: z=clz_bits(x,eb);break;
        case M_CNT: z=0;for(unsigned k=0;k<8;k++)z+=(x>>k)&1u;break;
        case M_NOT: z=~x;break;
        case M_RBIT:z=0;for(unsigned k=0;k<8;k++)if((x>>k)&1u)z|=UINT64_C(0x80)>>k;break;
        case M_CMGT0: z=s>0?m:0;break;
        case M_CMGE0: z=s>=0?m:0;break;
        case M_CMEQ0: z=x==0?m:0;break;
        case M_CMLE0: z=s<=0?m:0;break;
        case M_CMLT0: z=s<0?m:0;break;
        case M_ABS: z=s<0?(uint64_t)0-(uint64_t)s:x;break;
        case M_NEG: z=(uint64_t)0-x;break;
        default: return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
        }
        o[i]=z&m;
    }
    init_zero(r);pack(r->d,eb,n,o);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_across(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,ds=in->q?16u:8u,n=ds*8u/eb,sub=in->sub,rb=eb;
    uint64_t a[16],acc=0;
    NEED(r,in->rn,0,ds);
    unpack(r->b->bytes[in->rn],eb,n,a);
    for(unsigned i=0;i<n;i++){
        uint64_t x=a[i];int64_t s=sxt(x,eb);
        switch(sub){
        case A_ADDV: acc+=x;break;
        case A_UADDLV: acc+=x;rb=2u*eb;break;
        case A_SADDLV: acc+=(uint64_t)s;rb=2u*eb;break;
        case A_UMAXV: if(!i||x>acc)acc=x;break;
        case A_UMINV: if(!i||x<acc)acc=x;break;
        case A_SMAXV: if(!i||s>sxt(acc,eb))acc=x;break;
        default:      if(!i||s<sxt(acc,eb))acc=x;
        }
    }
    acc&=bmask(rb);
    init_zero(r);pack(r->d,rb,1,&acc);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_shift(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,sh=in->shift,sub=in->sub;
    if(sub==H_SHRN||sub==H_RSHRN||sub==H_SQSHRN||sub==H_UQSHRN||sub==H_SQRSHRN||sub==H_UQRSHRN||
       sub==H_SQSHRUN||sub==H_SQRSHRUN){
        unsigned seb=2u*eb,sn=in->scalar?1u:128u/seb,dn=sn;uint64_t s[16],o[16];
        int rnd=sub==H_RSHRN||sub==H_SQRSHRN||sub==H_UQRSHRN||sub==H_SQRSHRUN;
        NEED(r,in->rn,0,in->scalar?seb/8u:16u);
        unpack(r->b->bytes[in->rn],seb,sn,s);
        for(unsigned i=0;i<dn;i++){
            int64_t sv=sxt(s[i],seb);
            switch(sub){
            case H_SQSHRN: case H_SQRSHRN: o[i]=clamp_s((int64_t)rshift_s(sv,sh,rnd),eb,&r->qc);break;
            case H_SQSHRUN: case H_SQRSHRUN: o[i]=clamp_su((int64_t)rshift_s(sv,sh,rnd),eb,&r->qc);break;
            case H_UQSHRN: case H_UQRSHRN: o[i]=clamp_u(rshift_u(s[i],sh,rnd),eb,&r->qc);break;
            default: o[i]=rshift_u(s[i],sh,rnd)&bmask(eb);
            }
        }
        if(in->q&&!in->scalar){init_preserve(r,in->rd);pack(r->d+8,eb,dn,o);r->known=(uint16_t)((r->known&0x00ffu)|0xff00u);}
        else{init_zero(r);pack(r->d,eb,dn,o);}
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(sub==H_SSHLL||sub==H_USHLL){
        unsigned off=in->q?8u:0u,wn=64u/eb;uint64_t a[16],w[16];
        NEED(r,in->rn,off,8);
        unpack(r->b->bytes[in->rn]+off,eb,wn,a);
        for(unsigned i=0;i<wn;i++){
            uint64_t x=sub==H_SSHLL?(uint64_t)sxt(a[i],eb):a[i];
            w[i]=(x<<sh)&bmask(2u*eb);
        }
        init_zero(r);pack(r->d,2u*eb,wn,w);
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    {
        unsigned ds=in->scalar?eb/8u:in->q?16u:8u,n=in->scalar?1u:ds*8u/eb;
        uint64_t a[16],d[16],o[16],m=bmask(eb);
        int acc=sub==H_SSRA||sub==H_USRA||sub==H_SRSRA||sub==H_URSRA;
        NEED(r,in->rn,0,ds);
        if(acc||sub==H_SRI||sub==H_SLI)NEED(r,in->rd,0,ds);
        unpack(r->b->bytes[in->rn],eb,n,a);unpack(r->b->bytes[in->rd],eb,n,d);
        for(unsigned i=0;i<n;i++){
            uint64_t x=a[i],z;int64_t s=sxt(x,eb);
            switch(sub){
            case H_SSHR: case H_SSRA: z=(uint64_t)sar(s,sh);break;
            case H_USHR: case H_USRA: z=ushr(x,sh);break;
            case H_SRSHR: case H_SRSRA: z=(uint64_t)sar(s,sh)+(ushr(x,sh-1u)&1u);break;
            case H_URSHR: case H_URSRA: z=ushr(x,sh)+(ushr(x,sh-1u)&1u);break;
            case H_SHL: z=x<<sh;break;
            case H_SQSHL: z=sq_shl(s,sh,eb,&r->qc);break;
            case H_UQSHL: z=uq_shl(x,sh,eb,&r->qc);break;
            case H_SQSHLU: z=s<0?(r->qc=1,0):uq_shl((uint64_t)s,sh,eb,&r->qc);break;
            case H_SRI:{uint64_t mk=ushr(m,sh);z=(d[i]&~mk)|(ushr(x,sh)&mk);break;}
            case H_SLI:{uint64_t mk=(m<<sh)&m;z=(d[i]&~mk)|((x<<sh)&mk);break;}
            default: return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            }
            if(acc)z+=d[i];
            o[i]=z&m;
        }
        init_zero(r);pack(r->d,eb,n,o);
    }
    return OCNEXT_A64_SIMD_EXT_OK;
}
/* Shared widening kernel: lane i of the narrow operand pair (x,y) with the
 * old wide accumulator acc. */
static uint64_t widen_op(unsigned sub,unsigned usign,unsigned eb,uint64_t x,uint64_t y,uint64_t acc)
{
    uint64_t wm=bmask(2u*eb),a,b,ad;
    a=usign?x:(uint64_t)sxt(x,eb);b=usign?y:(uint64_t)sxt(y,eb);
    if(usign)ad=a>b?a-b:b-a;else ad=(int64_t)a>(int64_t)b?a-b:b-a;
    switch(sub){
    case D_ADDL: case D_ADDW: return (a+b)&wm;
    case D_SUBL: case D_SUBW: return (a-b)&wm;
    case D_ABAL: return (acc+ad)&wm;
    case D_ABDL: return ad&wm;
    case D_MLAL: return (acc+a*b)&wm;
    case D_MLSL: return (acc-a*b)&wm;
    default: return (a*b)&wm;
    }
}
static uint64_t pmul8w(uint64_t a,uint64_t b)
{
    uint64_t x=0;
    for(unsigned i=0;i<8;i++)if((b>>i)&1u)x^=a<<i;
    return x&0xffffu;
}
/* SignedSatQ(2*a*b, 2*eb) for the doubling multiplies (eb 16 or 32) */
static uint64_t sqdm_prod(int64_t a,int64_t b,unsigned eb,int *q)
{
    if(a==smin_b(eb)&&b==smin_b(eb)){*q=1;return (uint64_t)smax_b(2u*eb)&bmask(2u*eb);}
    return (uint64_t)(2*(a*b))&bmask(2u*eb);
}
/* SQDMULL / SQDMLAL / SQDMLSL lane: acc is the old wide lane */
static uint64_t sqdm_lane(unsigned kind,int64_t a,int64_t b,unsigned eb,uint64_t acc,int *q)
{
    unsigned wb=2u*eb;
    uint64_t prod=sqdm_prod(a,b,eb,q);
    if(kind==D_SQDMULL)return prod;
    if(kind==D_SQDMLAL)return sq_add(sxt(acc,wb),sxt(prod,wb),wb,q)&bmask(wb);
    return sq_sub(sxt(acc,wb),sxt(prod,wb),wb,q)&bmask(wb);
}
static res_t run_hn(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,seb=2u*eb,sn=128u/seb,sub=in->sub;
    uint64_t a[16],b[16],o[16],rc=(sub==D_RADDHN||sub==D_RSUBHN)?UINT64_C(1)<<(eb-1u):0;
    NEED(r,in->rn,0,16);NEED(r,in->rm,0,16);
    unpack(r->b->bytes[in->rn],seb,sn,a);unpack(r->b->bytes[in->rm],seb,sn,b);
    for(unsigned i=0;i<sn;i++){
        uint64_t sum=((sub==D_ADDHN||sub==D_RADDHN)?a[i]+b[i]:a[i]-b[i])+rc;
        o[i]=(sum&bmask(seb))>>eb;
    }
    if(in->q){init_preserve(r,in->rd);pack(r->d+8,eb,sn,o);r->known=(uint16_t)((r->known&0x00ffu)|0xff00u);}
    else{init_zero(r);pack(r->d,eb,sn,o);}
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_diff(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,wb=2u*eb,wn=in->scalar?1u:64u/eb,off=in->q?8u:0u,sub=in->sub;
    unsigned sb=in->scalar?eb/8u:8u;
    uint64_t a[16],b[16],acc[16],o[16];
    int wide=sub==D_ADDW||sub==D_SUBW;
    if(sub==D_ADDHN||sub==D_RADDHN||sub==D_SUBHN||sub==D_RSUBHN)return run_hn(r);
    NEED(r,in->rm,off,sb);
    if(wide){NEED(r,in->rn,0,16);unpack(r->b->bytes[in->rn],wb,wn,a);}
    else{NEED(r,in->rn,off,sb);unpack(r->b->bytes[in->rn]+off,eb,wn,a);}
    unpack(r->b->bytes[in->rm]+off,eb,wn,b);
    if(sub==D_ABAL||sub==D_MLAL||sub==D_MLSL||sub==D_SQDMLAL||sub==D_SQDMLSL){
        NEED(r,in->rd,0,in->scalar?wb/8u:16u);unpack(r->b->bytes[in->rd],wb,wn,acc);
    }else for(unsigned i=0;i<wn;i++)acc[i]=0;
    for(unsigned i=0;i<wn;i++){
        if(wide){
            uint64_t bb=in->u?b[i]:(uint64_t)sxt(b[i],eb);
            o[i]=(sub==D_ADDW?a[i]+bb:a[i]-bb)&bmask(wb);
        }else if(sub==D_PMULL)o[i]=pmul8w(a[i],b[i]);
        else if(sub==D_SQDMLAL||sub==D_SQDMLSL||sub==D_SQDMULL)
            o[i]=sqdm_lane(sub,sxt(a[i],eb),sxt(b[i],eb),eb,acc[i],&r->qc);
        else o[i]=widen_op(sub,in->u,eb,a[i],b[i],acc[i]);
    }
    init_zero(r);pack(r->d,wb,wn,o);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_elem(struct run *r)
{
    const struct inst *in=r->in;unsigned eb=in->eb,sub=in->sub,ib=eb/8u;
    uint64_t y,a[16],o[16],acc[16];
    NEED(r,in->rm,in->idx*ib,ib);
    unpack(r->b->bytes[in->rm]+in->idx*ib,eb,1,&y);
    if(sub==E_MUL||sub==E_MLA||sub==E_MLS||sub==E_SQDMULH||sub==E_SQRDMULH){
        unsigned ds=in->scalar?ib:in->q?16u:8u,n=in->scalar?1u:ds*8u/eb;
        NEED(r,in->rn,0,ds);
        if(sub==E_MLA||sub==E_MLS)NEED(r,in->rd,0,ds);
        unpack(r->b->bytes[in->rn],eb,n,a);unpack(r->b->bytes[in->rd],eb,n,acc);
        for(unsigned i=0;i<n;i++){
            uint64_t p=(a[i]*y)&bmask(eb);
            if(sub==E_SQDMULH||sub==E_SQRDMULH)
                o[i]=sq_dmulh(sxt(a[i],eb),sxt(y,eb),eb,sub==E_SQRDMULH,&r->qc);
            else o[i]=(sub==E_MUL?p:sub==E_MLA?acc[i]+p:acc[i]-p)&bmask(eb);
        }
        init_zero(r);pack(r->d,eb,n,o);
    }else{
        unsigned wb=2u*eb,wn=in->scalar?1u:64u/eb,off=in->q?8u:0u;
        unsigned dsub=sub==E_MULL?D_MULL:sub==E_MLAL?D_MLAL:sub==E_MLSL?D_MLSL:
                      sub==E_SQDMULL?D_SQDMULL:sub==E_SQDMLAL?D_SQDMLAL:D_SQDMLSL;
        int accum=sub==E_MLAL||sub==E_MLSL||sub==E_SQDMLAL||sub==E_SQDMLSL;
        NEED(r,in->rn,off,in->scalar?ib:8u);
        if(accum){NEED(r,in->rd,0,in->scalar?wb/8u:16u);unpack(r->b->bytes[in->rd],wb,wn,acc);}
        else for(unsigned i=0;i<wn;i++)acc[i]=0;
        unpack(r->b->bytes[in->rn]+off,eb,wn,a);
        for(unsigned i=0;i<wn;i++){
            if(dsub==D_SQDMULL||dsub==D_SQDMLAL||dsub==D_SQDMLSL)
                o[i]=sqdm_lane(dsub,sxt(a[i],eb),sxt(y,eb),eb,acc[i],&r->qc);
            else o[i]=widen_op(dsub,in->u,eb,a[i],y,acc[i]);
        }
        init_zero(r);pack(r->d,wb,wn,o);
    }
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_pair(struct run *r)
{
    uint64_t a[2],s;
    NEED(r,r->in->rn,0,16);
    unpack(r->b->bytes[r->in->rn],64,2,a);
    s=a[0]+a[1];
    init_zero(r);pack(r->d,64,1,&s);
    return OCNEXT_A64_SIMD_EXT_OK;
}
/* ---- scalar floating point (a64_fp_soft.c) ---- */
struct fpenv { struct ocnext_fp_ctx ctx; uint32_t nzcv; int nzcv_write; };
static int fp_cond_holds(uint32_t nzcv,unsigned cond)
{
    unsigned n=(nzcv>>31)&1u,z=(nzcv>>30)&1u,c=(nzcv>>29)&1u,v=(nzcv>>28)&1u,res=0;
    switch(cond>>1){
    case 0: res=z;break;
    case 1: res=c;break;
    case 2: res=n;break;
    case 3: res=v;break;
    case 4: res=c&&!z;break;
    case 5: res=n==v;break;
    case 6: res=(n==v)&&!z;break;
    default: res=1;
    }
    return (cond&1u)&&cond!=15u?!res:res;
}
static int fpcr_supported(const struct ocnext_a64_simd_ext_request *rq,struct fpenv *e)
{
    /* RMode (23:22) and FZ (24) must be zero; DN (25) is honoured. */
    if(!rq->fpcr_known||(rq->fpcr&UINT64_C(0x01c00000)))return 0;
    e->ctx.flags=0;e->ctx.dn=(unsigned)((rq->fpcr>>25)&1u);e->nzcv_write=0;e->nzcv=rq->nzcv;
    return 1;
}
static enum ocnext_fp_round rmode_of(unsigned rmode)
{
    return rmode==0?OCNEXT_FP_RN:rmode==1?OCNEXT_FP_RP:rmode==2?OCNEXT_FP_RM:OCNEXT_FP_RZ;
}
static res_t run_fpdp2(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u;uint64_t a,b,v=0;struct fpenv e;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    NEED(r,in->rn,0,bytes);NEED(r,in->rm,0,bytes);
    unpack(r->b->bytes[in->rn],bits,1,&a);unpack(r->b->bytes[in->rm],bits,1,&b);
    switch(in->sub){
    case 0: v=ocnext_fp_mul(bits,a,b,&e.ctx);break;
    case 1: v=ocnext_fp_div(bits,a,b,&e.ctx);break;
    case 2: v=ocnext_fp_add(bits,a,b,&e.ctx);break;
    case 3: v=ocnext_fp_sub(bits,a,b,&e.ctx);break;
    case 4: v=ocnext_fp_max(bits,a,b,0,&e.ctx);break;
    case 5: v=ocnext_fp_min(bits,a,b,0,&e.ctx);break;
    case 6: v=ocnext_fp_max(bits,a,b,1,&e.ctx);break;
    case 7: v=ocnext_fp_min(bits,a,b,1,&e.ctx);break;
    default: /* FNMUL */
        v=ocnext_fp_mul(bits,a,b,&e.ctx);
        v^=UINT64_C(1)<<(bits-1u);
    }
    init_zero(r);pack(r->d,bits,1,&v);fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpdp1(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u,sub=in->sub;uint64_t a,v=0;struct fpenv e;
    unsigned out_bits=bits;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    NEED(r,in->rn,0,bytes);
    unpack(r->b->bytes[in->rn],bits,1,&a);
    switch(sub){
    case 100: v=ocnext_fp_sqrt(bits,a,&e.ctx);break;
    case 101: v=ocnext_fp_convert(64,32,a,&e.ctx);out_bits=32;break;
    case 102: v=ocnext_fp_convert(32,64,a,&e.ctx);out_bits=64;break;
    case 8: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RN,0,&e.ctx);break;   /* FRINTN */
    case 9: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RP,0,&e.ctx);break;   /* FRINTP */
    case 10: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RM,0,&e.ctx);break;  /* FRINTM */
    case 11: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RZ,0,&e.ctx);break;  /* FRINTZ */
    case 12: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RA,0,&e.ctx);break;  /* FRINTA */
    case 14: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RN,1,&e.ctx);break;  /* FRINTX */
    default: v=ocnext_fp_round_int(bits,a,OCNEXT_FP_RN,0,&e.ctx);        /* FRINTI (RMode==RN) */
    }
    init_zero(r);pack(r->d,out_bits,1,&v);fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpfma(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u;uint64_t n,m,a,v,sbit=UINT64_C(1)<<(bits-1u);struct fpenv e;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    NEED(r,in->rn,0,bytes);NEED(r,in->rm,0,bytes);NEED(r,in->idx,0,bytes);
    unpack(r->b->bytes[in->rn],bits,1,&n);unpack(r->b->bytes[in->rm],bits,1,&m);unpack(r->b->bytes[in->idx],bits,1,&a);
    /* sub = o1:o0. FMADD 0, FMSUB 1, FNMADD 2, FNMSUB 3. Negate Fa when o1,
     * negate Fn when o1 != o0 (the negation is a plain sign-bit flip, NaNs included). */
    if(((in->sub>>1)^in->sub)&1u)n^=sbit;
    if(in->sub&2u)a^=sbit;
    v=ocnext_fp_fma(bits,a,n,m,&e.ctx);
    init_zero(r);pack(r->d,bits,1,&v);fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpcmp(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u,o2=in->sub;uint64_t a,b=0;struct fpenv e;unsigned nz;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    NEED(r,in->rn,0,bytes);
    if(!(o2&1u))NEED(r,in->rm,0,bytes);
    unpack(r->b->bytes[in->rn],bits,1,&a);
    if(!(o2&1u))unpack(r->b->bytes[in->rm],bits,1,&b);
    nz=ocnext_fp_compare(bits,a,b,(o2&2u)!=0,&e.ctx);
    fx->nzcv=(rq->nzcv&UINT32_C(0x0fffffff))|(nz<<28);fx->nzcv_write=1;fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpccmp(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u;uint64_t a,b;struct fpenv e;unsigned nz;
    unsigned cond=(in->op>>12)&15u;
    fx->nzcv_write=1;
    if(!fp_cond_holds(rq->nzcv,cond)){
        fx->nzcv=(rq->nzcv&UINT32_C(0x0fffffff))|((in->op&15u)<<28);
        return OCNEXT_A64_SIMD_EXT_OK; /* no operand is read when the condition fails */
    }
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    NEED(r,in->rn,0,bytes);NEED(r,in->rm,0,bytes);
    unpack(r->b->bytes[in->rn],bits,1,&a);unpack(r->b->bytes[in->rm],bits,1,&b);
    nz=ocnext_fp_compare(bits,a,b,in->sub!=0,&e.ctx);
    fx->nzcv=(rq->nzcv&UINT32_C(0x0fffffff))|(nz<<28);fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpcsel(struct run *r,const struct ocnext_a64_simd_ext_request *rq)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u,cond=(in->op>>12)&15u;uint64_t v;
    unsigned src=fp_cond_holds(rq->nzcv,cond)?in->rn:in->rm;
    NEED(r,src,0,bytes);
    unpack(r->b->bytes[src],bits,1,&v);
    init_zero(r);pack(r->d,bits,1,&v);
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpint(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned fbits_t=in->eb,bytes=fbits_t/8u,sf=in->op>>31,width=sf?64u:32u;
    unsigned rmode=(in->op>>19)&3u,opc=in->sub,fixed=in->idx2,fbits=fixed?in->idx:0u;
    struct fpenv e;uint64_t v;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    if(opc==2u||opc==3u){ /* SCVTF / UCVTF: GPR -> FP */
        uint64_t x=rq->gpr_value,mag;int neg=0;
        if(width==32)x&=bmask(32);
        if(opc==2u){
            int64_t sv=sxt(x,width);
            neg=sv<0;mag=neg?(uint64_t)0-(uint64_t)sv:(uint64_t)sv;
        }else mag=x;
        v=ocnext_fp_from_int(fbits_t,mag,neg,fbits,&e.ctx);
        init_zero(r);pack(r->d,fbits_t,1,&v);fx->fp_flags=(uint8_t)e.ctx.flags;
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    {   /* FCVT*: FP -> GPR */
        enum ocnext_fp_round rm=OCNEXT_FP_RN;uint64_t a;
        int is_signed=(opc==0u||opc==4u);
        if(opc<=1u)rm=fixed?OCNEXT_FP_RZ:rmode_of(rmode);else rm=OCNEXT_FP_RA;
        NEED(r,in->rn,0,bytes);
        unpack(r->b->bytes[in->rn],fbits_t,1,&a);
        v=ocnext_fp_to_int(fbits_t,a,rm,fbits,is_signed,width,&e.ctx);
        fx->gpr_write=1;fx->gpr_rd=(uint8_t)in->rd;fx->gpr_value=v;fx->fp_flags=(uint8_t)e.ctx.flags;
        return OCNEXT_A64_SIMD_EXT_OK;
    }
}
/* ---- vector floating point lane engine ---- */
static uint64_t fp_cmp_mask(unsigned bits,unsigned sub,uint64_t a,uint64_t b,struct ocnext_fp_ctx *c)
{
    /* FPCompareEQ/GE/GT semantics: NaN => false; EQ signals only on SNaN, GE/GT on any NaN. */
    uint64_t fm=bits==32?UINT64_C(0xffffffff):~UINT64_C(0);
    uint64_t exp_mask=bits==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
    uint64_t frac_mask=bits==32?UINT64_C(0x7fffff):UINT64_C(0xfffffffffffff);
    uint64_t qbit=bits==32?UINT64_C(0x400000):UINT64_C(0x8000000000000);
    int na=(a&exp_mask)==exp_mask&&(a&frac_mask),nb=(b&exp_mask)==exp_mask&&(b&frac_mask);
    int sna=na&&!(a&qbit),snb=nb&&!(b&qbit);
    unsigned nz;
    if(na||nb){
        if(sub==V3_FCMEQ){if(sna||snb)c->flags|=OCNEXT_FP_IOC;}
        else c->flags|=OCNEXT_FP_IOC;
        return 0;
    }
    nz=ocnext_fp_compare(bits,a,b,0,c);
    if(sub==V3_FCMEQ)return (nz&4u)?fm:0;
    if(sub==V3_FCMGE)return (nz&2u)?fm:0;  /* C set: a >= b (equal gives Z|C) */
    return (nz==2u)?fm:0;                  /* greater than: only the C-without-Z result */
}
static res_t run_fpv(struct run *r,const struct ocnext_a64_simd_ext_request *rq,struct ocnext_a64_simd_ext_effect *fx)
{
    const struct inst *in=r->in;unsigned bits=in->eb,bytes=bits/8u,sub=in->sub,grp=in->idx2;
    unsigned ds=in->scalar?bytes:in->q?16u:8u,n=in->scalar?1u:ds*8u/bits;
    uint64_t a[4],b[4],d[4],o[4],fm=bits==32?UINT64_C(0xffffffff):~UINT64_C(0),sbit=UINT64_C(1)<<(bits-1u);
    struct fpenv e;
    if(!fpcr_supported(rq,&e))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    switch(grp){
    case G3:{
        int pair=sub==V3_FADDP||sub==V3_FMAXP||sub==V3_FMINP||sub==V3_FMAXNMP||sub==V3_FMINNMP;
        NEED(r,in->rn,0,ds);NEED(r,in->rm,0,ds);
        if(sub==V3_FMLA||sub==V3_FMLS)NEED(r,in->rd,0,ds);
        unpack(r->b->bytes[in->rn],bits,n,a);unpack(r->b->bytes[in->rm],bits,n,b);unpack(r->b->bytes[in->rd],bits,n,d);
        if(pair){
            uint64_t cat[8];
            for(unsigned i=0;i<n;i++){cat[i]=a[i];cat[n+i]=b[i];}
            for(unsigned i=0;i<n;i++){
                uint64_t x=cat[2*i],y=cat[2*i+1];
                switch(sub){
                case V3_FADDP: o[i]=ocnext_fp_add(bits,x,y,&e.ctx);break;
                case V3_FMAXP: o[i]=ocnext_fp_max(bits,x,y,0,&e.ctx);break;
                case V3_FMINP: o[i]=ocnext_fp_min(bits,x,y,0,&e.ctx);break;
                case V3_FMAXNMP: o[i]=ocnext_fp_max(bits,x,y,1,&e.ctx);break;
                default: o[i]=ocnext_fp_min(bits,x,y,1,&e.ctx);
                }
            }
        }else for(unsigned i=0;i<n;i++){
            uint64_t x=a[i],y=b[i],z;
            switch(sub){
            case V3_FMAXNM: z=ocnext_fp_max(bits,x,y,1,&e.ctx);break;
            case V3_FMINNM: z=ocnext_fp_min(bits,x,y,1,&e.ctx);break;
            case V3_FMLA: z=ocnext_fp_fma(bits,d[i],x,y,&e.ctx);break;
            case V3_FMLS: z=ocnext_fp_fma(bits,d[i],x^sbit,y,&e.ctx);break;
            case V3_FADD: z=ocnext_fp_add(bits,x,y,&e.ctx);break;
            case V3_FSUB: z=ocnext_fp_sub(bits,x,y,&e.ctx);break;
            case V3_FABD: z=ocnext_fp_sub(bits,x,y,&e.ctx)&~sbit;break;
            case V3_FMULX: z=ocnext_fp_mulx(bits,x,y,&e.ctx);break;
            case V3_FMUL: z=ocnext_fp_mul(bits,x,y,&e.ctx);break;
            case V3_FCMEQ: case V3_FCMGE: case V3_FCMGT: z=fp_cmp_mask(bits,sub,x,y,&e.ctx);break;
            case V3_FACGE: z=fp_cmp_mask(bits,V3_FCMGE,x&~sbit,y&~sbit,&e.ctx);break;
            case V3_FACGT: z=fp_cmp_mask(bits,V3_FCMGT,x&~sbit,y&~sbit,&e.ctx);break;
            case V3_FMAX: z=ocnext_fp_max(bits,x,y,0,&e.ctx);break;
            case V3_FMIN: z=ocnext_fp_min(bits,x,y,0,&e.ctx);break;
            case V3_FRECPS: z=ocnext_fp_recps(bits,x,y,&e.ctx);break;
            case V3_FRSQRTS: z=ocnext_fp_rsqrts(bits,x,y,&e.ctx);break;
            default: z=ocnext_fp_div(bits,x,y,&e.ctx);
            }
            o[i]=z&fm;
        }
        init_zero(r);pack(r->d,bits,n,o);
        break;}
    case G2:{
        if(sub==V2_FCVTN){ /* 2 x f64 -> 2 x f32 in the low (Q=0) or high (Q=1) half */
            NEED(r,in->rn,0,16);
            unpack(r->b->bytes[in->rn],64,2,a);
            for(unsigned i=0;i<2;i++)o[i]=ocnext_fp_convert(64,32,a[i],&e.ctx);
            if(in->q){init_preserve(r,in->rd);pack(r->d+8,32,2,o);r->known=(uint16_t)((r->known&0x00ffu)|0xff00u);}
            else{init_zero(r);pack(r->d,32,2,o);}
            break;
        }
        if(sub==V2_FCVTL){ /* 2 x f32 (low half, or high half with Q=1) -> 2 x f64 */
            unsigned off=in->q?8u:0u;
            NEED(r,in->rn,off,8);
            unpack(r->b->bytes[in->rn]+off,32,2,a);
            for(unsigned i=0;i<2;i++)o[i]=ocnext_fp_convert(32,64,a[i],&e.ctx);
            init_zero(r);pack(r->d,64,2,o);
            break;
        }
        NEED(r,in->rn,0,ds);
        unpack(r->b->bytes[in->rn],bits,n,a);
        for(unsigned i=0;i<n;i++){
            uint64_t x=a[i],z=0;
            switch(sub){
            case V2_FABS: z=x&~sbit;break;
            case V2_FNEG: z=x^sbit;break;
            case V2_FSQRT: z=ocnext_fp_sqrt(bits,x,&e.ctx);break;
            case V2_FRINTN: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RN,0,&e.ctx);break;
            case V2_FRINTP: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RP,0,&e.ctx);break;
            case V2_FRINTM: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RM,0,&e.ctx);break;
            case V2_FRINTZ: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RZ,0,&e.ctx);break;
            case V2_FRINTA: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RA,0,&e.ctx);break;
            case V2_FRINTX: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RN,1,&e.ctx);break;
            case V2_FRINTI: z=ocnext_fp_round_int(bits,x,OCNEXT_FP_RN,0,&e.ctx);break;
            case V2_FCVTNS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RN,0,1,bits,&e.ctx);break;
            case V2_FCVTPS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RP,0,1,bits,&e.ctx);break;
            case V2_FCVTMS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RM,0,1,bits,&e.ctx);break;
            case V2_FCVTZS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RZ,0,1,bits,&e.ctx);break;
            case V2_FCVTAS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RA,0,1,bits,&e.ctx);break;
            case V2_FCVTNU: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RN,0,0,bits,&e.ctx);break;
            case V2_FCVTPU: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RP,0,0,bits,&e.ctx);break;
            case V2_FCVTMU: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RM,0,0,bits,&e.ctx);break;
            case V2_FCVTZU: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RZ,0,0,bits,&e.ctx);break;
            case V2_FCVTAU: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RA,0,0,bits,&e.ctx);break;
            case V2_SCVTF:{int64_t sv=sxt(x,bits);int neg=sv<0;z=ocnext_fp_from_int(bits,neg?(uint64_t)0-(uint64_t)sv:(uint64_t)sv,neg,0,&e.ctx);break;}
            case V2_UCVTF: z=ocnext_fp_from_int(bits,x,0,0,&e.ctx);break;
            case V2_FCMGT0: z=fp_cmp_mask(bits,V3_FCMGT,x,0,&e.ctx);break;
            case V2_FCMGE0: z=fp_cmp_mask(bits,V3_FCMGE,x,0,&e.ctx);break;
            case V2_FCMEQ0: z=fp_cmp_mask(bits,V3_FCMEQ,x,0,&e.ctx);break;
            case V2_FCMLE0: z=fp_cmp_mask(bits,V3_FCMGE,0,x,&e.ctx);break;
            case V2_FCMLT0: z=fp_cmp_mask(bits,V3_FCMGT,0,x,&e.ctx);break;
            default: return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            }
            o[i]=z&fm;
        }
        init_zero(r);pack(r->d,bits,n,o);
        break;}
    case GE:{
        uint64_t y;unsigned ib=bytes;
        NEED(r,in->rm,in->idx*ib,ib);
        NEED(r,in->rn,0,ds);
        if(sub==VE_FMLA||sub==VE_FMLS)NEED(r,in->rd,0,ds);
        unpack(r->b->bytes[in->rm]+in->idx*ib,bits,1,&y);
        unpack(r->b->bytes[in->rn],bits,n,a);unpack(r->b->bytes[in->rd],bits,n,d);
        for(unsigned i=0;i<n;i++){
            uint64_t z;
            switch(sub){
            case VE_FMLA: z=ocnext_fp_fma(bits,d[i],a[i],y,&e.ctx);break;
            case VE_FMLS: z=ocnext_fp_fma(bits,d[i],a[i]^sbit,y,&e.ctx);break;
            case VE_FMUL: z=ocnext_fp_mul(bits,a[i],y,&e.ctx);break;
            default: z=ocnext_fp_mulx(bits,a[i],y,&e.ctx);
            }
            o[i]=z&fm;
        }
        init_zero(r);pack(r->d,bits,n,o);
        break;}
    case GP:{ /* scalar pairwise: reduce the two lanes of Vn */
        uint64_t z;
        NEED(r,in->rn,0,2u*bytes);
        unpack(r->b->bytes[in->rn],bits,2,a);
        switch(sub){
        case VP_FADDP: z=ocnext_fp_add(bits,a[0],a[1],&e.ctx);break;
        case VP_FMAXNMP: z=ocnext_fp_max(bits,a[0],a[1],1,&e.ctx);break;
        case VP_FMINNMP: z=ocnext_fp_min(bits,a[0],a[1],1,&e.ctx);break;
        case VP_FMAXP: z=ocnext_fp_max(bits,a[0],a[1],0,&e.ctx);break;
        default: z=ocnext_fp_min(bits,a[0],a[1],0,&e.ctx);
        }
        z&=fm;
        init_zero(r);pack(r->d,bits,1,&z);
        break;}
    case GA:{ /* FMAXV family over 4 x f32: tree reduction as in the Arm pseudocode */
        uint64_t lo,hi,z;
        int nm=sub==VA_FMAXNMV||sub==VA_FMINNMV,mx=sub==VA_FMAXNMV||sub==VA_FMAXV;
        NEED(r,in->rn,0,16);
        unpack(r->b->bytes[in->rn],32,4,a);
        lo=mx?ocnext_fp_max(32,a[0],a[1],nm,&e.ctx):ocnext_fp_min(32,a[0],a[1],nm,&e.ctx);
        hi=mx?ocnext_fp_max(32,a[2],a[3],nm,&e.ctx):ocnext_fp_min(32,a[2],a[3],nm,&e.ctx);
        z=mx?ocnext_fp_max(32,lo,hi,nm,&e.ctx):ocnext_fp_min(32,lo,hi,nm,&e.ctx);
        init_zero(r);pack(r->d,32,1,&z);
        break;}
    default:{ /* GS: fixed-point conversions with `shift` fractional bits */
        unsigned fb=in->shift;
        NEED(r,in->rn,0,ds);
        unpack(r->b->bytes[in->rn],bits,n,a);
        for(unsigned i=0;i<n;i++){
            uint64_t x=a[i],z;
            switch(sub){
            case V2_SCVTF:{int64_t sv=sxt(x,bits);int neg=sv<0;z=ocnext_fp_from_int(bits,neg?(uint64_t)0-(uint64_t)sv:(uint64_t)sv,neg,fb,&e.ctx);break;}
            case V2_UCVTF: z=ocnext_fp_from_int(bits,x,0,fb,&e.ctx);break;
            case V2_FCVTZS: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RZ,fb,1,bits,&e.ctx);break;
            default: z=ocnext_fp_to_int(bits,x,OCNEXT_FP_RZ,fb,0,bits,&e.ctx);
            }
            o[i]=z&fm;
        }
        init_zero(r);pack(r->d,bits,n,o);
        break;}
    }
    fx->fp_flags=(uint8_t)e.ctx.flags;
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_fpreg(struct run *r)
{
    const struct inst *in=r->in;unsigned bytes=in->eb/8u;uint64_t v;
    NEED(r,in->rn,0,bytes);
    unpack(r->b->bytes[in->rn],in->eb,1,&v);
    if(in->sub==F_ABS)v&=~(UINT64_C(1)<<(in->eb-1u));
    else if(in->sub==F_NEG)v^=UINT64_C(1)<<(in->eb-1u);
    init_zero(r);pack(r->d,in->eb,1,&v);
    return OCNEXT_A64_SIMD_EXT_OK;
}
/* VFPExpandImm (DDI0487 J1.2): sign:NOT(b6):Replicate(b6,E-3):imm8<5:4>:imm8<3:0>:Zeros */
static uint64_t vfp_expand(unsigned imm,unsigned bits)
{
    unsigned e=bits==64?11u:8u,f=bits-1u-e;
    uint64_t sign=(imm>>7)&1u,b6=(imm>>6)&1u,exp,frac;
    exp=((b6^1u)<<(e-1u));
    for(unsigned i=0;i<e-3u;i++)exp|=b6<<(e-2u-i);
    exp|=(uint64_t)((imm>>4)&3u);
    frac=(uint64_t)(imm&15u)<<(f-4u);
    return (sign<<(bits-1u))|(exp<<f)|frac;
}
static res_t run_fpimm(struct run *r)
{
    uint64_t v=vfp_expand(r->in->idx,r->in->eb);
    init_zero(r);pack(r->d,r->in->eb,1,&v);
    return OCNEXT_A64_SIMD_EXT_OK;
}
/* AdvSIMDExpandImm for ORR/BIC/MVNI and vector FMOV (DDI0487 J1.2). */
static res_t run_modimm(struct run *r)
{
    const struct inst *in=r->in;uint32_t op=in->op;
    unsigned cmode=(op>>12)&15u,imm8=((op>>16)&7u)<<5|((op>>5)&31u),ds=in->q?16u:8u;
    uint64_t imm=0;
    uint8_t old[16];
    if(in->sub==I_FMOV){
        imm=in->u?vfp_expand(imm8,64):(vfp_expand(imm8,32)|vfp_expand(imm8,32)<<32);
    }else if((cmode&8u)==0){
        uint64_t lane=(uint64_t)imm8<<(8u*((cmode>>1)&3u));
        imm=lane|lane<<32;
    }else if((cmode&12u)==8u){
        uint64_t lane=(uint64_t)imm8<<(8u*((cmode>>1)&1u));
        imm=lane|lane<<16|lane<<32|lane<<48;
    }else{ /* 110x: shifting ones (MVNI only) */
        uint64_t lane=(cmode&1u)?((uint64_t)imm8<<16|0xffffu):((uint64_t)imm8<<8|0xffu);
        imm=lane|lane<<32;
    }
    if(in->sub==I_MVNI)imm=~imm;
    if(in->sub==I_ORR||in->sub==I_BIC)NEED(r,in->rd,0,ds);
    for(unsigned i=0;i<16;i++)old[i]=r->b->bytes[in->rd][i];
    init_zero(r);
    for(unsigned i=0;i<ds;i++){
        uint8_t ib=(uint8_t)(imm>>(8u*(i&7u)));
        r->d[i]=in->sub==I_ORR?(uint8_t)(old[i]|ib):in->sub==I_BIC?(uint8_t)(old[i]&~ib):ib;
    }
    return OCNEXT_A64_SIMD_EXT_OK;
}
static res_t run_tbl(struct run *r)
{
    const struct inst *in=r->in;unsigned ds=in->q?16u:8u,regs=in->shift,tbx=in->sub;
    uint8_t d[16];
    NEED(r,in->rm,0,ds);
    for(unsigned i=0;i<16;i++)d[i]=0;
    for(unsigned i=0;i<ds;i++){
        unsigned idx=r->b->bytes[in->rm][i];
        if(idx<16u*regs){
            unsigned reg=(in->rn+idx/16u)&31u;
            if(!(r->b->known_bytes[reg]&(1u<<(idx%16u))))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            d[i]=r->b->bytes[reg][idx%16u];
        }else if(tbx){
            if(!(r->b->known_bytes[in->rd]&(1u<<i)))return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            d[i]=r->b->bytes[in->rd][i];
        }
    }
    init_zero(r);
    for(unsigned i=0;i<ds;i++)r->d[i]=d[i];
    return OCNEXT_A64_SIMD_EXT_OK;
}

enum ocnext_a64_simd_ext_result ocnext_a64_simd_ext_prepare(
    const struct ocnext_a64_vector_registers *b,const struct ocnext_a64_simd_ext_request *rq,
    struct ocnext_a64_simd_ext_effect *out)
{
    struct inst in;struct run r;struct ocnext_a64_simd_ext_effect fx;res_t s=OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    unsigned kind;
    if(!span(b,sizeof(*b))||!span(rq,sizeof(*rq))||!span(out,sizeof(*out))||
       overlap(b,sizeof(*b),rq,sizeof(*rq))||overlap(b,sizeof(*b),out,sizeof(*out))||
       overlap(rq,sizeof(*rq),out,sizeof(*out)))return OCNEXT_A64_SIMD_EXT_ARGUMENT;
    if(!ocnext_a64_simd_integer_valid(b)||rq->reserved)return OCNEXT_A64_SIMD_EXT_ARGUMENT;
    kind=(unsigned)classify(rq->opcode,&in);
    if(!kind)return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
    in.kind=kind;
    r.b=b;r.in=&in;r.qc=0;init_zero(&r);
    for(unsigned i=0;i<sizeof(fx);i++)((uint8_t *)&fx)[i]=0;
    switch(kind){
    case K_COPY:s=run_copy(&r,rq,&fx);break;
    case K_EXT:s=run_ext(&r);break;
    case K_PERM:s=run_perm(&r);break;
    case K_SAME:s=run_same(&r);break;
    case K_DIFF:s=run_diff(&r);break;
    case K_MISC:s=run_misc(&r);break;
    case K_ACROSS:s=run_across(&r);break;
    case K_SHIFT:s=run_shift(&r);break;
    case K_ELEM:s=run_elem(&r);break;
    case K_PAIR:s=run_pair(&r);break;
    case K_FPREG:s=run_fpreg(&r);break;
    case K_FPIMM:s=run_fpimm(&r);break;
    case K_TBL:s=run_tbl(&r);break;
    case K_MODIMM:s=run_modimm(&r);break;
    case K_FPDP2:s=run_fpdp2(&r,rq,&fx);break;
    case K_FPDP1:s=run_fpdp1(&r,rq,&fx);break;
    case K_FPCMP:s=run_fpcmp(&r,rq,&fx);break;
    case K_FPCCMP:s=run_fpccmp(&r,rq,&fx);break;
    case K_FPCSEL:s=run_fpcsel(&r,rq);break;
    case K_FPINT:s=run_fpint(&r,rq,&fx);break;
    case K_FPFMA:s=run_fpfma(&r,rq,&fx);break;
    case K_FPV:s=run_fpv(&r,rq,&fx);break;
    }
    if(s!=OCNEXT_A64_SIMD_EXT_OK)return s;
    fx.opcode=rq->opcode;fx.qc=(uint8_t)(r.qc!=0);
    if(!(kind==K_COPY&&(in.sub==C_SMOV||in.sub==C_UMOV))&&kind!=K_FPCMP&&kind!=K_FPCCMP&&
       !(kind==K_FPINT&&fx.gpr_write)){
        for(unsigned i=0;i<16;i++)fx.bytes[i]=r.d[i];
        fx.known_bytes=r.known;fx.destination=(uint8_t)in.rd;fx.vector_write=1;
    }
    *out=fx;
    return OCNEXT_A64_SIMD_EXT_OK;
}

/* ---- structure / register loads and stores ---- */
unsigned ocnext_a64_simd_mem_decode(uint32_t op,struct ocnext_a64_simd_mem_plan *p)
{
    unsigned q=(op>>30)&1u,post=(op>>23)&1u,rm=(op>>16)&31u;
    for(unsigned i=0;i<sizeof(*p);i++)((uint8_t *)p)[i]=0;
    p->opcode=op;p->rt=(uint8_t)(op&31u);p->rn=(uint8_t)((op>>5)&31u);p->rm=(uint8_t)rm;
    p->load=(uint8_t)((op>>22)&1u);p->q=(uint8_t)q;
    if((op&UINT32_C(0xbf200000))==UINT32_C(0x0c000000)){ /* multiple structures */
        unsigned opc=(op>>12)&15u,size=(op>>10)&3u,selem,rpt;
        if(!post&&(op&UINT32_C(0x001f0000)))return 0;
        switch(opc){
        case 0: selem=4;rpt=1;break;
        case 2: selem=1;rpt=4;break;
        case 4: selem=3;rpt=1;break;
        case 6: selem=1;rpt=3;break;
        case 7: selem=1;rpt=1;break;
        case 8: selem=2;rpt=1;break;
        case 10: selem=1;rpt=2;break;
        default: return 0;
        }
        if(size==3&&!q&&selem!=1)return 0;
        p->form=OCNEXT_A64_SIMD_MEM_MULTI;p->selem=(uint8_t)selem;p->nregs=(uint8_t)(selem*rpt);
        p->esize=(uint8_t)(1u<<size);p->bytes=(uint16_t)(selem*rpt*(q?16u:8u));
        p->wb=(uint8_t)(post?(rm==31u?1u:2u):0u);
        return p->form;
    }
    if((op&UINT32_C(0xbf000000))==UINT32_C(0x0d000000)){ /* single structure / replicate */
        unsigned l=(op>>22)&1u,r=(op>>21)&1u,opc=(op>>13)&7u,s=(op>>12)&1u,size=(op>>10)&3u;
        unsigned selem=(((opc&1u)<<1)|r)+1u,scale=opc>>1;
        if(!post&&(op&UINT32_C(0x001f0000)))return 0;
        p->selem=(uint8_t)selem;p->nregs=(uint8_t)selem;p->form=OCNEXT_A64_SIMD_MEM_SINGLE;
        switch(scale){
        case 0: p->esize=1;p->lane=(uint8_t)(q<<3|s<<2|size);break;
        case 1: if(size&1u)return 0;p->esize=2;p->lane=(uint8_t)(q<<2|s<<1|(size>>1));break;
        case 2: if(size&2u)return 0;
                if(!(size&1u)){p->esize=4;p->lane=(uint8_t)(q<<1|s);}
                else{if(s)return 0;p->esize=8;p->lane=(uint8_t)q;}
                break;
        default: if(!l||s)return 0;p->form=OCNEXT_A64_SIMD_MEM_REPLICATE;p->esize=(uint8_t)(1u<<size);
        }
        p->bytes=(uint16_t)(selem*p->esize);
        p->wb=(uint8_t)(post?(rm==31u?1u:2u):0u);
        return p->form;
    }
    if((op&UINT32_C(0x3f000000))==UINT32_C(0x1c000000)){ /* LDR (literal), SIMD&FP */
        unsigned opc=(op>>30)&3u;
        if(opc==3)return 0;
        p->form=OCNEXT_A64_SIMD_MEM_LITERAL;p->load=1;p->esize=(uint8_t)(4u<<opc);p->bytes=p->esize;
        p->selem=p->nregs=1;
        p->literal=sxt((op>>5)&UINT32_C(0x7ffff),19)*4;
        return p->form;
    }
    if((op&UINT32_C(0x3f200c00))==UINT32_C(0x3c200800)){ /* LDR/STR register offset */
        unsigned size=(op>>30)&3u,opc=(op>>22)&3u,option=(op>>13)&7u,s=(op>>12)&1u,lg;
        if(option!=2u&&option!=3u&&option!=6u&&option!=7u)return 0;
        if(opc&2u){if(size)return 0;lg=4;}else lg=size;
        p->form=OCNEXT_A64_SIMD_MEM_REGOFF;p->load=(uint8_t)(opc&1u);p->esize=(uint8_t)(1u<<lg);
        p->bytes=p->esize;p->selem=p->nregs=1;p->option=(uint8_t)option;p->shift=(uint8_t)(s?lg:0u);
        return p->form;
    }
    return 0;
}
uint64_t ocnext_a64_simd_mem_offset(const struct ocnext_a64_simd_mem_plan *p,uint64_t xm)
{
    uint64_t v=xm;
    switch(p->option){
    case 2: v=xm&bmask(32);break;                  /* UXTW */
    case 6: v=(uint64_t)sxt(xm,32);break;          /* SXTW */
    default: break;                                /* LSL / SXTX use Xm */
    }
    return v<<p->shift;
}
enum ocnext_a64_simd_ext_result ocnext_a64_simd_mem_gather(
    const struct ocnext_a64_vector_registers *b,const struct ocnext_a64_simd_mem_plan *p,uint8_t *buf)
{
    unsigned es=p->esize;
    if(!span(b,sizeof(*b))||!ocnext_a64_simd_integer_valid(b))return OCNEXT_A64_SIMD_EXT_ARGUMENT;
    if(p->load)return OCNEXT_A64_SIMD_EXT_ARGUMENT;
    if(p->form==OCNEXT_A64_SIMD_MEM_MULTI){
        unsigned ds=p->q?16u:8u,elems=ds/es,sel=p->selem,rpt=p->nregs/sel;
        for(unsigned r=0;r<rpt;r++)for(unsigned e=0;e<elems;e++)for(unsigned s=0;s<sel;s++){
            unsigned reg=(p->rt+r+s)&31u,at=((r*elems+e)*sel+s)*es;
            uint16_t m=rangemask(e*es,es);
            if((b->known_bytes[reg]&m)!=m)return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            for(unsigned k=0;k<es;k++)buf[at+k]=b->bytes[reg][e*es+k];
        }
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(p->form==OCNEXT_A64_SIMD_MEM_SINGLE){
        for(unsigned s=0;s<p->selem;s++){
            unsigned reg=(p->rt+s)&31u;uint16_t m=rangemask(p->lane*es,es);
            if((b->known_bytes[reg]&m)!=m)return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
            for(unsigned k=0;k<es;k++)buf[s*es+k]=b->bytes[reg][p->lane*es+k];
        }
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(p->form==OCNEXT_A64_SIMD_MEM_REGOFF){
        uint16_t m=rangemask(0,es);
        if((b->known_bytes[p->rt]&m)!=m)return OCNEXT_A64_SIMD_EXT_UNSUPPORTED;
        for(unsigned k=0;k<es;k++)buf[k]=b->bytes[p->rt][k];
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    return OCNEXT_A64_SIMD_EXT_ARGUMENT;
}
enum ocnext_a64_simd_ext_result ocnext_a64_simd_mem_scatter(
    const struct ocnext_a64_vector_registers *b,const struct ocnext_a64_simd_mem_plan *p,
    const uint8_t *buf,struct ocnext_a64_simd_mem_dest out[4],unsigned *n)
{
    unsigned es=p->esize,sel=p->selem;
    if(!span(b,sizeof(*b))||!ocnext_a64_simd_integer_valid(b)||!p->load||p->nregs>4)return OCNEXT_A64_SIMD_EXT_ARGUMENT;
    for(unsigned i=0;i<4;i++){for(unsigned k=0;k<16;k++)out[i].bytes[k]=0;out[i].known_bytes=0xffffu;out[i].reg=0;out[i].reserved=0;}
    *n=p->nregs;
    if(p->form==OCNEXT_A64_SIMD_MEM_MULTI){
        unsigned ds=p->q?16u:8u,elems=ds/es,rpt=p->nregs/sel;
        for(unsigned r=0;r<rpt;r++)for(unsigned s=0;s<sel;s++)out[r+s].reg=(uint8_t)((p->rt+r+s)&31u);
        for(unsigned r=0;r<rpt;r++)for(unsigned e=0;e<elems;e++)for(unsigned s=0;s<sel;s++){
            unsigned at=((r*elems+e)*sel+s)*es;
            for(unsigned k=0;k<es;k++)out[r+s].bytes[e*es+k]=buf[at+k];
        }
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(p->form==OCNEXT_A64_SIMD_MEM_SINGLE){
        for(unsigned s=0;s<sel;s++){
            unsigned reg=(p->rt+s)&31u;
            out[s].reg=(uint8_t)reg;
            for(unsigned k=0;k<16;k++)out[s].bytes[k]=b->bytes[reg][k];
            out[s].known_bytes=(uint16_t)(b->known_bytes[reg]|rangemask(p->lane*es,es));
            for(unsigned k=0;k<es;k++)out[s].bytes[p->lane*es+k]=buf[s*es+k];
        }
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    if(p->form==OCNEXT_A64_SIMD_MEM_REPLICATE){
        unsigned ds=p->q?16u:8u;
        for(unsigned s=0;s<sel;s++){
            out[s].reg=(uint8_t)((p->rt+s)&31u);
            for(unsigned e=0;e<ds/es;e++)for(unsigned k=0;k<es;k++)out[s].bytes[e*es+k]=buf[s*es+k];
        }
        return OCNEXT_A64_SIMD_EXT_OK;
    }
    /* LITERAL / REGOFF load: one register, upper bytes known zero */
    out[0].reg=p->rt;
    for(unsigned k=0;k<es;k++)out[0].bytes[k]=buf[k];
    return OCNEXT_A64_SIMD_EXT_OK;
}
