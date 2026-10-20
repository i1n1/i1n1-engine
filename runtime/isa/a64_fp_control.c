#include "ocnext/a64_fp_control.h"
static int span(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return p && !(a&7u) && n<=UINTPTR_MAX-a;}
static int overlaps(const void *a,size_t n,const void *b,size_t m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m && y<x+n;}
static void copy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;for(size_t i=0;i<n;i++)x[i]=y[i];}
static void zero(void *d,size_t n){uint8_t *p=d;for(size_t i=0;i<n;i++)p[i]=0;}
int ocnext_a64_fp_control_valid(const struct ocnext_a64_fp_registers *b)
{
    if(!span(b,sizeof(*b)))return 0;
    return b->abi_version==OCNEXT_A64_FP_REGISTERS_ABI_VERSION && !(b->known_mask&~OCNEXT_A64_FP_KNOWN_ALL) &&
        !(b->cpacr_el1&~OCNEXT_A64_FP_CPACR_MASK) && !(b->fpcr&~OCNEXT_A64_FP_FPCR_MASK) && !(b->fpsr&~OCNEXT_A64_FP_FPSR_MASK) &&
        ((b->known_mask&OCNEXT_A64_FP_KNOWN_CPACR)||!b->cpacr_el1) &&
        ((b->known_mask&OCNEXT_A64_FP_KNOWN_FPCR)||!b->fpcr) && ((b->known_mask&OCNEXT_A64_FP_KNOWN_FPSR)||!b->fpsr);
}
int ocnext_a64_fp_control_reset(struct ocnext_a64_fp_registers *b)
{
    if(!span(b,sizeof(*b)))return -1;
    zero(b,sizeof(*b));b->abi_version=OCNEXT_A64_FP_REGISTERS_ABI_VERSION;return 0;
}
unsigned ocnext_a64_fp_control_decode(uint32_t op)
{
    switch(op&UINT32_C(0xffffffE0)){
    case UINT32_C(0xd5381040):case UINT32_C(0xd5181040):return OCNEXT_A64_FP_CONTROL_CPACR;
    case UINT32_C(0xd53b4400):case UINT32_C(0xd51b4400):return OCNEXT_A64_FP_CONTROL_FPCR;
    case UINT32_C(0xd53b4420):case UINT32_C(0xd51b4420):return OCNEXT_A64_FP_CONTROL_FPSR;
    default:return 0;
    }
}
enum ocnext_a64_fp_control_result ocnext_a64_fp_access_prepare(
    const struct ocnext_a64_fp_registers *b,const struct ocnext_a64_fp_access_request *r,
    struct ocnext_a64_fp_access_effect *out)
{
    struct ocnext_a64_fp_access_effect next={0};unsigned fp;
    if(!span(b,sizeof(*b))||!span(r,sizeof(*r))||!span(out,sizeof(*out))||
       overlaps(b,sizeof(*b),r,sizeof(*r))||overlaps(b,sizeof(*b),out,sizeof(*out))||
       overlaps(r,sizeof(*r),out,sizeof(*out)))return OCNEXT_A64_FP_CONTROL_ARGUMENT;
    if(!ocnext_a64_fp_control_valid(b)||r->current_el>1||r->profile>1||r->reserved)
        return OCNEXT_A64_FP_CONTROL_ARGUMENT;
    if(r->profile!=OCNEXT_A64_FP_CONTROL_FPEN_ONLY||!(b->known_mask&OCNEXT_A64_FP_KNOWN_CPACR))
        return OCNEXT_A64_FP_CONTROL_UNSUPPORTED;
    fp=(unsigned)(b->cpacr_el1>>20);
    if(fp==0||fp==2||(fp==1&&!r->current_el)){
        next.action=OCNEXT_A64_FP_ACCESS_EXCEPTION;next.esr=UINT32_C(0x1fe00000);
    }else next.action=OCNEXT_A64_FP_ACCESS_ALLOWED;
    copy(out,&next,sizeof(next));return OCNEXT_A64_FP_CONTROL_OK;
}
enum ocnext_a64_fp_control_result ocnext_a64_fp_control_prepare(
    const struct ocnext_a64_fp_registers *b,const struct ocnext_a64_fp_control_request *r,
    struct ocnext_a64_fp_control_effect *out)
{
    struct ocnext_a64_fp_control_effect next;unsigned reg,read,bit,fp;
    uint64_t value,mask;
    if(!span(b,sizeof(*b))||!span(r,sizeof(*r))||!span(out,sizeof(*out))||
       overlaps(b,sizeof(*b),r,sizeof(*r))||overlaps(b,sizeof(*b),out,sizeof(*out))||overlaps(r,sizeof(*r),out,sizeof(*out)))return OCNEXT_A64_FP_CONTROL_ARGUMENT;
    if(!ocnext_a64_fp_control_valid(b)||r->current_el>1||r->profile>2||r->reserved[0]||r->reserved[1])return OCNEXT_A64_FP_CONTROL_ARGUMENT;
    reg=ocnext_a64_fp_control_decode(r->opcode);if(!reg)return OCNEXT_A64_FP_CONTROL_NOT_ALLOCATED;
    zero(&next,sizeof(next));copy(&next.bank_after,b,sizeof(*b));next.rt=r->opcode&31u;
    if(reg==OCNEXT_A64_FP_CONTROL_CPACR&&!r->current_el){next.action=OCNEXT_A64_FP_CONTROL_EXCEPTION;next.esr=UINT32_C(0x02000000);goto publish;}
    if(r->profile!=OCNEXT_A64_FP_CONTROL_FPEN_ONLY&&r->profile!=OCNEXT_A64_FP_CONTROL_FPEN_NOTRAP)return OCNEXT_A64_FP_CONTROL_UNSUPPORTED;
    read=(r->opcode>>21)&1u;bit=1u<<(reg-1u);
    if(reg!=OCNEXT_A64_FP_CONTROL_CPACR){
        if(!(b->known_mask&OCNEXT_A64_FP_KNOWN_CPACR))return OCNEXT_A64_FP_CONTROL_UNSUPPORTED;
        fp=(unsigned)(b->cpacr_el1>>20);
        /* DDI0487H.a D13-5464: A64 FP traps have CV=1, COND=1110. */
        if(fp==0||fp==2||(fp==1&&!r->current_el)){next.action=OCNEXT_A64_FP_CONTROL_EXCEPTION;next.esr=UINT32_C(0x1fe00000);goto publish;}
    }
    if(read){
        if(!(b->known_mask&bit))return OCNEXT_A64_FP_CONTROL_UNSUPPORTED;
        next.value=reg==1?b->cpacr_el1:reg==2?b->fpcr:b->fpsr;next.action=OCNEXT_A64_FP_CONTROL_READ;
    }else{
        value=next.rt==31?0:r->operand;
        if(reg==OCNEXT_A64_FP_CONTROL_FPCR&&r->profile==OCNEXT_A64_FP_CONTROL_FPEN_NOTRAP)value&=~OCNEXT_A64_FPCR_TRAP_ENABLE_MASK;
        mask=reg==1?OCNEXT_A64_FP_CPACR_MASK:reg==2?OCNEXT_A64_FP_FPCR_MASK:OCNEXT_A64_FP_FPSR_MASK;
        if(value&~mask)return OCNEXT_A64_FP_CONTROL_UNSUPPORTED;
        if(reg==1)next.bank_after.cpacr_el1=value;else if(reg==2)next.bank_after.fpcr=value;else next.bank_after.fpsr=value;
        next.bank_after.known_mask|=bit;next.action=OCNEXT_A64_FP_CONTROL_WRITE;
    }
publish:
    copy(out,&next,sizeof(next));return OCNEXT_A64_FP_CONTROL_OK;
}
