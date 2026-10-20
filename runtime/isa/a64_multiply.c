#include "ocnext/a64_multiply.h"
#include <stddef.h>
#include <stdint.h>
_Static_assert(sizeof(struct ocnext_a64_mul_request)==48,"request48");
_Static_assert(sizeof(struct ocnext_a64_mul_effect)==32,"effect32");
_Static_assert(_Alignof(struct ocnext_a64_mul_request)==8,"requestalign8");
_Static_assert(_Alignof(struct ocnext_a64_mul_effect)==8,"effectalign8");
_Static_assert(offsetof(struct ocnext_a64_mul_request,nzcv)==32,"requestNZCV32");
_Static_assert(offsetof(struct ocnext_a64_mul_effect,reserved)==24,"effectreserved24");

static int span(const void *pointer,size_t size,uintptr_t *first,uintptr_t *last)
{
    uintptr_t p=(uintptr_t)pointer;
    if(!pointer||(p&7u)||p>UINTPTR_MAX-(size-1u))return 0;
    *first=p;*last=p+size-1u;return 1;
}

enum kind { OUTSIDE=0, LOW, SIGNED_LONG, UNSIGNED_LONG, SIGNED_HIGH, UNSIGNED_HIGH };
static enum kind classify(uint32_t op)
{
    if((op&UINT32_C(0x7fe00000))==UINT32_C(0x1b000000))return LOW;
    if((op&UINT32_C(0xffe00000))==UINT32_C(0x9b200000))return SIGNED_LONG;
    if((op&UINT32_C(0xffe00000))==UINT32_C(0x9ba00000))return UNSIGNED_LONG;
    if((op&UINT32_C(0xffe0fc00))==UINT32_C(0x9b407c00))return SIGNED_HIGH;
    if((op&UINT32_C(0xffe0fc00))==UINT32_C(0x9bc07c00))return UNSIGNED_HIGH;
    return OUTSIDE;
}
int ocnext_a64_mul_decode(uint32_t opcode){return classify(opcode)!=OUTSIDE;}

/* Four32-bit limbs; every multiplication is an unsigned64 result.
 * The middle sum is at most3*(2^32-1), so its carry is bounded below2^34.
 * No signed arithmetic or128-bit compiler helper exists in this module. */
static uint64_t high_unsigned(uint64_t a,uint64_t b)
{
    uint64_t al=(uint32_t)a,bl=(uint32_t)b,ah=a>>32,bh=b>>32;
    uint64_t lo=al*bl,cross1=ah*bl,cross2=al*bh;
    uint64_t middle=(lo>>32)+(uint32_t)cross1+(uint32_t)cross2;
    return ah*bh+(cross1>>32)+(cross2>>32)+(middle>>32);
}
static uint64_t signed32_bits(uint64_t x)
{x&=UINT64_C(0xffffffff);return x&UINT64_C(0x80000000)?x|UINT64_C(0xffffffff00000000):x;}

enum ocnext_a64_mul_status ocnext_a64_mul_prepare(
    const struct ocnext_a64_mul_request *request,
    struct ocnext_a64_mul_effect *effect)
{
    uintptr_t rf,rl,ef,el;
    enum kind kind;
    uint64_t operands[3],result,product,mask;
    unsigned regs[3],widths[3],high,active,rd,width,source_width,i,j;
    struct ocnext_a64_mul_effect staged;
    if(!span(request,48,&rf,&rl)||!span(effect,32,&ef,&el)||(rf<=el&&ef<=rl))return OCNEXT_A64_MUL_ARGUMENT;
    if(request->abi_version!=OCNEXT_A64_MUL_ABI||(request->operand_known&~7u)||
       (request->nzcv_known&~15u)||(request->nzcv&~OCNEXT_A64_MUL_NZCV_MASK))return OCNEXT_A64_MUL_ARGUMENT;
    for(i=0;i<sizeof(request->reserved);++i)if(request->reserved[i])return OCNEXT_A64_MUL_ARGUMENT;
    kind=classify(request->opcode);if(!kind)return OCNEXT_A64_MUL_UNSUPPORTED;
    high=kind==SIGNED_HIGH||kind==UNSIGNED_HIGH;
    width=kind==LOW?((request->opcode>>31)?64u:32u):64u;
    source_width=kind==SIGNED_LONG||kind==UNSIGNED_LONG?32u:width;
    active=high?2u:3u;rd=request->opcode&31u;
    regs[0]=(request->opcode>>5)&31u;regs[1]=(request->opcode>>16)&31u;regs[2]=(request->opcode>>10)&31u;
    widths[0]=widths[1]=source_width;widths[2]=width;
    operands[0]=request->rn_value;operands[1]=request->rm_value;operands[2]=request->ra_value;
    for(i=0;i<active;++i)for(j=i+1;j<active;++j){
        unsigned common=widths[i]<widths[j]?widths[i]:widths[j];
        uint64_t common_mask=common==64?UINT64_MAX:UINT64_C(0xffffffff);
        if(regs[i]!=31&&regs[i]==regs[j]&&(request->operand_known&(1u<<i))&&
           (request->operand_known&(1u<<j))&&((operands[i]^operands[j])&common_mask))return OCNEXT_A64_MUL_ARGUMENT;
    }
    for(i=0;i<active;++i){
        if(regs[i]==31)operands[i]=0;
        else if(!(request->operand_known&(1u<<i)))return OCNEXT_A64_MUL_UNSUPPORTED;
        if(widths[i]==32)operands[i]&=UINT64_C(0xffffffff);
    }
    if(high){
        result=high_unsigned(operands[0],operands[1]);
        if(kind==SIGNED_HIGH){
            if(operands[0]>>63)result-=operands[1];
            if(operands[1]>>63)result-=operands[0];
        }
    }else{
        if(kind==SIGNED_LONG){operands[0]=signed32_bits(operands[0]);operands[1]=signed32_bits(operands[1]);}
        product=operands[0]*operands[1];
        result=(request->opcode&UINT32_C(0x8000))?operands[2]-product:operands[2]+product;
        mask=width==64?UINT64_MAX:UINT64_C(0xffffffff);result&=mask;
    }
    staged.result=rd==31?0:result;staged.nzcv=request->nzcv;staged.destination=rd;staged.abi_version=1;
    staged.width=(uint8_t)width;staged.rn_rm_width=(uint8_t)source_width;staged.write_gpr=(uint8_t)(rd!=31);staged.nzcv_known=request->nzcv_known;
    for(i=0;i<sizeof(staged.reserved);++i)staged.reserved[i]=0;
    for(i=0;i<sizeof(staged);++i)((uint8_t*)effect)[i]=((const uint8_t*)&staged)[i];
    return OCNEXT_A64_MUL_OK;
}
