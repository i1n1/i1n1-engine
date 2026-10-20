#include "ocnext/a64_divbit.h"
static int span(const void *p,size_t n)
{uintptr_t a=(uintptr_t)p;return p&&!(a&7u)&&n<=UINTPTR_MAX-a;}
static int overlaps(const void *a,size_t n,const void *b,size_t m)
{uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m&&y<x+n;}
static uint64_t width_mask(unsigned width)
{return width==32?UINT64_C(0xffffffff):UINT64_MAX;}
unsigned ocnext_a64_divbit_decode(uint32_t op)
{
 uint32_t two=op&UINT32_C(0x7fe0fc00),one=op&UINT32_C(0xfffffc00);
 if(two==UINT32_C(0x1ac00800))return OCNEXT_A64_DIVBIT_UDIV;
 if(two==UINT32_C(0x1ac00c00))return OCNEXT_A64_DIVBIT_SDIV;
 switch(one){
 case UINT32_C(0x5ac00000):case UINT32_C(0xdac00000):return OCNEXT_A64_DIVBIT_RBIT;
 case UINT32_C(0x5ac00400):case UINT32_C(0xdac00400):return OCNEXT_A64_DIVBIT_REV16;
 case UINT32_C(0x5ac00800):case UINT32_C(0xdac00c00):return OCNEXT_A64_DIVBIT_REV;
 case UINT32_C(0xdac00800):return OCNEXT_A64_DIVBIT_REV32;
 case UINT32_C(0x5ac01000):case UINT32_C(0xdac01000):return OCNEXT_A64_DIVBIT_CLZ;
 case UINT32_C(0x5ac01400):case UINT32_C(0xdac01400):return OCNEXT_A64_DIVBIT_CLS;
 default:return 0;
 }
}
static unsigned leading_zero(uint64_t x,unsigned width)
{unsigned n=0;for(unsigned i=width;i>0;--i){if((x>>(i-1u))&1u)break;++n;}return n;}
static uint64_t signed_divide(uint64_t a,uint64_t b,unsigned width)
{
 uint64_t mask=width_mask(width),sign=UINT64_C(1)<<(width-1u),x,y,q;
 unsigned an=(a&sign)!=0,bn=(b&sign)!=0;
 if(!b)return 0;
 x=an?(~a+UINT64_C(1))&mask:a;y=bn?(~b+UINT64_C(1))&mask:b;
 q=x/y;return (an!=bn?(~q+UINT64_C(1)):q)&mask;
}
static uint64_t reverse_bytes(uint64_t x,unsigned width,unsigned container)
{
 uint64_t v=0;unsigned bytes=width/8u,group=container/8u;
 for(unsigned i=0;i<bytes;++i){unsigned target=(i/group)*group+group-1u-(i%group);
  v|=((x>>(8u*i))&UINT64_C(255))<<(8u*target);}
 return v;
}
enum ocnext_a64_divbit_result ocnext_a64_divbit_prepare(
 const struct ocnext_a64_divbit_request *r,struct ocnext_a64_divbit_effect *out)
{
 struct ocnext_a64_divbit_effect next;unsigned kind,width,rn,rm,rd;uint64_t a,b,value=0,mask;
 if(!span(r,sizeof(*r))||!span(out,sizeof(*out))||overlaps(r,sizeof(*r),out,sizeof(*out)))
  return OCNEXT_A64_DIVBIT_ARGUMENT;
 if(r->abi_version!=OCNEXT_A64_DIVBIT_ABI||(r->operand_known&~3u))return OCNEXT_A64_DIVBIT_ARGUMENT;
 for(unsigned i=0;i<7;++i)if(r->reserved[i])return OCNEXT_A64_DIVBIT_ARGUMENT;
 kind=ocnext_a64_divbit_decode(r->opcode);if(!kind)return OCNEXT_A64_DIVBIT_UNSUPPORTED;
 width=(r->opcode>>31)?64u:32u;rn=(r->opcode>>5)&31u;rm=(r->opcode>>16)&31u;rd=r->opcode&31u;
 mask=width_mask(width);a=rn==31?0:r->rn_value&mask;b=rm==31?0:r->rm_value&mask;
 if(kind<=OCNEXT_A64_DIVBIT_SDIV&&rn==rm&&rn!=31&&
    (r->operand_known&3u)==3u&&a!=b)return OCNEXT_A64_DIVBIT_ARGUMENT;
 if((rn!=31&&!(r->operand_known&OCNEXT_A64_DIVBIT_KNOWN_RN))||
    (kind<=OCNEXT_A64_DIVBIT_SDIV&&rm!=31&&!(r->operand_known&OCNEXT_A64_DIVBIT_KNOWN_RM)))
  return OCNEXT_A64_DIVBIT_UNSUPPORTED;
 if(kind==OCNEXT_A64_DIVBIT_UDIV)value=b?a/b:0;
 else if(kind==OCNEXT_A64_DIVBIT_SDIV)value=signed_divide(a,b,width);
 else if(kind==OCNEXT_A64_DIVBIT_RBIT){for(unsigned i=0;i<width;++i)value|=((a>>i)&1u)<<(width-1u-i);}
 else if(kind==OCNEXT_A64_DIVBIT_REV16)value=reverse_bytes(a,width,16);
 else if(kind==OCNEXT_A64_DIVBIT_REV32)value=reverse_bytes(a,width,32);
 else if(kind==OCNEXT_A64_DIVBIT_REV)value=reverse_bytes(a,width,width);
 else if(kind==OCNEXT_A64_DIVBIT_CLZ)value=leading_zero(a,width);
 else value=leading_zero(a^(a&(UINT64_C(1)<<(width-1u))?mask:0),width)-1u;
 for(unsigned i=0;i<sizeof(next);++i)((uint8_t*)&next)[i]=0;
 next.result=rd==31?0:value&mask;next.destination=rd;next.abi_version=OCNEXT_A64_DIVBIT_ABI;
 next.width=(uint8_t)width;next.write_gpr=(uint8_t)(rd!=31);
 for(unsigned i=0;i<sizeof(next);++i)((uint8_t*)out)[i]=((const uint8_t*)&next)[i];
 return OCNEXT_A64_DIVBIT_OK;
}
