#include "ocnext/a64_simd_integer.h"
static int span(const void *p,size_t n){uintptr_t a=(uintptr_t)p;return p&&!(a&15u)&&n<=UINTPTR_MAX-a;}
static int overlap(const void *a,size_t n,const void *b,size_t m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m&&y<x+n;}
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static void copy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;}
int ocnext_a64_simd_integer_valid(const struct ocnext_a64_vector_registers *b)
{
    if(!span(b,sizeof(*b))||b->abi_version!=OCNEXT_A64_VECTOR_REGISTERS_ABI_VERSION)return 0;
    for(unsigned i=0;i<12;i++)if(b->reserved[i])return 0;
    for(unsigned r=0;r<32;r++)for(unsigned i=0;i<16;i++)if(!(b->known_bytes[r]&(1u<<i))&&b->bytes[r][i])return 0;
    return 1;
}
int ocnext_a64_simd_integer_reset(struct ocnext_a64_vector_registers *b)
{if(!span(b,sizeof(*b)))return -1;zero(b,sizeof(*b));b->abi_version=1;return 0;}
unsigned ocnext_a64_simd_integer_decode(uint32_t op)
{
    switch(op&UINT32_C(0xbfe0fc00)){
    case UINT32_C(0x0e201c00):return OCNEXT_A64_SIMD_INTEGER_AND;
    case UINT32_C(0x0e601c00):return OCNEXT_A64_SIMD_INTEGER_BIC;
    case UINT32_C(0x0ea01c00):return OCNEXT_A64_SIMD_INTEGER_ORR;
    case UINT32_C(0x0ee01c00):return OCNEXT_A64_SIMD_INTEGER_ORN;
    case UINT32_C(0x2e201c00):return OCNEXT_A64_SIMD_INTEGER_EOR;
    case UINT32_C(0x2e601c00):return OCNEXT_A64_SIMD_INTEGER_BSL;
    case UINT32_C(0x2ea01c00):return OCNEXT_A64_SIMD_INTEGER_BIT;
    case UINT32_C(0x2ee01c00):return OCNEXT_A64_SIMD_INTEGER_BIF;
    }
    if((op&UINT32_C(0xbf20fc00))==UINT32_C(0x0e208400)||
       (op&UINT32_C(0xbf20fc00))==UINT32_C(0x2e208400)){
        if(!(op&UINT32_C(0x40000000))&&((op>>22)&3u)==3u)return 0;
        return (op&UINT32_C(0x20000000))?OCNEXT_A64_SIMD_INTEGER_SUB:OCNEXT_A64_SIMD_INTEGER_ADD;
    }
    if((op&UINT32_C(0x9ff80c00))==UINT32_C(0x0f000400)){
        unsigned mode=(op>>12)&15u,bit=(op>>29)&1u;
        if((!bit&&(mode==0||mode==2||mode==4||mode==6||mode==8||mode==10||mode==12||mode==13||mode==14))||
           (bit&&mode==14))return OCNEXT_A64_SIMD_INTEGER_MOVI;
    }
    return 0;
}
static int reserved_encoding(uint32_t op)
{
    uint32_t family=op&UINT32_C(0xbf20fc00);
    if((family==UINT32_C(0x0e208400)||family==UINT32_C(0x2e208400))&&
       !(op&UINT32_C(0x40000000))&&((op>>22)&3u)==3u)return 1;
    return (op&UINT32_C(0x9ff80c00))==UINT32_C(0x0f000400)&&
        !(op&UINT32_C(0x40000000))&&(op&UINT32_C(0x20000000))&&((op>>12)&15u)==15;
}
static uint64_t load(const uint8_t *p,unsigned n)
{uint64_t value=0;for(unsigned i=0;i<n;i++)value|=(uint64_t)p[i]<<(8u*i);return value;}
static uint64_t immediate(uint32_t op)
{
    unsigned mode=(op>>12)&15u,imm=((op>>16)&7u)<<5|((op>>5)&31u);
    uint64_t value=0,lane;unsigned bytes;
    if(mode==14&&op&UINT32_C(0x20000000)){
        for(unsigned i=0;i<8;i++)if(imm&(1u<<i))value|=UINT64_C(255)<<(8u*i);
        return value;
    }
    if(mode<8){bytes=4;lane=(uint64_t)imm<<(8u*(mode>>1));}
    else if(mode<12){bytes=2;lane=(uint64_t)imm<<(mode==10?8:0);}
    else if(mode<14){bytes=4;unsigned shift=mode==12?8:16;lane=(uint64_t)imm<<shift|((UINT64_C(1)<<shift)-1);}
    else{bytes=1;lane=imm;}
    for(unsigned i=0;i<8;i+=bytes)value|=lane<<(8u*i);
    return value;
}
/* A source identity denotes one architectural input byte. Unknown bytes are
 * never compared numerically. The two mask/data identities reduce select to
 * OR/AND before considering a numeric mask, including a known annihilator. */
static int select_byte(const struct ocnext_a64_vector_registers *b,unsigned mask,
    unsigned a,unsigned v,unsigned i,uint8_t *result)
{
    unsigned mk=(b->known_bytes[mask]>>i)&1u,ak=(b->known_bytes[a]>>i)&1u;
    unsigned vk=(b->known_bytes[v]>>i)&1u;
    uint8_t M=b->bytes[mask][i],A=b->bytes[a][i],B=b->bytes[v][i];
    if(a==v){if(!ak)return 0;*result=A;return 1;}
    if(mask==a){
        if((mk&&M==255)||(vk&&B==255))*result=255;
        else{if(!mk||!vk)return 0;*result=(uint8_t)(M|B);}
        return 1;
    }
    if(mask==v){
        if((mk&&!M)||(ak&&!A))*result=0;
        else{if(!mk||!ak)return 0;*result=(uint8_t)(M&A);}
        return 1;
    }
    if(mk){
        if(!M){if(!vk)return 0;*result=B;}
        else if(M==255){if(!ak)return 0;*result=A;}
        else{if(!ak||!vk)return 0;*result=(uint8_t)((A&M)|(B&(uint8_t)~M));}
        return 1;
    }
    if(!ak||!vk||A!=B)return 0;
    *result=A;return 1;
}
enum ocnext_a64_simd_integer_result ocnext_a64_simd_integer_prepare(
    const struct ocnext_a64_vector_registers *b,const struct ocnext_a64_simd_integer_request *r,
    struct ocnext_a64_simd_integer_effect *out)
{
    struct ocnext_a64_simd_integer_effect next;unsigned kind,n,m,size;uint32_t op;
    if(!span(b,sizeof(*b))||!span(r,sizeof(*r))||!span(out,sizeof(*out))||
       overlap(b,sizeof(*b),r,sizeof(*r))||overlap(b,sizeof(*b),out,sizeof(*out))||overlap(r,sizeof(*r),out,sizeof(*out)))return OCNEXT_A64_SIMD_INTEGER_ARGUMENT;
    if(!ocnext_a64_simd_integer_valid(b)||r->reserved[0]||r->reserved[1]||r->reserved[2])return OCNEXT_A64_SIMD_INTEGER_ARGUMENT;
    op=r->opcode;kind=ocnext_a64_simd_integer_decode(op);
    if(!kind)return reserved_encoding(op)?OCNEXT_A64_SIMD_INTEGER_NOT_ALLOCATED:OCNEXT_A64_SIMD_INTEGER_UNSUPPORTED;
    zero(&next,sizeof(next));next.opcode=op;next.destination=(uint8_t)(op&31u);next.known_bytes=UINT16_C(0xffff);
    n=(op>>5)&31u;m=(op>>16)&31u;size=(op&UINT32_C(0x40000000))?16:8;
    if(kind==OCNEXT_A64_SIMD_INTEGER_MOVI){
        uint64_t imm=immediate(op);for(unsigned i=0;i<size;i++)next.bytes[i]=(uint8_t)(imm>>(8u*(i&7u)));
    }else if(kind==OCNEXT_A64_SIMD_INTEGER_ADD||kind==OCNEXT_A64_SIMD_INTEGER_SUB){
        unsigned lane_bytes=1u<<((op>>22)&3u);
        for(unsigned i=0;i<size;i++)if(!(b->known_bytes[n]&(1u<<i))||!(b->known_bytes[m]&(1u<<i)))return OCNEXT_A64_SIMD_INTEGER_UNSUPPORTED;
        for(unsigned i=0;i<size;i+=lane_bytes){
            uint64_t a=load(b->bytes[n]+i,lane_bytes),v=load(b->bytes[m]+i,lane_bytes);
            uint64_t result=kind==OCNEXT_A64_SIMD_INTEGER_ADD?a+v:a-v;
            for(unsigned j=0;j<lane_bytes;j++)next.bytes[i+j]=(uint8_t)(result>>(8u*j));
        }
    }else if(kind>=OCNEXT_A64_SIMD_INTEGER_BSL){
        unsigned d=next.destination;
        unsigned mask=kind==OCNEXT_A64_SIMD_INTEGER_BSL?d:m;
        unsigned a=kind==OCNEXT_A64_SIMD_INTEGER_BIF?d:n;
        unsigned v=kind==OCNEXT_A64_SIMD_INTEGER_BSL?m:
            kind==OCNEXT_A64_SIMD_INTEGER_BIT?d:n;
        for(unsigned i=0;i<size;i++)
            if(!select_byte(b,mask,a,v,i,&next.bytes[i]))return OCNEXT_A64_SIMD_INTEGER_UNSUPPORTED;
    }else{
        for(unsigned i=0;i<size;i++){
            unsigned ak=(b->known_bytes[n]>>i)&1u,bk=(b->known_bytes[m]>>i)&1u;
            uint8_t a=b->bytes[n][i],v=b->bytes[m][i],result=0;int known=ak&&bk;
            if(n==m&&(kind==OCNEXT_A64_SIMD_INTEGER_EOR||kind==OCNEXT_A64_SIMD_INTEGER_BIC)){known=1;result=0;}
            else if(n==m&&kind==OCNEXT_A64_SIMD_INTEGER_ORN){known=1;result=255;}
            else if(kind==OCNEXT_A64_SIMD_INTEGER_AND&&((ak&&!a)||(bk&&!v))){known=1;result=0;}
            else if(kind==OCNEXT_A64_SIMD_INTEGER_ORR&&((ak&&a==255)||(bk&&v==255))){known=1;result=255;}
            else if(kind==OCNEXT_A64_SIMD_INTEGER_BIC&&((ak&&!a)||(bk&&v==255))){known=1;result=0;}
            else if(kind==OCNEXT_A64_SIMD_INTEGER_ORN&&((ak&&a==255)||(bk&&!v))){known=1;result=255;}
            else if(known){
                if(kind==OCNEXT_A64_SIMD_INTEGER_AND)result=(uint8_t)(a&v);
                else if(kind==OCNEXT_A64_SIMD_INTEGER_BIC)result=(uint8_t)(a&~v);
                else if(kind==OCNEXT_A64_SIMD_INTEGER_ORR)result=(uint8_t)(a|v);
                else if(kind==OCNEXT_A64_SIMD_INTEGER_ORN)result=(uint8_t)(a|~v);
                else result=(uint8_t)(a^v);
            }
            if(!known)return OCNEXT_A64_SIMD_INTEGER_UNSUPPORTED;
            next.bytes[i]=result;
        }
    }
    copy(out,&next,sizeof(next));return OCNEXT_A64_SIMD_INTEGER_OK;
}
