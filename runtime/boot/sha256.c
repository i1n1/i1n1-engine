#include "ocnext/sha256.h"

static const uint32_t constants[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t rotate(uint32_t x,unsigned n) {return (x>>n)|(x<<(32-n));}
static int overlap(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an && bn && (x<=y ? y-x<an : x-y<bn);
}
static void compress(struct ocnext_sha256 *ctx,const uint8_t block[64])
{
    uint32_t w[64],a,b,c,d,e,f,g,h;unsigned i;
    for(i=0;i<16;++i)w[i]=(uint32_t)block[4*i]<<24|(uint32_t)block[4*i+1]<<16|
        (uint32_t)block[4*i+2]<<8|block[4*i+3];
    for(i=16;i<64;++i) {
        uint32_t s0=rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];
    e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
    for(i=0;i<64;++i) {
        uint32_t s1=rotate(e,6)^rotate(e,11)^rotate(e,25);
        uint32_t t1=h+s1+((e&f)^((~e)&g))+constants[i]+w[i];
        uint32_t s0=rotate(a,2)^rotate(a,13)^rotate(a,22);
        uint32_t t2=s0+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;
    ctx->h[4]+=e;ctx->h[5]+=f;ctx->h[6]+=g;ctx->h[7]+=h;
}
static int valid(const struct ocnext_sha256 *ctx)
{
    return ctx && !ctx->finalized && !ctx->reserved[0] && !ctx->reserved[1] &&
        !ctx->reserved[2] && ctx->used<64 && ctx->total_bytes<=UINT64_MAX/8 &&
        ctx->used==(ctx->total_bytes&63);
}
int ocnext_sha256_init(struct ocnext_sha256 *ctx)
{
    static const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t *p=(uint8_t *)ctx;size_t i;
    if(!ctx)return -1;
    for(i=0;i<sizeof(*ctx);++i)p[i]=0;
    for(i=0;i<8;++i)ctx->h[i]=initial[i];
    return 0;
}
int ocnext_sha256_update(struct ocnext_sha256 *ctx,const uint8_t *data,size_t n)
{
    size_t i;
    if(!valid(ctx) || (!data && n) || n>UINT64_MAX/8-ctx->total_bytes ||
        overlap(ctx,sizeof(*ctx),data,n))return -1;
    ctx->total_bytes+=(uint64_t)n;
    for(i=0;i<n;++i) {
        ctx->block[ctx->used++]=data[i];
        if(ctx->used==64) {compress(ctx,ctx->block);ctx->used=0;}
    }
    return 0;
}
int ocnext_sha256_final(struct ocnext_sha256 *ctx,uint8_t out[32])
{
    uint64_t bits;unsigned i;
    if(!valid(ctx) || !out || overlap(ctx,sizeof(*ctx),out,32))return -1;
    bits=ctx->total_bytes*8;ctx->block[ctx->used++]=0x80;
    if(ctx->used>56) {
        while(ctx->used<64)ctx->block[ctx->used++]=0;
        compress(ctx,ctx->block);ctx->used=0;
    }
    while(ctx->used<56)ctx->block[ctx->used++]=0;
    for(i=0;i<8;++i)ctx->block[56+i]=(uint8_t)(bits>>(56-8*i));
    compress(ctx,ctx->block);
    for(i=0;i<32;++i)out[i]=(uint8_t)(ctx->h[i/4]>>(24-8*(i%4)));
    for(i=0;i<64;++i)ctx->block[i]=0;
    ctx->used=0;ctx->finalized=1;return 0;
}
int ocnext_sha256_digest(const uint8_t *data,size_t n,uint8_t out[32])
{
    struct ocnext_sha256 ctx;
    if(!out || (!data && n))return -1;
    if(ocnext_sha256_init(&ctx) || ocnext_sha256_update(&ctx,data,n))return -1;
    return ocnext_sha256_final(&ctx,out);
}
