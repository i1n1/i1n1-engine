#include "ocnext/a64_fp_soft.h"

/* Integer soft-float core. Design: every finite nonzero operand is unpacked to
 * (sign, e, sig) with value = sig/2^62 * 2^e and bit 62 of sig set. Results are
 * produced in the same form (sticky information jammed into bit 0) and
 * rounded/packed by round_pack(), which implements FPRoundBase for the
 * binary32/binary64 formats with tininess detected before rounding. */

struct fmt { unsigned bits,mbits,ebits; int bias; uint64_t expmax; };
static struct fmt fmt_of(unsigned bits)
{
    struct fmt f;
    f.bits=bits;
    f.mbits=bits==32?23u:52u;
    f.ebits=bits==32?8u:11u;
    f.bias=bits==32?127:1023;
    f.expmax=(UINT64_C(1)<<f.ebits)-1u;
    return f;
}
enum cls { C_ZERO,C_FIN,C_INF,C_QNAN,C_SNAN };
struct unp { unsigned sign; int e; uint64_t sig; enum cls c; };
struct u128 { uint64_t hi,lo; };

static unsigned msb(uint64_t v){unsigned n=0;while(v>>=1)++n;return n;}
static uint64_t jam(uint64_t v,unsigned n)
{
    if(!n)return v;
    if(n>=64)return v!=0;
    return (v>>n)|((v<<(64u-n))!=0);
}
static uint64_t default_nan(const struct fmt *f){return f->bits==32?UINT64_C(0x7fc00000):UINT64_C(0x7ff8000000000000);}
static uint64_t quiet(const struct fmt *f,uint64_t v){return v|(UINT64_C(1)<<(f->mbits-1u));}
static uint64_t sign_bit(const struct fmt *f){return UINT64_C(1)<<(f->bits-1u);}
static uint64_t bits_mask(const struct fmt *f){return f->bits==64?~UINT64_C(0):(UINT64_C(1)<<f->bits)-1u;}

static void unpack_fp(const struct fmt *f,uint64_t v,struct unp *u)
{
    uint64_t frac=v&((UINT64_C(1)<<f->mbits)-1u),ex=(v>>f->mbits)&f->expmax;
    u->sign=(unsigned)((v>>(f->bits-1u))&1u);u->e=0;u->sig=0;
    if(ex==f->expmax){
        u->c=!frac?C_INF:((frac>>(f->mbits-1u))&1u)?C_QNAN:C_SNAN;
    }else if(!ex){
        if(!frac)u->c=C_ZERO;
        else{
            unsigned m=msb(frac);
            u->c=C_FIN;u->sig=frac<<(62u-m);
            u->e=(1-f->bias-(int)f->mbits)+(int)m;
        }
    }else{
        u->c=C_FIN;
        u->sig=(frac|(UINT64_C(1)<<f->mbits))<<(62u-f->mbits);
        u->e=(int)ex-f->bias;
    }
}
static uint64_t inf_of(const struct fmt *f,unsigned sign){return (sign?sign_bit(f):0)|(f->expmax<<f->mbits);}
static uint64_t zero_of(const struct fmt *f,unsigned sign){return sign?sign_bit(f):0;}
static uint64_t max_finite(const struct fmt *f,unsigned sign)
{
    return (sign?sign_bit(f):0)|(((f->expmax-1u)<<f->mbits)|((UINT64_C(1)<<f->mbits)-1u));
}

/* FPRoundBase + packing. sig has bit 62 set (or is a jammed denormal-bound value). */
static uint64_t round_pack(const struct fmt *f,unsigned sign,int e,uint64_t sig,
                           enum ocnext_fp_round rm,struct ocnext_fp_ctx *x)
{
    unsigned sh=62u-f->mbits;
    int64_t biased=(int64_t)e+f->bias;
    int tiny=0;
    uint64_t rb,half,inc=0,packed,top;
    if(biased>=(int64_t)f->expmax)goto overflow;
    if(biased<=0){
        uint64_t n=(uint64_t)(1-biased);
        tiny=1;sig=jam(sig,n>=64?64u:(unsigned)n);biased=1;
    }
    rb=sig&((UINT64_C(1)<<sh)-1u);half=UINT64_C(1)<<(sh-1u);
    sig>>=sh;
    switch(rm){
    case OCNEXT_FP_RN: inc=rb>half||(rb==half&&(sig&1u)); break;
    case OCNEXT_FP_RA: inc=rb>=half; break;
    case OCNEXT_FP_RP: inc=!sign&&rb; break;
    case OCNEXT_FP_RM: inc=sign&&rb; break;
    default: inc=0;
    }
    if(rb){x->flags|=OCNEXT_FP_IXC;if(tiny)x->flags|=OCNEXT_FP_UFC;}
    sig+=inc;
    packed=((uint64_t)(biased-1)<<f->mbits)+sig;
    top=f->expmax<<f->mbits;
    if(packed>=top)goto overflow;
    return (sign?sign_bit(f):0)|packed;
overflow:
    x->flags|=OCNEXT_FP_OFC|OCNEXT_FP_IXC;
    switch(rm){
    case OCNEXT_FP_RZ: return max_finite(f,sign);
    case OCNEXT_FP_RP: return sign?max_finite(f,1):inf_of(f,0);
    case OCNEXT_FP_RM: return sign?inf_of(f,1):max_finite(f,0);
    default: return inf_of(f,sign);
    }
}

/* FPProcessNaNs for two operands. */
static int nan2(const struct fmt *f,const struct unp *ua,const struct unp *ub,uint64_t a,uint64_t b,
                struct ocnext_fp_ctx *x,uint64_t *out)
{
    uint64_t r;
    if(ua->c==C_SNAN||ub->c==C_SNAN)x->flags|=OCNEXT_FP_IOC;
    if(ua->c==C_SNAN)r=quiet(f,a);
    else if(ub->c==C_SNAN)r=quiet(f,b);
    else if(ua->c==C_QNAN)r=a;
    else if(ub->c==C_QNAN)r=b;
    else return 0;
    *out=x->dn?default_nan(f):r;
    return 1;
}
static uint64_t invalid(const struct fmt *f,struct ocnext_fp_ctx *x){x->flags|=OCNEXT_FP_IOC;return default_nan(f);}

static void mul64(uint64_t a,uint64_t b,struct u128 *p)
{
    uint64_t a0=a&0xffffffffu,a1=a>>32,b0=b&0xffffffffu,b1=b>>32;
    uint64_t t0=a0*b0,t1=a1*b0,t2=a0*b1,t3=a1*b1;
    uint64_t mid=(t0>>32)+(t1&0xffffffffu)+(t2&0xffffffffu);
    p->lo=(t0&0xffffffffu)|(mid<<32);
    p->hi=t3+(t1>>32)+(t2>>32)+(mid>>32);
}

static uint64_t addsub(unsigned bits,uint64_t a,uint64_t b,int negate_b,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    uint64_t r,sa,sb;
    int ea,eb;
    unsigned sgn_a,sgn_b;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(nan2(&f,&ua,&ub,a,b,x,&r))return r;
    sgn_a=ua.sign;sgn_b=ub.sign^(unsigned)(negate_b!=0);
    if(ua.c==C_INF||ub.c==C_INF){
        if(ua.c==C_INF&&ub.c==C_INF)return sgn_a==sgn_b?inf_of(&f,sgn_a):invalid(&f,x);
        return ua.c==C_INF?inf_of(&f,sgn_a):inf_of(&f,sgn_b);
    }
    if(ua.c==C_ZERO&&ub.c==C_ZERO)return zero_of(&f,sgn_a&sgn_b);
    if(ua.c==C_ZERO)return negate_b?(b^sign_bit(&f)):b;
    if(ub.c==C_ZERO)return a;
    sa=ua.sig;sb=ub.sig;ea=ua.e;eb=ub.e;
    if(ea<eb||(ea==eb&&sa<sb)){
        uint64_t t=sa;int te=ea;unsigned ts=sgn_a;
        sa=sb;ea=eb;sgn_a=sgn_b;sb=t;eb=te;sgn_b=ts;
    }
    {
        int d=ea-eb;
        sb=jam(sb,d>=64?64u:(unsigned)d);
    }
    if(sgn_a==sgn_b){
        uint64_t sum=sa+sb;
        if(sum>>63){sum=(sum>>1)|(sum&1u);ea+=1;}
        return round_pack(&f,sgn_a,ea,sum,OCNEXT_FP_RN,x);
    }else{
        uint64_t diff=sa-sb;
        unsigned sh;
        if(!diff)return zero_of(&f,0);
        sh=62u-msb(diff);
        return round_pack(&f,sgn_a,ea-(int)sh,diff<<sh,OCNEXT_FP_RN,x);
    }
}
uint64_t ocnext_fp_add(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x){return addsub(bits,a,b,0,x);}
uint64_t ocnext_fp_sub(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x){return addsub(bits,a,b,1,x);}

uint64_t ocnext_fp_mul(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    struct u128 p;
    uint64_t r,sig;
    unsigned sign;
    int e;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(nan2(&f,&ua,&ub,a,b,x,&r))return r;
    sign=ua.sign^ub.sign;
    if(ua.c==C_INF||ub.c==C_INF){
        if(ua.c==C_ZERO||ub.c==C_ZERO)return invalid(&f,x);
        return inf_of(&f,sign);
    }
    if(ua.c==C_ZERO||ub.c==C_ZERO)return zero_of(&f,sign);
    mul64(ua.sig,ub.sig,&p);
    e=ua.e+ub.e;
    if((p.hi>>61)&1u){
        sig=(p.hi<<1)|(p.lo>>63);
        sig|=(p.lo&((UINT64_C(1)<<63)-1u))!=0;
        e+=1;
    }else{
        sig=(p.hi<<2)|(p.lo>>62);
        sig|=(p.lo&((UINT64_C(1)<<62)-1u))!=0;
    }
    return round_pack(&f,sign,e,sig,OCNEXT_FP_RN,x);
}

uint64_t ocnext_fp_div(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    uint64_t r,rem,q=0;
    unsigned sign;
    int e;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(nan2(&f,&ua,&ub,a,b,x,&r))return r;
    sign=ua.sign^ub.sign;
    if((ua.c==C_INF&&ub.c==C_INF)||(ua.c==C_ZERO&&ub.c==C_ZERO))return invalid(&f,x);
    if(ua.c==C_INF||ub.c==C_ZERO){
        if(ub.c==C_ZERO&&ua.c==C_FIN)x->flags|=OCNEXT_FP_DZC;
        return inf_of(&f,sign);
    }
    if(ua.c==C_ZERO||ub.c==C_INF)return zero_of(&f,sign);
    rem=ua.sig;e=ua.e-ub.e;
    if(rem<ub.sig){rem<<=1;e-=1;}
    for(unsigned i=0;i<63;i++){
        unsigned bit=rem>=ub.sig;
        q=(q<<1)|bit;
        if(bit)rem-=ub.sig;
        rem<<=1;
    }
    if(rem)q|=1u;
    return round_pack(&f,sign,e,q,OCNEXT_FP_RN,x);
}

static int u128_ge(struct u128 a,struct u128 b){return a.hi>b.hi||(a.hi==b.hi&&a.lo>=b.lo);}
static struct u128 u128_add(struct u128 a,struct u128 b)
{
    struct u128 r;
    r.lo=a.lo+b.lo;r.hi=a.hi+b.hi+(r.lo<a.lo);
    return r;
}
static struct u128 u128_sub(struct u128 a,struct u128 b)
{
    struct u128 r;
    r.lo=a.lo-b.lo;r.hi=a.hi-b.hi-(a.lo<b.lo);
    return r;
}
static struct u128 u128_shr(struct u128 a,unsigned n)
{
    struct u128 r;
    r.lo=(a.lo>>n)|(a.hi<<(64u-n));r.hi=a.hi>>n;
    return r;
}
uint64_t ocnext_fp_sqrt(unsigned bits,uint64_t a,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp u;
    uint64_t sig;
    struct u128 num,res={0,0},bit;
    int e;
    a&=bits_mask(&f);
    unpack_fp(&f,a,&u);
    if(u.c==C_SNAN||u.c==C_QNAN){
        if(u.c==C_SNAN)x->flags|=OCNEXT_FP_IOC;
        return x->dn?default_nan(&f):(u.c==C_SNAN?quiet(&f,a):a);
    }
    if(u.c==C_ZERO)return a;
    if(u.sign)return invalid(&f,x);
    if(u.c==C_INF)return a;
    sig=u.sig;e=u.e;
    if(e&1){sig<<=1;e-=1;}
    num.hi=sig>>2;num.lo=sig<<62;
    bit.hi=UINT64_C(1)<<62;bit.lo=0;
    while(!u128_ge(num,bit)&&(bit.hi||bit.lo))bit=u128_shr(bit,2);
    while(bit.hi||bit.lo){
        struct u128 t=u128_add(res,bit);
        if(u128_ge(num,t)){num=u128_sub(num,t);res=u128_add(u128_shr(res,1),bit);}
        else res=u128_shr(res,1);
        bit=u128_shr(bit,2);
    }
    sig=res.lo|((num.hi|num.lo)!=0);
    return round_pack(&f,0,e/2,sig,OCNEXT_FP_RN,x);
}

/* Total-order key for finite/infinite values (zeros handled by the caller). */
static int less(const struct fmt *f,uint64_t a,uint64_t b)
{
    unsigned sa=(unsigned)((a>>(f->bits-1u))&1u),sb=(unsigned)((b>>(f->bits-1u))&1u);
    uint64_t ma=a&~sign_bit(f),mb=b&~sign_bit(f);
    if(!ma&&!mb)return 0;
    if(sa!=sb)return sa>sb;
    return sa?ma>mb:ma<mb;
}
static uint64_t maxmin(unsigned bits,uint64_t a,uint64_t b,int numeric,int is_max,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    uint64_t r;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(numeric){
        if(ua.c==C_QNAN&&ub.c!=C_QNAN&&ub.c!=C_SNAN){a=inf_of(&f,is_max?1u:0u);unpack_fp(&f,a,&ua);}
        else if(ub.c==C_QNAN&&ua.c!=C_QNAN&&ua.c!=C_SNAN){b=inf_of(&f,is_max?1u:0u);unpack_fp(&f,b,&ub);}
    }
    if(nan2(&f,&ua,&ub,a,b,x,&r))return r;
    if(ua.c==C_ZERO&&ub.c==C_ZERO&&ua.sign!=ub.sign)
        return zero_of(&f,is_max?0u:1u);
    if(is_max)return less(&f,b,a)?a:b;
    return less(&f,a,b)?a:b;
}
uint64_t ocnext_fp_max(unsigned bits,uint64_t a,uint64_t b,int numeric,struct ocnext_fp_ctx *x){return maxmin(bits,a,b,numeric,1,x);}
uint64_t ocnext_fp_min(unsigned bits,uint64_t a,uint64_t b,int numeric,struct ocnext_fp_ctx *x){return maxmin(bits,a,b,numeric,0,x);}

unsigned ocnext_fp_compare(unsigned bits,uint64_t a,uint64_t b,int signal_all_nans,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(ua.c==C_QNAN||ua.c==C_SNAN||ub.c==C_QNAN||ub.c==C_SNAN){
        if(ua.c==C_SNAN||ub.c==C_SNAN||signal_all_nans)x->flags|=OCNEXT_FP_IOC;
        return 3u;
    }
    {
        int za=(a&~sign_bit(&f))==0,zb=(b&~sign_bit(&f))==0;
        if((za&&zb)||a==b)return 6u;
    }
    return less(&f,a,b)?8u:2u;
}

uint64_t ocnext_fp_convert(unsigned from_bits,unsigned to_bits,uint64_t a,struct ocnext_fp_ctx *x)
{
    struct fmt s=fmt_of(from_bits),d=fmt_of(to_bits);
    struct unp u;
    a&=bits_mask(&s);
    unpack_fp(&s,a,&u);
    switch(u.c){
    case C_SNAN: case C_QNAN:{
        uint64_t sign=u.sign?sign_bit(&d):0,frac,r;
        if(u.c==C_SNAN)x->flags|=OCNEXT_FP_IOC;
        if(x->dn)return default_nan(&d);
        frac=a&((UINT64_C(1)<<s.mbits)-1u);
        if(d.mbits>s.mbits)frac<<=d.mbits-s.mbits;else frac>>=s.mbits-d.mbits;
        r=sign|(d.expmax<<d.mbits)|frac;
        return quiet(&d,r);}
    case C_INF: return inf_of(&d,u.sign);
    case C_ZERO: return zero_of(&d,u.sign);
    default: return round_pack(&d,u.sign,u.e,u.sig,OCNEXT_FP_RN,x);
    }
}

uint64_t ocnext_fp_from_int(unsigned bits,uint64_t mag,int neg,unsigned fbits,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    unsigned pos;
    uint64_t sig;
    if(!mag)return 0;
    pos=msb(mag);
    sig=pos<=62?mag<<(62u-pos):jam(mag,pos-62u);
    return round_pack(&f,neg!=0,(int)pos-(int)fbits,sig,OCNEXT_FP_RN,x);
}

/* Shared integer rounding of |v| * 2^fbits. Returns the rounded magnitude in
 * *mag (saturating flag in *ovf when it does not fit 64 bits) and whether the
 * value was inexact. v must be finite and nonzero. */
static void round_to_integer(const struct fmt *f,const struct unp *u,unsigned fbits,
                             enum ocnext_fp_round rm,uint64_t *mag,int *inexact,int *ovf)
{
    int e=u->e+(int)fbits;           /* value = (sig/2^62) * 2^e */
    uint64_t sig=u->sig,ip,roundbit=0,sticky=0;
    unsigned sign=u->sign;
    (void)f;
    *ovf=0;*inexact=0;
    if(e>=64){ *ovf=1;*mag=0;return; }
    if(e>=62){
        ip=sig<<(e-62);              /* no fractional bits */
    }else if(e>=0){
        /* integer part = sig >> (62-e), fraction = low (62-e) bits */
        unsigned sh=62u-(unsigned)e;
        uint64_t rem_bits=sig&((UINT64_C(1)<<sh)-1u);
        ip=sig>>sh;
        roundbit=(rem_bits>>(sh-1u))&1u;
        sticky=(rem_bits&((UINT64_C(1)<<(sh-1u))-1u))!=0;
    }else{
        ip=0;
        if(e==-1){roundbit=1;sticky=(sig&((UINT64_C(1)<<62)-1u))!=0;}
        else{roundbit=0;sticky=1;}
    }
    *inexact=roundbit||sticky;
    {
        int inc=0;
        switch(rm){
        case OCNEXT_FP_RN: inc=roundbit&&(sticky||(ip&1u)); break;
        case OCNEXT_FP_RA: inc=roundbit!=0; break;
        case OCNEXT_FP_RP: inc=!sign&&(roundbit||sticky); break;
        case OCNEXT_FP_RM: inc=sign&&(roundbit||sticky); break;
        default: inc=0;
        }
        if(inc){ if(ip==~UINT64_C(0)){*ovf=1;*mag=0;return;} ++ip; }
    }
    *mag=ip;
}

uint64_t ocnext_fp_round_int(unsigned bits,uint64_t a,enum ocnext_fp_round mode,int exact,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp u;
    uint64_t mag;
    int inexact,ovf;
    a&=bits_mask(&f);
    unpack_fp(&f,a,&u);
    if(u.c==C_SNAN||u.c==C_QNAN){
        if(u.c==C_SNAN)x->flags|=OCNEXT_FP_IOC;
        return x->dn?default_nan(&f):(u.c==C_SNAN?quiet(&f,a):a);
    }
    if(u.c==C_INF||u.c==C_ZERO)return a;
    if(u.e>=(int)f.mbits)return a; /* already integral */
    round_to_integer(&f,&u,0,mode,&mag,&inexact,&ovf);
    if(inexact&&exact)x->flags|=OCNEXT_FP_IXC;
    if(!mag)return zero_of(&f,u.sign);
    return ocnext_fp_from_int(bits,mag,(int)u.sign,0,x);
}

uint64_t ocnext_fp_to_int(unsigned bits,uint64_t a,enum ocnext_fp_round mode,unsigned fbits,
                          int is_signed,unsigned width,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp u;
    uint64_t mag=0,wmask=width==64?~UINT64_C(0):(UINT64_C(1)<<width)-1u;
    uint64_t smax=is_signed?(UINT64_C(1)<<(width-1u))-1u:wmask;
    uint64_t smin_mag=is_signed?UINT64_C(1)<<(width-1u):0;
    int inexact=0,ovf=0;
    a&=bits_mask(&f);
    unpack_fp(&f,a,&u);
    if(u.c==C_SNAN||u.c==C_QNAN){x->flags|=OCNEXT_FP_IOC;return 0;}
    if(u.c==C_INF)ovf=1;
    else if(u.c==C_ZERO)return 0;
    else round_to_integer(&f,&u,fbits,mode,&mag,&inexact,&ovf);
    if(!ovf){
        if(u.sign){ if(mag>smin_mag||(!is_signed&&mag))ovf=1; }
        else if(mag>smax)ovf=1;
    }
    if(ovf){
        x->flags|=OCNEXT_FP_IOC;
        if(u.sign)return is_signed?((UINT64_C(0)-smin_mag)&wmask):0;
        return smax;
    }
    if(inexact)x->flags|=OCNEXT_FP_IXC;
    return (u.sign?(UINT64_C(0)-mag):mag)&wmask;
}

/* ---- fused multiply-add: addend + n*m with a single rounding ---- */
static struct u128 u128_shl_n(struct u128 a,unsigned n)
{
    struct u128 r;
    if(!n)return a;
    if(n>=128){r.hi=r.lo=0;return r;}
    if(n>=64){r.hi=a.lo<<(n-64u);r.lo=0;}
    else{r.hi=(a.hi<<n)|(a.lo>>(64u-n));r.lo=a.lo<<n;}
    return r;
}
static struct u128 u128_shr_jam(struct u128 a,unsigned n)
{
    struct u128 r;
    if(!n)return a;
    if(n>=128){r.hi=0;r.lo=(a.hi|a.lo)!=0;return r;}
    if(n>=64){
        unsigned k=n-64u;
        uint64_t lost=k?(a.hi<<(64u-k)):0;
        r.hi=0;r.lo=(k?a.hi>>k:a.hi)|((lost|a.lo)!=0);
        return r;
    }
    r.hi=a.hi>>n;
    r.lo=(a.lo>>n)|(a.hi<<(64u-n));
    r.lo|=(a.lo<<(64u-n))!=0;
    return r;
}
static unsigned u128_msb(struct u128 a){return a.hi?64u+msb(a.hi):msb(a.lo);}
static int u128_is_zero(struct u128 a){return !(a.hi|a.lo);}

static uint64_t fma_core(unsigned bits,uint64_t addend,uint64_t n,uint64_t m,int halve,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,u1,u2;
    unsigned sign_p,inf_p,zero_p;
    addend&=bits_mask(&f);n&=bits_mask(&f);m&=bits_mask(&f);
    unpack_fp(&f,addend,&ua);unpack_fp(&f,n,&u1);unpack_fp(&f,m,&u2);
    if(ua.c==C_QNAN&&((u1.c==C_INF&&u2.c==C_ZERO)||(u1.c==C_ZERO&&u2.c==C_INF)))return invalid(&f,x);
    if(u1.c>=C_QNAN||u2.c>=C_QNAN||ua.c>=C_QNAN){
        uint64_t sel;
        if(u1.c==C_SNAN||u2.c==C_SNAN||ua.c==C_SNAN)x->flags|=OCNEXT_FP_IOC;
        /* FPProcessNaNs3(typeA, type1, type2, ...): the addend has priority */
        if(ua.c==C_SNAN)sel=quiet(&f,addend);
        else if(u1.c==C_SNAN)sel=quiet(&f,n);
        else if(u2.c==C_SNAN)sel=quiet(&f,m);
        else if(ua.c==C_QNAN)sel=addend;
        else if(u1.c==C_QNAN)sel=n;
        else sel=m;
        return x->dn?default_nan(&f):sel;
    }
    sign_p=u1.sign^u2.sign;
    inf_p=u1.c==C_INF||u2.c==C_INF;
    zero_p=u1.c==C_ZERO||u2.c==C_ZERO;
    if((u1.c==C_INF&&u2.c==C_ZERO)||(u1.c==C_ZERO&&u2.c==C_INF)||(ua.c==C_INF&&inf_p&&ua.sign!=sign_p))
        return invalid(&f,x);
    if((ua.c==C_INF&&!ua.sign)||(inf_p&&!sign_p))return inf_of(&f,0);
    if(ua.c==C_INF||inf_p)return inf_of(&f,1);
    if(ua.c==C_ZERO&&zero_p&&ua.sign==sign_p)return zero_of(&f,ua.sign);
    if(zero_p){
        if(ua.c==C_ZERO)return zero_of(&f,0);
        if(halve)return round_pack(&f,ua.sign,ua.e-halve,ua.sig,OCNEXT_FP_RN,x);
        return addend; /* exact */
    }
    {
        struct u128 p,rp,ra,big,small,res;
        int ep,ea,eb,es;
        unsigned sgn_big,sgn_small,d;
        int p_is_big;
        mul64(u1.sig,u2.sig,&p);
        if((p.hi>>61)&1u){rp=u128_shl_n(p,1);ep=u1.e+u2.e+1;}
        else{rp=u128_shl_n(p,2);ep=u1.e+u2.e;}
        if(ua.c==C_ZERO){
            return round_pack(&f,sign_p,ep-halve,rp.hi|((rp.lo)!=0),OCNEXT_FP_RN,x);
        }
        ra.hi=ua.sig;ra.lo=0;ea=ua.e;
        /* pick the larger magnitude */
        p_is_big=ep>ea||(ep==ea&&u128_ge(rp,ra));
        if(p_is_big){big=rp;eb=ep;sgn_big=sign_p;small=ra;es=ea;sgn_small=ua.sign;}
        else{big=ra;eb=ea;sgn_big=ua.sign;small=rp;es=ep;sgn_small=sign_p;}
        d=(unsigned)((eb-es)>127?128:(eb-es));
        small=u128_shr_jam(small,d);
        if(sgn_big==sgn_small){
            res=u128_add(big,small);
            if(res.hi>>63){res=u128_shr_jam(res,1);eb+=1;}
        }else{
            res=u128_sub(big,small);
            if(u128_is_zero(res))return zero_of(&f,0);
            {
                unsigned sh=126u-u128_msb(res);
                res=u128_shl_n(res,sh);
                eb-=(int)sh;
            }
        }
        return round_pack(&f,sgn_big,eb-halve,res.hi|(res.lo!=0),OCNEXT_FP_RN,x);
    }
}
uint64_t ocnext_fp_fma(unsigned bits,uint64_t addend,uint64_t n,uint64_t m,struct ocnext_fp_ctx *x)
{
    return fma_core(bits,addend,n,m,0,x);
}

/* FMULX: FMUL, except 0 * inf = +/-2.0. */
uint64_t ocnext_fp_mulx(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    a&=bits_mask(&f);b&=bits_mask(&f);
    unpack_fp(&f,a,&ua);unpack_fp(&f,b,&ub);
    if(((ua.c==C_INF&&ub.c==C_ZERO)||(ua.c==C_ZERO&&ub.c==C_INF)))
        return (ua.sign^ub.sign?sign_bit(&f):0)|(bits==32?UINT64_C(0x40000000):UINT64_C(0x4000000000000000));
    return ocnext_fp_mul(bits,a,b,x);
}
static uint64_t step_fused(unsigned bits,uint64_t a,uint64_t b,int rsqrt,struct ocnext_fp_ctx *x)
{
    struct fmt f=fmt_of(bits);
    struct unp ua,ub;
    uint64_t na,three_or_two;
    a&=bits_mask(&f);b&=bits_mask(&f);
    na=a^sign_bit(&f);
    unpack_fp(&f,na,&ua);unpack_fp(&f,b,&ub);
    three_or_two=bits==32?(rsqrt?UINT64_C(0x40400000):UINT64_C(0x40000000)):
                          (rsqrt?UINT64_C(0x4008000000000000):UINT64_C(0x4000000000000000));
    if(ua.c<C_QNAN&&ub.c<C_QNAN){
        if((ua.c==C_INF&&ub.c==C_ZERO)||(ua.c==C_ZERO&&ub.c==C_INF))
            return rsqrt?(bits==32?UINT64_C(0x3fc00000):UINT64_C(0x3ff8000000000000))
                        :(bits==32?UINT64_C(0x40000000):UINT64_C(0x4000000000000000));
        if(ua.c==C_INF||ub.c==C_INF)return inf_of(&f,ua.sign^ub.sign);
    }
    return fma_core(bits,three_or_two,na,b,rsqrt,x);
}
uint64_t ocnext_fp_recps(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x){return step_fused(bits,a,b,0,x);}
uint64_t ocnext_fp_rsqrts(unsigned bits,uint64_t a,uint64_t b,struct ocnext_fp_ctx *x){return step_fused(bits,a,b,1,x);}
