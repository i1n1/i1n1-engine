#include "ocnext/pac_pointer.h"
#include "ocnext/pac_qarma5.h"
#include <stddef.h>

_Static_assert(sizeof(struct ocnext_pac_pointer_config)==16,"PAC config ABI1");
_Static_assert(sizeof(struct ocnext_pac_pointer_request)==48,"PAC request ABI1");
_Static_assert(sizeof(struct ocnext_pac_pointer_output)==32,"PAC output ABI1");

struct native_span { uintptr_t begin,end; };
static int native_span(const void *p,size_t bytes,size_t alignment,struct native_span *out)
{
    uintptr_t begin=(uintptr_t)p;
    if(p==NULL || begin%alignment || bytes>UINTPTR_MAX-begin)return 0;
    out->begin=begin;out->end=begin+bytes;return 1;
}
static int disjoint(const struct native_span *a,const struct native_span *b)
{
    return a->end<=b->begin || b->end<=a->begin;
}

int ocnext_pac_pointer_config_valid(const struct ocnext_pac_pointer_config *config)
{
    struct native_span span;
    unsigned i;
    if(!native_span(config,sizeof(*config),_Alignof(struct ocnext_pac_pointer_config),&span))return 0;
    if(config->abi_version!=OCNEXT_PAC_POINTER_ABI_VERSION ||
       (config->profile!=OCNEXT_PAC_POINTER_QARMA5_PAUTH2 && config->profile!=OCNEXT_PAC_POINTER_QARMA5_FPAC &&
        config->profile!=OCNEXT_PAC_POINTER_QARMA5_PAUTH1))return 0;
    for(i=0;i<2;++i)
        if(config->va_bits[i]<25 || config->va_bits[i]>48 || config->tbi[i]>1 || config->tbid[i]>1 || config->reserved[i])return 0;
    return 1;
}

enum ocnext_pac_pointer_result ocnext_pac_pointer_execute(
    const struct ocnext_pac_key_bank *bank,const struct ocnext_pac_pointer_config *config,
    const struct ocnext_pac_pointer_request *request,struct ocnext_pac_pointer_output *output)
{
    struct native_span spans[4];
    struct ocnext_pac_pointer_output staged={0};
    unsigned i,j,region,width,top,data;
    uint64_t field,pac_field,extension,restored,mac,result;
    int tbi,canonical;
    if(!native_span(bank,sizeof(*bank),_Alignof(struct ocnext_pac_key_bank),&spans[0]) ||
       !native_span(config,sizeof(*config),_Alignof(struct ocnext_pac_pointer_config),&spans[1]) ||
       !native_span(request,sizeof(*request),_Alignof(struct ocnext_pac_pointer_request),&spans[2]) ||
       !native_span(output,sizeof(*output),_Alignof(struct ocnext_pac_pointer_output),&spans[3]))return OCNEXT_PAC_POINTER_ARGUMENT;
    for(i=0;i<4;++i)for(j=i+1;j<4;++j)if(!disjoint(&spans[i],&spans[j]))return OCNEXT_PAC_POINTER_ARGUMENT;
    if(!ocnext_pac_keys_valid(bank) || !ocnext_pac_pointer_config_valid(config))return OCNEXT_PAC_POINTER_ARGUMENT;
    if(request->operation<OCNEXT_PAC_POINTER_SIGN || request->operation>OCNEXT_PAC_POINTER_STRIP ||
       request->key_index>OCNEXT_PAC_KEY_DB || request->current_el>1 || request->key_enabled>1)return OCNEXT_PAC_POINTER_UNSUPPORTED;
    for(i=0;i<6;++i)if(request->reserved[i])return OCNEXT_PAC_POINTER_ARGUMENT;
    if(bank->profile!=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC)return OCNEXT_PAC_POINTER_INACTIVE;
    if(request->owner_id!=bank->owner_id || request->generation!=bank->generation)return OCNEXT_PAC_POINTER_STALE;
    if(!(bank->known_mask&(1u<<request->key_index)))return OCNEXT_PAC_POINTER_KEY_UNKNOWN;
    data=request->key_index>=OCNEXT_PAC_KEY_DA;
    region=(unsigned)((request->pointer>>55)&1u);
    tbi=config->tbi[region] && (data || !config->tbid[region]);
    if(request->operation==OCNEXT_PAC_POINTER_SIGN) {
        /* Arm ARM AddPAC selector: bit55 when any range has an effective TBI
         * for this key class, otherwise bit63; the selector's range sets the
         * bottom PAC bit. The "awkward" mix (a range-wide TBI that the bit55
         * range itself lacks, with bit63!=bit55) is where the architectural
         * text and the pinned QEMU reference disagree, so it is a stop. */
        int any_tbi=data ? (config->tbi[0] || config->tbi[1]) :
            ((config->tbi[0] && !config->tbid[0]) || (config->tbi[1] && !config->tbid[1]));
        unsigned bit63=(unsigned)((request->pointer>>63)&1u);
        if(any_tbi && !tbi && bit63!=region && request->key_enabled)return OCNEXT_PAC_POINTER_UNSUPPORTED;
        if(!any_tbi)region=bit63;
        /* Likewise QEMU sizes the field by bit55's range even when the
         * selector is bit63; only a differing range width exposes it. */
        if(region!=((request->pointer>>55)&1u) && config->va_bits[0]!=config->va_bits[1] &&
           request->key_enabled)return OCNEXT_PAC_POINTER_UNSUPPORTED;
    }
    width=config->va_bits[region];top=tbi ? 56u : 64u;
    /* Geometry validation gives25<=width<=48<top. Avoid a shift by64. */
    field=(UINT64_MAX<<width) & (top==64u ? UINT64_MAX : ((UINT64_C(1)<<top)-1u));
    pac_field=field & ~(UINT64_C(1)<<55);
    extension=region ? field : 0;
    restored=(request->pointer&~field)|extension;
    staged.generation=bank->generation;
    if(request->operation==OCNEXT_PAC_POINTER_STRIP) {
        staged.pointer=restored;staged.outcome=OCNEXT_PAC_POINTER_STRIPPED;
    } else if(!request->key_enabled) {
        staged.pointer=request->pointer;staged.outcome=OCNEXT_PAC_POINTER_DISABLED;
    } else {
        mac=ocnext_pac_qarma5_mac(restored,request->modifier,
            bank->keys[request->key_index].lo,bank->keys[request->key_index].hi);
        if(config->profile==OCNEXT_PAC_POINTER_QARMA5_PAUTH1) {
            /* FEAT_PAuth without PAuth2: the PAC replaces the field; a bad
             * extension flips PAC[top-1] at signing; a failed AUT yields the
             * restored pointer with error code (key B, not key B) in
             * [top-2:top-3] (bits 62:61, or 54:53 with TBI). */
            unsigned top_bit=tbi ? 55u : 63u;
            uint64_t sel=(uint64_t)region<<55;
            if(request->operation==OCNEXT_PAC_POINTER_SIGN) {
                if((request->pointer^extension)&field)mac^=UINT64_C(1)<<(top_bit-1u);
                staged.pointer=(request->pointer&~(pac_field|(UINT64_C(1)<<55)))|(mac&pac_field)|sel;
                staged.outcome=OCNEXT_PAC_POINTER_SIGNED;
            } else if(((mac^request->pointer)&pac_field)==0) {
                staged.pointer=restored;staged.outcome=OCNEXT_PAC_POINTER_AUTH_SUCCESS;
            } else {
                uint64_t code=(request->key_index&1u) ? 2u : 1u;
                staged.pointer=(restored&~(UINT64_C(3)<<(top_bit-2u)))|(code<<(top_bit-2u));
                staged.outcome=OCNEXT_PAC_POINTER_AUTH_CORRUPTED;
            }
            *output=staged;
            return OCNEXT_PAC_POINTER_OK;
        }
        result=request->pointer^(mac&pac_field);
        if(request->operation==OCNEXT_PAC_POINTER_SIGN) {
            result=(result&~(UINT64_C(1)<<55))|((uint64_t)region<<55);
            staged.pointer=result;staged.outcome=OCNEXT_PAC_POINTER_SIGNED;
        } else {
            canonical=((result^extension)&field)==0;
            if(!canonical && config->profile==OCNEXT_PAC_POINTER_QARMA5_FPAC) {
                staged.pointer=request->pointer;
                staged.esr=UINT64_C(0x72000000)|(data<<1)|(request->key_index&1u);
                staged.outcome=OCNEXT_PAC_POINTER_AUTH_EXCEPTION;
            } else {
                staged.pointer=result;
                staged.outcome=canonical ? OCNEXT_PAC_POINTER_AUTH_SUCCESS : OCNEXT_PAC_POINTER_AUTH_CORRUPTED;
            }
        }
    }
    *output=staged;
    return OCNEXT_PAC_POINTER_OK;
}
