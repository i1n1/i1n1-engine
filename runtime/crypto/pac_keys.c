#include "ocnext/pac_keys.h"
#include <stddef.h>

_Static_assert(sizeof(struct ocnext_pac_key)==16, "key ABI drift");
_Static_assert(sizeof(struct ocnext_pac_key_bank)==112, "key bank ABI drift");
_Static_assert(offsetof(struct ocnext_pac_key_bank,generation)==80, "key generation offset");
_Static_assert(offsetof(struct ocnext_pac_key_bank,abi_version)==104, "key ABI offset");

static int span_valid(const void *p,size_t n,size_t align)
{
    uintptr_t a=(uintptr_t)p;
    return p && a%align==0 && n<=UINTPTR_MAX-a;
}
static int disjoint(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x+an<=y || y+bn<=x;
}
static void clear(struct ocnext_pac_key_bank *b)
{
    unsigned i;
    for(i=0;i<OCNEXT_PAC_KEY_COUNT;++i){b->keys[i].lo=0;b->keys[i].hi=0;}
    b->generation=0;b->owner_id=0;b->profile=0;b->known_mask=0;
    b->abi_version=OCNEXT_PAC_KEYS_ABI_VERSION;b->reserved=0;
}
int ocnext_pac_keys_valid(const struct ocnext_pac_key_bank *b)
{
    unsigned i;
    if(!span_valid(b,sizeof(*b),_Alignof(struct ocnext_pac_key_bank)) ||
       b->abi_version!=OCNEXT_PAC_KEYS_ABI_VERSION || b->reserved ||
       (b->known_mask&~OCNEXT_PAC_KEYS_KNOWN_ALL))return 0;
    for(i=0;i<OCNEXT_PAC_KEY_COUNT;++i)
        if(!(b->known_mask&(1u<<i)) && (b->keys[i].lo || b->keys[i].hi))return 0;
    if(!b->owner_id)return !b->generation && !b->profile && !b->known_mask;
    if(!b->generation)return 0;
    if(!b->profile)return !b->known_mask && b->generation>=2;
    return b->profile==OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC && b->known_mask!=0;
}
enum ocnext_pac_key_result ocnext_pac_keys_reset(struct ocnext_pac_key_bank *b)
{
    if(!span_valid(b,sizeof(*b),_Alignof(struct ocnext_pac_key_bank)))return OCNEXT_PAC_KEYS_ARGUMENT;
    clear(b);return OCNEXT_PAC_KEYS_OK;
}
static enum ocnext_pac_key_result issue(struct ocnext_pac_key_bank *b,
    uint64_t owner,uint64_t generation,uint32_t mask,const struct ocnext_pac_key *keys,
    int rotating)
{
    struct ocnext_pac_key_bank next;
    unsigned i;
    if(!ocnext_pac_keys_valid(b) || !owner || !mask ||
       (mask&~OCNEXT_PAC_KEYS_KNOWN_ALL) ||
       !span_valid(keys,OCNEXT_PAC_KEY_COUNT*sizeof(*keys),_Alignof(struct ocnext_pac_key)) ||
       !disjoint(b,sizeof(*b),keys,OCNEXT_PAC_KEY_COUNT*sizeof(*keys)))return OCNEXT_PAC_KEYS_ARGUMENT;
    if(generation!=b->generation || (b->owner_id && owner!=b->owner_id))return OCNEXT_PAC_KEYS_STALE;
    if((rotating && b->profile!=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC) ||
       (!rotating && b->profile!=OCNEXT_PAC_KEYS_NONE))return OCNEXT_PAC_KEYS_STATE;
    if(b->generation==UINT64_MAX)return OCNEXT_PAC_KEYS_OVERFLOW;
    for(i=0;i<OCNEXT_PAC_KEY_COUNT;++i)
        if(!(mask&(1u<<i)) && (keys[i].lo || keys[i].hi))return OCNEXT_PAC_KEYS_ARGUMENT;
    clear(&next);next.owner_id=owner;next.generation=b->generation+1;
    next.profile=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC;next.known_mask=mask;
    for(i=0;i<OCNEXT_PAC_KEY_COUNT;++i)next.keys[i]=keys[i];
    *b=next;return OCNEXT_PAC_KEYS_OK;
}
enum ocnext_pac_key_result ocnext_pac_keys_provision(struct ocnext_pac_key_bank *b,
    uint64_t owner,uint64_t generation,uint32_t mask,const struct ocnext_pac_key *keys)
{return issue(b,owner,generation,mask,keys,0);}
enum ocnext_pac_key_result ocnext_pac_keys_rotate(struct ocnext_pac_key_bank *b,
    uint64_t owner,uint64_t generation,uint32_t mask,const struct ocnext_pac_key *keys)
{return issue(b,owner,generation,mask,keys,1);}
enum ocnext_pac_key_result ocnext_pac_keys_close(struct ocnext_pac_key_bank *b,
    uint64_t owner,uint64_t generation)
{
    struct ocnext_pac_key_bank next;
    if(!ocnext_pac_keys_valid(b) || !owner)return OCNEXT_PAC_KEYS_ARGUMENT;
    if(owner!=b->owner_id || generation!=b->generation)return OCNEXT_PAC_KEYS_STALE;
    if(b->profile!=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC)return OCNEXT_PAC_KEYS_STATE;
    if(b->generation==UINT64_MAX)return OCNEXT_PAC_KEYS_OVERFLOW;
    clear(&next);next.owner_id=owner;next.generation=generation+1;
    *b=next;return OCNEXT_PAC_KEYS_OK;
}
