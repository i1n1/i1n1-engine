#include "ocnext/ordering.h"
#include <stdatomic.h>

static void copy_bytes(void *out,const void *input,size_t n)
{
    uint8_t *to=out;const uint8_t *from=input;
    while(n--)*to++=*from++;
}
int ocnext_ordering_init(struct ocnext_ordering *state,enum ocnext_ordering_profile profile)
{
    uint8_t *p=(uint8_t *)state;size_t i;
    if(!state || profile!=OCNEXT_ORDERING_SERIAL_RAM)return -1;
    for(i=0;i<sizeof(*state);++i)p[i]=0;
    state->abi_version=OCNEXT_ORDERING_ABI_VERSION;
    state->profile=(uint32_t)profile;return 0;
}
static int valid_request(const struct ocnext_a64_sync_request *r)
{
    uint32_t base;unsigned i;
    if(r->current_el>1 || r->pc%4 || r->pc>UINT64_MAX-4 || r->option>15)return 0;
    for(i=0;i<sizeof(r->reserved);++i)if(r->reserved[i])return 0;
    if(r->kind==OCNEXT_A64_SYNC_ISB) {
        if(r->option!=15)return 0;
        base=UINT32_C(0xd50330df);
    } else if(r->kind==OCNEXT_A64_SYNC_DMB || r->kind==OCNEXT_A64_SYNC_DSB) {
        if(!(r->option&3))return 0;
        base=r->kind==OCNEXT_A64_SYNC_DMB ? UINT32_C(0xd50330bf) : UINT32_C(0xd503309f);
    } else return 0;
    return r->domain==(enum ocnext_a64_sync_domain)(r->option>>2) &&
        r->types==(enum ocnext_a64_sync_types)(r->option&3) &&
        r->opcode==(base|((uint32_t)r->option<<8));
}
enum ocnext_a64_sync_result ocnext_ordering_sync(void *context,
                                   const struct ocnext_a64_sync_request *input)
{
    struct ocnext_ordering *state=context;
    struct ocnext_a64_sync_request r;
    if(!state || !input)return OCNEXT_A64_SYNC_FAILED;
    if(state->abi_version!=OCNEXT_ORDERING_ABI_VERSION ||
       state->profile!=OCNEXT_ORDERING_SERIAL_RAM)return OCNEXT_A64_SYNC_UNSUPPORTED;
    copy_bytes(&r,input,sizeof(r));
    if(!valid_request(&r) || state->events==UINT64_MAX || state->host_fences==UINT64_MAX ||
        (r.kind==OCNEXT_A64_SYNC_DMB && state->dmb==UINT64_MAX) ||
        (r.kind==OCNEXT_A64_SYNC_DSB && state->dsb==UINT64_MAX) ||
        (r.kind==OCNEXT_A64_SYNC_ISB &&
         (state->isb==UINT64_MAX || state->instruction_epoch==UINT64_MAX)))
        return OCNEXT_A64_SYNC_FAILED;
    atomic_thread_fence(memory_order_seq_cst);
    ++state->events;++state->host_fences;
    if(r.kind==OCNEXT_A64_SYNC_DMB)++state->dmb;
    else if(r.kind==OCNEXT_A64_SYNC_DSB)++state->dsb;
    else {++state->isb;++state->instruction_epoch;}
    copy_bytes(&state->last,&r,sizeof(r));
    return OCNEXT_A64_SYNC_COMPLETED;
}
