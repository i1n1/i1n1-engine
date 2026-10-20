#include "ocnext/pac_service.h"
#include "ocnext/pac_qarma5.h"

_Static_assert(sizeof(struct ocnext_pac_service_state)==48, "service state ABI1");
_Static_assert(sizeof(struct ocnext_pac_service_request)==208, "service request ABI1");
_Static_assert(sizeof(struct ocnext_pac_service_result)==136, "service result ABI1");
_Static_assert(sizeof(struct ocnext_pac_service_snapshot)==160, "service snapshot ABI1");

struct span { uintptr_t first, last; };

static int span_make(const void *pointer, size_t bytes, struct span *out)
{
    uintptr_t first=(uintptr_t)pointer;
    if (!pointer || !bytes || bytes>UINTPTR_MAX-first) return 0;
    out->first=first; out->last=first+bytes;
    return 1;
}

static int disjoint(const struct span *spans, size_t count)
{
    size_t i,j;
    for (i=0;i<count;i++) for (j=i+1;j<count;j++)
        if (spans[i].first<spans[j].last && spans[j].first<spans[i].last) return 0;
    return 1;
}

static void bytes_copy(void *out, const void *in, size_t count)
{
    unsigned char *d=out; const unsigned char *s=in; size_t i;
    for (i=0;i<count;i++) d[i]=s[i];
}

static int bytes_equal(const void *a, const void *b, size_t count)
{
    const unsigned char *x=a,*y=b; size_t i;
    for (i=0;i<count;i++) if (x[i]!=y[i]) return 0;
    return 1;
}

static int bytes_zero(const void *object, size_t count)
{
    const unsigned char *bytes=object;size_t i;
    for (i=0;i<count;i++) if (bytes[i]) return 0;
    return 1;
}

static void bytes_clear(void *object, size_t count)
{
    volatile unsigned char *bytes=object;size_t i;
    for (i=0;i<count;i++) bytes[i]=0;
}

static int state_valid(const struct ocnext_pac_service_state *state)
{
    return state->abi_version==OCNEXT_PAC_SERVICE_ABI_VERSION &&
        state->bytes==sizeof(*state) && state->profile==OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC &&
        state->reserved==0 && state->owner_id!=0 && state->session_id!=0 &&
        state->epoch!=0 && state->completed_events==state->epoch-1;
}

static int request_valid(const struct ocnext_pac_service_request *request)
{
    size_t i;
    if (request->abi_version!=OCNEXT_PAC_SERVICE_ABI_VERSION || request->bytes!=sizeof(*request) ||
        request->reserved || request->reserved_byte || (request->known_input_mask&~255u) ||
        !(request->known_input_mask&1u) || request->x[0]!=request->function_id ||
        (request->context_known_mask&~OCNEXT_PAC_SERVICE_CONTEXT_ALL) ||
        (request->mmu_known_mask&~31u) || (request->tls_known_mask&~7u)) return 0;
    if (!(request->context_known_mask&OCNEXT_PAC_SERVICE_CONTEXT_PC) && request->pc) return 0;
    if (!(request->context_known_mask&OCNEXT_PAC_SERVICE_CONTEXT_PSTATE) && request->pstate) return 0;
    if (!(request->context_known_mask&OCNEXT_PAC_SERVICE_CONTEXT_EL) && request->current_el) return 0;
    for (i=0;i<5;i++) if (!(request->mmu_known_mask&(1u<<i)) && request->mmu[i]) return 0;
    for (i=0;i<3;i++) if (!(request->tls_known_mask&(1u<<i)) && request->tls[i]) return 0;
    return 1;
}

static enum ocnext_pac_service_result_code ready(
    const struct ocnext_pac_service_snapshot *before,
    const struct ocnext_pac_service_request *request)
{
    if (!state_valid(&before->state) || !request_valid(request)) return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (request->owner_id!=before->state.owner_id || request->session_id!=before->state.session_id ||
        request->expected_epoch!=before->state.epoch) return OCNEXT_PAC_SERVICE_DENIED;
    /* No Apple/private call reaches a provider, even with an explicit key bank. */
    if (request->function_id!=OCNEXT_PAC_SERVICE_SYNTHETIC_MACGA || request->hvc_immediate ||
        !(request->context_known_mask&OCNEXT_PAC_SERVICE_CONTEXT_EL) || request->current_el!=1)
        return OCNEXT_PAC_SERVICE_UNSUPPORTED;
    if (request->known_input_mask!=7u) return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (!ocnext_pac_keys_valid(&before->bank)) return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (before->bank.profile!=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC ||
        !(before->bank.known_mask&(1u<<OCNEXT_PAC_KEY_GA))) return OCNEXT_PAC_SERVICE_UNSUPPORTED;
    if (before->bank.owner_id!=request->owner_id ||
        before->bank.generation!=request->expected_key_generation) return OCNEXT_PAC_SERVICE_DENIED;
    if (before->state.epoch==UINT64_MAX || before->state.completed_events==UINT64_MAX)
        return OCNEXT_PAC_SERVICE_OVERFLOW;
    return OCNEXT_PAC_SERVICE_COMPLETED;
}

enum ocnext_pac_service_result_code ocnext_pac_service_init(
    struct ocnext_pac_service_state *state, uint64_t owner_id, uint64_t session_id)
{
    struct ocnext_pac_service_state next; struct span check;
    if (!span_make(state,sizeof(*state),&check) ||
        (check.first%_Alignof(struct ocnext_pac_service_state)) || !owner_id || !session_id)
        return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (!bytes_zero(state,sizeof(*state))) return OCNEXT_PAC_SERVICE_DENIED;
    bytes_clear(&next,sizeof(next));
    next.abi_version=OCNEXT_PAC_SERVICE_ABI_VERSION;next.bytes=sizeof(next);
    next.profile=OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC;
    next.owner_id=owner_id;next.session_id=session_id;next.epoch=1;
    bytes_copy(state,&next,sizeof(next));
    return OCNEXT_PAC_SERVICE_COMPLETED;
}

enum ocnext_pac_service_result_code ocnext_pac_service_prepare_synthetic(
    const void *context, size_t context_bytes,
    const struct ocnext_pac_service_snapshot *before,
    const struct ocnext_pac_service_request *request,
    struct ocnext_pac_service_result *candidate)
{
    struct span spans[3]; struct ocnext_pac_service_result next;
    enum ocnext_pac_service_result_code code; size_t i;
    if (context || context_bytes || !span_make(before,sizeof(*before),&spans[0]) ||
        !span_make(request,sizeof(*request),&spans[1]) ||
        !span_make(candidate,sizeof(*candidate),&spans[2]) || !disjoint(spans,3) ||
        spans[0].first%_Alignof(struct ocnext_pac_service_snapshot) ||
        spans[1].first%_Alignof(struct ocnext_pac_service_request) ||
        spans[2].first%_Alignof(struct ocnext_pac_service_result)) return OCNEXT_PAC_SERVICE_ARGUMENT;
    code=ready(before,request);if (code!=OCNEXT_PAC_SERVICE_COMPLETED) return code;
    bytes_clear(&next,sizeof(next));
    next.abi_version=OCNEXT_PAC_SERVICE_ABI_VERSION;next.bytes=sizeof(next);
    next.known_output_mask=1;next.clobber_mask=1;
    for (i=0;i<8;i++) next.x[i]=request->x[i];
    next.x[0]=ocnext_pac_qarma5_mac(request->x[1],request->x[2],
        before->bank.keys[OCNEXT_PAC_KEY_GA].lo,before->bank.keys[OCNEXT_PAC_KEY_GA].hi)&UINT64_C(0xffffffff00000000);
    next.owner_id=before->state.owner_id;next.session_id=before->state.session_id;
    next.before_epoch=before->state.epoch;next.after_epoch=before->state.epoch+1;
    next.key_generation=before->bank.generation;next.profile=before->bank.profile;
    bytes_copy(candidate,&next,sizeof(next));
    return OCNEXT_PAC_SERVICE_COMPLETED;
}

enum ocnext_pac_service_result_code ocnext_pac_service_execute(
    struct ocnext_pac_service_state *state, const struct ocnext_pac_key_bank *bank,
    const struct ocnext_pac_service_request *request,
    const struct ocnext_pac_service_provider *provider,
    struct ocnext_pac_service_result *result)
{
    struct span spans[6]; size_t count=5, i;
    struct ocnext_pac_service_snapshot before;
    struct ocnext_pac_service_request copied_request;
    struct ocnext_pac_service_provider copied_provider;
    struct ocnext_pac_service_result candidate, expected;
    struct ocnext_pac_service_state next;
    _Alignas(max_align_t) unsigned char copied_context[OCNEXT_PAC_SERVICE_MAX_CONTEXT];
    enum ocnext_pac_service_result_code code;
    if (!span_make(state,sizeof(*state),&spans[0]) || !span_make(bank,sizeof(*bank),&spans[1]) ||
        !span_make(request,sizeof(*request),&spans[2]) || !span_make(provider,sizeof(*provider),&spans[3]) ||
        !span_make(result,sizeof(*result),&spans[4]) || !disjoint(spans,count)) return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (spans[0].first%_Alignof(struct ocnext_pac_service_state) ||
        spans[1].first%_Alignof(struct ocnext_pac_key_bank) ||
        spans[2].first%_Alignof(struct ocnext_pac_service_request) ||
        spans[3].first%_Alignof(struct ocnext_pac_service_provider) ||
        spans[4].first%_Alignof(struct ocnext_pac_service_result)) return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (provider->abi_version!=OCNEXT_PAC_SERVICE_ABI_VERSION || provider->bytes!=sizeof(*provider) ||
        provider->context_bytes>OCNEXT_PAC_SERVICE_MAX_CONTEXT ||
        (!provider->context && provider->context_bytes) || (provider->context && !provider->context_bytes))
        return OCNEXT_PAC_SERVICE_ARGUMENT;
    if (provider->context_bytes) {
        if (!span_make(provider->context,provider->context_bytes,&spans[5]) || !disjoint(spans,6))
            return OCNEXT_PAC_SERVICE_ARGUMENT;
    }
    bytes_copy(&before.state,state,sizeof(*state));bytes_copy(&before.bank,bank,sizeof(*bank));
    bytes_copy(&copied_request,request,sizeof(*request));bytes_copy(&copied_provider,provider,sizeof(*provider));
    code=ready(&before,&copied_request);if (code!=OCNEXT_PAC_SERVICE_COMPLETED) return code;
    if (!copied_provider.prepare) return OCNEXT_PAC_SERVICE_UNSUPPORTED;
    bytes_clear(&candidate,sizeof(candidate));bytes_clear(&expected,sizeof(expected));
    for (i=0;i<copied_provider.context_bytes;i++) copied_context[i]=((const unsigned char *)copied_provider.context)[i];
    code=copied_provider.prepare(copied_provider.context_bytes ? copied_context : NULL,
        copied_provider.context_bytes,&before,&copied_request,&candidate);
    if (!bytes_equal(&before.state,state,sizeof(*state)) || !bytes_equal(&before.bank,bank,sizeof(*bank)) ||
        !bytes_equal(&copied_request,request,sizeof(*request)) ||
        !bytes_equal(&copied_provider,provider,sizeof(*provider)) ||
        (copied_provider.context_bytes && !bytes_equal(copied_context,copied_provider.context,copied_provider.context_bytes)))
        return OCNEXT_PAC_SERVICE_PROVIDER_FAILED;
    if (code==OCNEXT_PAC_SERVICE_UNSUPPORTED) return code;
    if (code!=OCNEXT_PAC_SERVICE_COMPLETED) return OCNEXT_PAC_SERVICE_PROVIDER_FAILED;
    code=ocnext_pac_service_prepare_synthetic(NULL,0,&before,&copied_request,&expected);
    if (code!=OCNEXT_PAC_SERVICE_COMPLETED || !bytes_equal(&candidate,&expected,sizeof(candidate)))
        return OCNEXT_PAC_SERVICE_PROVIDER_FAILED;
    bytes_copy(&next,&before.state,sizeof(next));next.epoch++;next.completed_events++;
    /* No fallible operations, callback or key/RAM access after publication starts. */
    bytes_copy(state,&next,sizeof(next));bytes_copy(result,&candidate,sizeof(candidate));
    return OCNEXT_PAC_SERVICE_COMPLETED;
}
