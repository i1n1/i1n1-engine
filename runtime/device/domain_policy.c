#include "ocnext/native_domain.h"
#define ND_MAGIC UINT64_C(0x314e49414d4f444e)
struct nd_edge { uint64_t id,offset,bytes;uint32_t permissions,reserved; };
struct nd_submission { struct ocnext_nd_handle handle;uint64_t queue;
    uint32_t count,state;struct nd_edge edges[OCNEXT_ND_MAX_REFERENCES]; };
struct ocnext_native_domain { uint64_t magic;struct ocnext_nd_config config;
    uint64_t sequence,next_id,events;uint32_t generation,state;
    struct ocnext_nd_resource_info resources[OCNEXT_ND_MAX_RESOURCES];
    struct nd_submission submissions[OCNEXT_ND_MAX_SUBMISSIONS]; };
static void nd_copy(void *out,const void *in,size_t n)
{uint8_t *d=out;const uint8_t *s=in;while(n--)*d++=*s++;}
static void nd_zero(void *out,size_t n) {uint8_t *p=out;while(n--)*p++=0;}
static int nd_empty(const void *in,size_t n)
{const uint8_t *p=in;while(n--)if(*p++)return 0;return 1;}
static int nd_native(const void *p,size_t n)
{return p && n && n<=UINTPTR_MAX-(uintptr_t)p;}
static int nd_object(const void *p,size_t n)
{return nd_native(p,n) && (uintptr_t)p%_Alignof(uint64_t)==0;}
static int nd_alias(const void *a,size_t an,const void *b,size_t bn)
{uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y ? y-x<an : x-y<bn;}
static int nd_range_overlap(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{return a<=b ? b-a<an : a-b<bn;}
static int nd_pending(uint32_t state)
{return state==OCNEXT_ND_PENDING || state==OCNEXT_ND_UNKNOWN;}
static int nd_config(const struct ocnext_nd_config *c)
{
    return c->domain && c->owner && c->session && c->provider && c->generation &&
        c->buffer_byte_quota && c->iova_byte_quota && c->initial_sequence && c->initial_handle_id &&
        c->max_resources && c->max_resources<=OCNEXT_ND_MAX_RESOURCES &&
        c->max_queues && c->max_queues<=OCNEXT_ND_MAX_QUEUES && c->max_queues<=c->max_resources &&
        c->max_submissions && c->max_submissions<=OCNEXT_ND_MAX_SUBMISSIONS &&
        c->address_bits==48 && c->profile==OCNEXT_ND_OFFLINE_POLICY_ONLY &&
        c->abi_version==OCNEXT_NATIVE_DOMAIN_ABI_VERSION && !c->reserved;
}
size_t ocnext_native_domain_storage_size(void) {return sizeof(struct ocnext_native_domain);}
size_t ocnext_native_domain_storage_alignment(void) {return _Alignof(struct ocnext_native_domain);}
struct ocnext_nd_config ocnext_native_domain_default_config(void)
{
    struct ocnext_nd_config c;nd_zero(&c,sizeof(c));
    c.buffer_byte_quota=UINT64_C(1048576);c.iova_byte_quota=UINT64_C(1048576);
    c.initial_sequence=1;c.initial_handle_id=1;c.generation=1;
    c.max_resources=OCNEXT_ND_MAX_RESOURCES;c.max_queues=OCNEXT_ND_MAX_QUEUES;
    c.max_submissions=OCNEXT_ND_MAX_SUBMISSIONS;c.address_bits=48;
    c.profile=OCNEXT_ND_OFFLINE_POLICY_ONLY;c.abi_version=OCNEXT_NATIVE_DOMAIN_ABI_VERSION;return c;
}
struct ocnext_native_domain *ocnext_native_domain_init(void *storage,size_t bytes,
    const struct ocnext_nd_config *config)
{
    struct ocnext_nd_config c;struct ocnext_native_domain *d=storage;
    if(!nd_native(storage,sizeof(*d)) || bytes<sizeof(*d) ||
       (uintptr_t)storage%_Alignof(struct ocnext_native_domain) ||
       !nd_object(config,sizeof(*config)) || nd_alias(storage,sizeof(*d),config,sizeof(*config)))return NULL;
    nd_copy(&c,config,sizeof(c));
    if(!nd_config(&c) || !nd_empty(storage,sizeof(*d)))return NULL;
    d->magic=ND_MAGIC;nd_copy(&d->config,&c,sizeof(c));d->sequence=c.initial_sequence;
    d->next_id=c.initial_handle_id;d->generation=c.generation;d->state=OCNEXT_ND_ACTIVE;return d;
}
enum ocnext_nd_result ocnext_native_domain_validate_span(const struct ocnext_nd_span *s,unsigned bits)
{
    if(!nd_object(s,sizeof(*s)) || !bits || bits>64 ||
       s->namespace_id<OCNEXT_ND_GUEST_VA || s->namespace_id>OCNEXT_ND_GPU_VA)return OCNEXT_ND_ARGUMENT;
    if(!s->permissions || (s->permissions&~3u))return OCNEXT_ND_PERMISSION;
    if(!s->bytes || s->base>UINT64_MAX-s->bytes ||
       (bits<64 && (s->base>=(UINT64_C(1)<<bits) || s->bytes>(UINT64_C(1)<<bits)-s->base)))return OCNEXT_ND_RANGE;
    return OCNEXT_ND_OK;
}
static int nd_find_resource(const struct ocnext_native_domain *d,uint64_t id)
{unsigned i;for(i=0;i<OCNEXT_ND_MAX_RESOURCES;++i)if(d->resources[i].handle.id==id)return (int)i;return -1;}
static int nd_find_submission(const struct ocnext_native_domain *d,uint64_t id)
{unsigned i;for(i=0;i<OCNEXT_ND_MAX_SUBMISSIONS;++i)if(d->submissions[i].handle.id==id)return (int)i;return -1;}
static struct ocnext_nd_handle nd_handle(const struct ocnext_native_domain *d,uint64_t id,unsigned kind)
{
    struct ocnext_nd_handle h;h.id=id;h.domain=d->config.domain;h.generation=d->generation;
    h.kind=kind;h.reserved=0;return h;
}
static enum ocnext_nd_result nd_handle_shape(const struct ocnext_native_domain *d,const struct ocnext_nd_handle *h)
{
    if(!h->id || h->reserved || h->domain!=d->config.domain ||
       h->kind<OCNEXT_ND_BUFFER || h->kind>OCNEXT_ND_SUBMISSION)return OCNEXT_ND_BAD_HANDLE;
    return h->generation==d->generation ? OCNEXT_ND_OK : OCNEXT_ND_STALE;
}
static enum ocnext_nd_result nd_lookup_resource(const struct ocnext_native_domain *d,
    const struct ocnext_nd_handle *h,int *index)
{
    enum ocnext_nd_result result=nd_handle_shape(d,h);int i;
    if(result!=OCNEXT_ND_OK)return result;
    i=nd_find_resource(d,h->id);
    if(i<0 || d->resources[i].handle.kind!=h->kind)return OCNEXT_ND_BAD_HANDLE;
    *index=i;return OCNEXT_ND_OK;
}
static enum ocnext_nd_result nd_lookup_submission(const struct ocnext_native_domain *d,
    const struct ocnext_nd_handle *h,int *index)
{
    enum ocnext_nd_result result=nd_handle_shape(d,h);int i;
    if(result!=OCNEXT_ND_OK)return result;
    i=nd_find_submission(d,h->id);
    if(i<0 || h->kind!=OCNEXT_ND_SUBMISSION)return OCNEXT_ND_BAD_HANDLE;
    *index=i;return OCNEXT_ND_OK;
}
/* Recompute graph counts independently of cached refcounts on every API entry.
 * The bound is32 submissions*8 edges*32 resources, with no provider calls. */
static int nd_valid(const struct ocnext_native_domain *d)
{
    unsigned i,j,k;uint64_t buffers=0,mappings=0;unsigned count=0,queues=0,subs=0,pending=0;
    if(!nd_native(d,sizeof(*d)) || (uintptr_t)d%_Alignof(struct ocnext_native_domain) ||
       d->magic!=ND_MAGIC || !nd_config(&d->config) || !d->generation ||
        !d->sequence || !d->next_id || d->generation<d->config.generation ||
        (d->generation==d->config.generation && d->sequence<d->config.initial_sequence) ||
        d->next_id<d->config.initial_handle_id || d->state<OCNEXT_ND_ACTIVE || d->state>OCNEXT_ND_CLOSED)return 0;
    for(i=0;i<OCNEXT_ND_MAX_RESOURCES;++i) {
        const struct ocnext_nd_resource_info *r=&d->resources[i];unsigned children=0,flight=0;
        if(!r->handle.id) {if(!nd_empty(r,sizeof(*r)))return 0;continue;}
        ++count;
        if(nd_handle_shape(d,&r->handle)!=OCNEXT_ND_OK || r->handle.id>=d->next_id ||
           r->handle.kind==OCNEXT_ND_SUBMISSION || r->reserved ||
           (r->state!=OCNEXT_ND_LIVE && r->state!=OCNEXT_ND_REVOKED))return 0;
        for(j=0;j<i;++j)if(d->resources[j].handle.id==r->handle.id)return 0;
        if(r->handle.kind==OCNEXT_ND_QUEUE) {
            ++queues;if(!nd_empty(&r->span,sizeof(r->span)) || !nd_empty(&r->parent,sizeof(r->parent)) || r->parent_offset)return 0;
        } else {
            if(ocnext_native_domain_validate_span(&r->span,48)!=OCNEXT_ND_OK ||
               r->span.base%OCNEXT_ND_PAGE_BYTES || r->span.bytes%OCNEXT_ND_PAGE_BYTES ||
               r->span.bytes>OCNEXT_ND_MAX_RESOURCE_BYTES)return 0;
            if(r->handle.kind==OCNEXT_ND_BUFFER) {
                if(r->span.namespace_id!=OCNEXT_ND_NATIVE_PA ||
                   !nd_empty(&r->parent,sizeof(r->parent)) || r->parent_offset ||
                   buffers>UINT64_MAX-r->span.bytes)return 0;
                buffers+=r->span.bytes;
            } else {
                int parent=nd_find_resource(d,r->parent.id);
                if(r->span.namespace_id!=OCNEXT_ND_IOVA || nd_handle_shape(d,&r->parent)!=OCNEXT_ND_OK ||
                   r->parent.kind!=OCNEXT_ND_BUFFER || parent<0 ||
                   d->resources[parent].handle.kind!=OCNEXT_ND_BUFFER ||
                   r->parent_offset%OCNEXT_ND_PAGE_BYTES || r->parent_offset>d->resources[parent].span.bytes ||
                   r->span.bytes>d->resources[parent].span.bytes-r->parent_offset ||
                   (r->span.permissions&d->resources[parent].span.permissions)!=r->span.permissions ||
                   mappings>UINT64_MAX-r->span.bytes)return 0;
                mappings+=r->span.bytes;
            }
            for(j=0;j<i;++j)if(d->resources[j].handle.id &&
                d->resources[j].span.namespace_id==r->span.namespace_id &&
                nd_range_overlap(r->span.base,r->span.bytes,d->resources[j].span.base,d->resources[j].span.bytes))return 0;
        }
        for(j=0;j<OCNEXT_ND_MAX_RESOURCES;++j)if(d->resources[j].handle.id && d->resources[j].parent.id==r->handle.id)++children;
        for(j=0;j<OCNEXT_ND_MAX_SUBMISSIONS;++j)if(d->submissions[j].handle.id && nd_pending(d->submissions[j].state)) {
            if(!d->submissions[j].count || d->submissions[j].count>OCNEXT_ND_MAX_REFERENCES)return 0;
            if(d->submissions[j].queue==r->handle.id)++flight;
            for(k=0;k<d->submissions[j].count;++k)if(d->submissions[j].edges[k].id==r->handle.id)++flight;
        }
        if(r->children!=children || r->in_flight!=flight)return 0;
    }
    for(i=0;i<OCNEXT_ND_MAX_SUBMISSIONS;++i) {
        const struct nd_submission *s=&d->submissions[i];int q;
        if(!s->handle.id) {if(!nd_empty(s,sizeof(*s)))return 0;continue;}
        ++subs;
        if(nd_pending(s->state))++pending;
        if(nd_handle_shape(d,&s->handle)!=OCNEXT_ND_OK || s->handle.kind!=OCNEXT_ND_SUBMISSION ||
           s->handle.id>=d->next_id || !s->count || s->count>OCNEXT_ND_MAX_REFERENCES ||
           s->state<OCNEXT_ND_PENDING || s->state>OCNEXT_ND_CANCELLED || nd_find_resource(d,s->handle.id)>=0)return 0;
        for(j=0;j<i;++j)if(d->submissions[j].handle.id==s->handle.id)return 0;
        q=nd_find_resource(d,s->queue);
        if(nd_pending(s->state) && (q<0 || d->resources[q].handle.kind!=OCNEXT_ND_QUEUE))return 0;
        for(j=0;j<OCNEXT_ND_MAX_REFERENCES;++j) {
            const struct nd_edge *edge=&s->edges[j];int r;
            if(j>=s->count) {if(!nd_empty(edge,sizeof(*edge)))return 0;continue;}
            if(!edge->id || edge->reserved || !edge->bytes || !edge->permissions || (edge->permissions&~3u))return 0;
            for(k=0;k<j;++k)if(s->edges[k].id==edge->id)return 0;
            r=nd_find_resource(d,edge->id);
            if(nd_pending(s->state) && (r<0 || d->resources[r].handle.kind==OCNEXT_ND_QUEUE ||
                edge->offset>d->resources[r].span.bytes || edge->bytes>d->resources[r].span.bytes-edge->offset ||
                (edge->permissions&d->resources[r].span.permissions)!=edge->permissions))return 0;
        }
    }
    return count<=d->config.max_resources && queues<=d->config.max_queues && subs<=d->config.max_submissions &&
        buffers<=d->config.buffer_byte_quota && mappings<=d->config.iova_byte_quota &&
        ((d->state!=OCNEXT_ND_QUIESCED && d->state!=OCNEXT_ND_CLOSED) || !pending) &&
        (d->state!=OCNEXT_ND_CLOSED || (!count && !subs));
}
static enum ocnext_nd_result nd_ticket(const struct ocnext_native_domain *d,const struct ocnext_nd_ticket *t)
{
    if(t->abi_version!=OCNEXT_NATIVE_DOMAIN_ABI_VERSION || t->reserved[0] || t->reserved[1])return OCNEXT_ND_ARGUMENT;
    if(t->owner!=d->config.owner || t->session!=d->config.session)return OCNEXT_ND_AUTHORITY;
    if(t->generation!=d->generation)return OCNEXT_ND_STALE;
    if(t->sequence!=d->sequence)return OCNEXT_ND_REPLAY;
    return OCNEXT_ND_OK;
}
static void nd_stats(const struct ocnext_native_domain *d,struct ocnext_nd_stats *s)
{
    unsigned i;nd_zero(s,sizeof(*s));s->generation=d->generation;s->state=d->state;
    s->events=d->events;s->next_sequence=d->sequence;
    for(i=0;i<OCNEXT_ND_MAX_RESOURCES;++i)if(d->resources[i].handle.id) {
        ++s->resources;
        switch(d->resources[i].handle.kind) {
        case OCNEXT_ND_QUEUE:++s->queues;break;
        case OCNEXT_ND_BUFFER:++s->buffers;s->buffer_bytes+=d->resources[i].span.bytes;break;
        default:++s->mappings;s->iova_bytes+=d->resources[i].span.bytes;break;
        }
    }
    for(i=0;i<OCNEXT_ND_MAX_SUBMISSIONS;++i)if(d->submissions[i].handle.id) {
        ++s->submissions;if(nd_pending(d->submissions[i].state))++s->pending;
    }
}
static int nd_query_spans(const struct ocnext_native_domain *d,const struct ocnext_nd_ticket *t,
    const void *extra,size_t extra_n,void *out,size_t out_n)
{
    if(!nd_object(d,sizeof(*d)) || !nd_object(t,sizeof(*t)) || !nd_object(out,out_n) ||
       nd_alias(d,sizeof(*d),t,sizeof(*t)) || nd_alias(d,sizeof(*d),out,out_n) || nd_alias(t,sizeof(*t),out,out_n))return 0;
    if(extra_n && (!nd_object(extra,extra_n) || nd_alias(extra,extra_n,d,sizeof(*d)) ||
       nd_alias(extra,extra_n,t,sizeof(*t)) || nd_alias(extra,extra_n,out,out_n)))return 0;
    return 1;
}
enum ocnext_nd_result ocnext_native_domain_stats(const struct ocnext_native_domain *d,
    const struct ocnext_nd_ticket *t,struct ocnext_nd_stats *out)
{
    struct ocnext_nd_stats staged;enum ocnext_nd_result result;
    if(!nd_query_spans(d,t,NULL,0,out,sizeof(*out)))return OCNEXT_ND_ARGUMENT;
    if(!nd_valid(d))return OCNEXT_ND_CORRUPT;
    result=nd_ticket(d,t);if(result!=OCNEXT_ND_OK)return result;
    nd_stats(d,&staged);nd_copy(out,&staged,sizeof(staged));return OCNEXT_ND_OK;
}
enum ocnext_nd_result ocnext_native_domain_resource(const struct ocnext_native_domain *d,
    const struct ocnext_nd_ticket *t,const struct ocnext_nd_handle *h,struct ocnext_nd_resource_info *out)
{
    int i;enum ocnext_nd_result result;
    if(!nd_query_spans(d,t,h,sizeof(*h),out,sizeof(*out)))return OCNEXT_ND_ARGUMENT;
    if(!nd_valid(d))return OCNEXT_ND_CORRUPT;
    result=nd_ticket(d,t);if(result!=OCNEXT_ND_OK)return result;
    result=nd_lookup_resource(d,h,&i);if(result!=OCNEXT_ND_OK)return result;
    nd_copy(out,&d->resources[i],sizeof(*out));return OCNEXT_ND_OK;
}
enum ocnext_nd_result ocnext_native_domain_submission(const struct ocnext_native_domain *d,
    const struct ocnext_nd_ticket *t,const struct ocnext_nd_handle *h,struct ocnext_nd_submission_info *out)
{
    int i;struct ocnext_nd_submission_info staged;enum ocnext_nd_result result;
    if(!nd_query_spans(d,t,h,sizeof(*h),out,sizeof(*out)))return OCNEXT_ND_ARGUMENT;
    if(!nd_valid(d))return OCNEXT_ND_CORRUPT;
    result=nd_ticket(d,t);if(result!=OCNEXT_ND_OK)return result;
    result=nd_lookup_submission(d,h,&i);if(result!=OCNEXT_ND_OK)return result;
    nd_zero(&staged,sizeof(staged));staged.handle=d->submissions[i].handle;
    staged.queue=nd_handle(d,d->submissions[i].queue,OCNEXT_ND_QUEUE);
    staged.reference_count=d->submissions[i].count;staged.state=d->submissions[i].state;
    nd_copy(out,&staged,sizeof(staged));return OCNEXT_ND_OK;
}
static int nd_command_shape(const struct ocnext_nd_command *c)
{
    struct ocnext_nd_command rest;unsigned i;
    if(c->abi_version!=OCNEXT_NATIVE_DOMAIN_ABI_VERSION || c->reserved ||
       c->op<OCNEXT_ND_DECLARE_BUFFER || c->op>OCNEXT_ND_CLOSE || c->reference_count>OCNEXT_ND_MAX_REFERENCES)return 0;
    nd_copy(&rest,c,sizeof(rest));rest.abi_version=0;rest.op=0;
    if(c->op==OCNEXT_ND_DECLARE_BUFFER || c->op==OCNEXT_ND_DECLARE_MAPPING)nd_zero(&rest.span,sizeof(rest.span));
    if(c->op==OCNEXT_ND_DECLARE_MAPPING) {nd_zero(&rest.parent,sizeof(rest.parent));rest.parent_offset=0;}
    if(c->op>=OCNEXT_ND_REVOKE && c->op<=OCNEXT_ND_COMPLETE)nd_zero(&rest.target,sizeof(rest.target));
    if(c->op==OCNEXT_ND_SUBMIT) {
        if(!c->reference_count)return 0;
        for(i=0;i<c->reference_count;++i)nd_zero(&rest.references[i],sizeof(rest.references[i]));
        rest.reference_count=0;
    }
    if(c->op==OCNEXT_ND_COMPLETE || c->op==OCNEXT_ND_QUIESCE_RESULT)nd_zero(&rest.evidence,sizeof(rest.evidence));
    return nd_empty(&rest,sizeof(rest));
}
static int nd_evidence(const struct ocnext_native_domain *d,const struct ocnext_nd_evidence *e,
    const struct ocnext_nd_handle *submission)
{
    return e->issuer==d->config.provider && e->domain==d->config.domain &&
        e->owner==d->config.owner && e->session==d->config.session && e->generation==d->generation &&
        e->scope==OCNEXT_ND_OFFLINE_POLICY_ONLY && !e->reserved &&
        e->outcome>=OCNEXT_ND_PROVEN_FINISHED && e->outcome<=OCNEXT_ND_PROVIDER_UNKNOWN &&
        (submission ? e->submission_id==submission->id && e->submission_generation==submission->generation :
         !e->submission_id && !e->submission_generation);
}
static void nd_finish(struct ocnext_native_domain *d,struct nd_submission *s,unsigned state)
{
    unsigned i;int q=nd_find_resource(d,s->queue);--d->resources[q].in_flight;
    for(i=0;i<s->count;++i) {int r=nd_find_resource(d,s->edges[i].id);--d->resources[r].in_flight;}
    s->state=state;
}
enum ocnext_nd_result ocnext_native_domain_apply(struct ocnext_native_domain *d,
    const struct ocnext_nd_ticket *ticket,const struct ocnext_nd_command *input,struct ocnext_nd_reply *out)
{
    struct ocnext_nd_command c;struct ocnext_nd_reply reply;struct ocnext_nd_stats stats;
    enum ocnext_nd_result result;int index=-1,parent=-1;unsigned i,j;int free_resource=-1,free_submission=-1;
    int ref_index[OCNEXT_ND_MAX_REFERENCES];struct ocnext_nd_handle produced;
    if(!nd_query_spans(d,ticket,input,sizeof(*input),out,sizeof(*out)))return OCNEXT_ND_ARGUMENT;
    if(!nd_valid(d))return OCNEXT_ND_CORRUPT;
    result=nd_ticket(d,ticket);if(result!=OCNEXT_ND_OK)return result;
    nd_copy(&c,input,sizeof(c));if(!nd_command_shape(&c))return OCNEXT_ND_ARGUMENT;
    if(d->state==OCNEXT_ND_CLOSED)return OCNEXT_ND_BAD_STATE;
    if(d->sequence==UINT64_MAX || d->events==UINT64_MAX)return OCNEXT_ND_EXHAUSTED;
    nd_stats(d,&stats);nd_zero(&produced,sizeof(produced));
    if(c.op<=OCNEXT_ND_DECLARE_QUEUE || c.op==OCNEXT_ND_SUBMIT) {
        if(d->state!=OCNEXT_ND_ACTIVE)return OCNEXT_ND_BAD_STATE;
        if(d->next_id==UINT64_MAX)return OCNEXT_ND_EXHAUSTED;
    }
    if(c.op<=OCNEXT_ND_DECLARE_QUEUE) {
        if(stats.resources>=d->config.max_resources)return OCNEXT_ND_QUOTA;
        for(i=0;i<OCNEXT_ND_MAX_RESOURCES;++i)if(!d->resources[i].handle.id) {free_resource=(int)i;break;}
        if(free_resource<0)return OCNEXT_ND_QUOTA;
        if(c.op==OCNEXT_ND_DECLARE_QUEUE) {if(stats.queues>=d->config.max_queues)return OCNEXT_ND_QUOTA;}
        else {
            result=ocnext_native_domain_validate_span(&c.span,48);if(result!=OCNEXT_ND_OK)return result;
            if(c.span.base%OCNEXT_ND_PAGE_BYTES || c.span.bytes%OCNEXT_ND_PAGE_BYTES ||
               c.span.bytes>OCNEXT_ND_MAX_RESOURCE_BYTES)return OCNEXT_ND_RANGE;
            if(c.span.namespace_id!=(c.op==OCNEXT_ND_DECLARE_BUFFER ? OCNEXT_ND_NATIVE_PA : OCNEXT_ND_IOVA))return OCNEXT_ND_UNSUPPORTED;
            for(i=0;i<OCNEXT_ND_MAX_RESOURCES;++i)if(d->resources[i].handle.id &&
                d->resources[i].span.namespace_id==c.span.namespace_id &&
                nd_range_overlap(c.span.base,c.span.bytes,d->resources[i].span.base,d->resources[i].span.bytes))return OCNEXT_ND_RANGE;
            if(c.op==OCNEXT_ND_DECLARE_BUFFER) {
                if(c.span.bytes>d->config.buffer_byte_quota-stats.buffer_bytes)return OCNEXT_ND_QUOTA;
            } else {
                result=nd_lookup_resource(d,&c.parent,&parent);if(result!=OCNEXT_ND_OK)return result;
                if(c.parent.kind!=OCNEXT_ND_BUFFER)return OCNEXT_ND_BAD_HANDLE;
                if(d->resources[parent].state!=OCNEXT_ND_LIVE)return OCNEXT_ND_BAD_STATE;
                if(c.parent_offset%OCNEXT_ND_PAGE_BYTES || c.parent_offset>d->resources[parent].span.bytes ||
                   c.span.bytes>d->resources[parent].span.bytes-c.parent_offset)return OCNEXT_ND_RANGE;
                if((c.span.permissions&d->resources[parent].span.permissions)!=c.span.permissions)return OCNEXT_ND_PERMISSION;
                if(c.span.bytes>d->config.iova_byte_quota-stats.iova_bytes)return OCNEXT_ND_QUOTA;
                if(d->resources[parent].children==UINT32_MAX)return OCNEXT_ND_EXHAUSTED;
            }
        }
        produced=nd_handle(d,d->next_id,c.op);
    } else if(c.op==OCNEXT_ND_REVOKE || c.op==OCNEXT_ND_RELEASE) {
        if(c.target.kind==OCNEXT_ND_SUBMISSION) {
            if(c.op!=OCNEXT_ND_RELEASE)return OCNEXT_ND_UNSUPPORTED;
            result=nd_lookup_submission(d,&c.target,&index);if(result!=OCNEXT_ND_OK)return result;
            if(nd_pending(d->submissions[index].state))return OCNEXT_ND_BUSY;
        } else {
            result=nd_lookup_resource(d,&c.target,&index);if(result!=OCNEXT_ND_OK)return result;
            if(c.op==OCNEXT_ND_REVOKE && d->resources[index].state==OCNEXT_ND_REVOKED)return OCNEXT_ND_BAD_STATE;
            if(c.op==OCNEXT_ND_RELEASE && (d->resources[index].in_flight || d->resources[index].children))return OCNEXT_ND_BUSY;
        }
        if(c.op==OCNEXT_ND_RELEASE && d->state!=OCNEXT_ND_ACTIVE && d->state!=OCNEXT_ND_QUIESCED)return OCNEXT_ND_BAD_STATE;
    } else if(c.op==OCNEXT_ND_SUBMIT) {
        result=nd_lookup_resource(d,&c.target,&index);if(result!=OCNEXT_ND_OK)return result;
        if(c.target.kind!=OCNEXT_ND_QUEUE)return OCNEXT_ND_BAD_HANDLE;
        if(d->resources[index].state!=OCNEXT_ND_LIVE)return OCNEXT_ND_BAD_STATE;
        if(stats.submissions>=d->config.max_submissions)return OCNEXT_ND_QUOTA;
        for(i=0;i<OCNEXT_ND_MAX_SUBMISSIONS;++i)if(!d->submissions[i].handle.id) {free_submission=(int)i;break;}
        if(free_submission<0)return OCNEXT_ND_QUOTA;
        for(i=0;i<c.reference_count;++i) {
            const struct ocnext_nd_reference *ref=&c.references[i];int r;
            if(ref->reserved)return OCNEXT_ND_ARGUMENT;
            result=nd_lookup_resource(d,&ref->handle,&r);if(result!=OCNEXT_ND_OK)return result;
            if(ref->handle.kind!=OCNEXT_ND_BUFFER && ref->handle.kind!=OCNEXT_ND_MAPPING)return OCNEXT_ND_BAD_HANDLE;
            if(d->resources[r].state!=OCNEXT_ND_LIVE)return OCNEXT_ND_BAD_STATE;
            if(ref->handle.kind==OCNEXT_ND_MAPPING) {
                int p=nd_find_resource(d,d->resources[r].parent.id);
                if(d->resources[p].state!=OCNEXT_ND_LIVE)return OCNEXT_ND_BAD_STATE;
            }
            if(!ref->bytes || ref->offset>d->resources[r].span.bytes ||
               ref->bytes>d->resources[r].span.bytes-ref->offset)return OCNEXT_ND_RANGE;
            if(!ref->permissions || (ref->permissions&~3u) ||
               (ref->permissions&d->resources[r].span.permissions)!=ref->permissions)return OCNEXT_ND_PERMISSION;
            for(j=0;j<i;++j)if(c.references[j].handle.id==ref->handle.id)return OCNEXT_ND_ARGUMENT;
            if(d->resources[r].in_flight==UINT32_MAX)return OCNEXT_ND_EXHAUSTED;
            ref_index[i]=r;
        }
        if(d->resources[index].in_flight==UINT32_MAX)return OCNEXT_ND_EXHAUSTED;
        produced=nd_handle(d,d->next_id,OCNEXT_ND_SUBMISSION);
    } else if(c.op==OCNEXT_ND_COMPLETE) {
        result=nd_lookup_submission(d,&c.target,&index);if(result!=OCNEXT_ND_OK)return result;
        if(!nd_pending(d->submissions[index].state))return OCNEXT_ND_BAD_STATE;
        if(!nd_evidence(d,&c.evidence,&c.target))return OCNEXT_ND_BAD_EVIDENCE;
    } else if(c.op==OCNEXT_ND_BEGIN_QUIESCE) {
        if(d->state!=OCNEXT_ND_ACTIVE && d->state!=OCNEXT_ND_QUARANTINED)return OCNEXT_ND_BAD_STATE;
    } else if(c.op==OCNEXT_ND_QUIESCE_RESULT) {
        if(d->state!=OCNEXT_ND_QUIESCING || !nd_evidence(d,&c.evidence,NULL))return OCNEXT_ND_BAD_EVIDENCE;
    } else {
        if(d->state!=OCNEXT_ND_QUIESCED)return OCNEXT_ND_BAD_STATE;
        if(c.op==OCNEXT_ND_RESET && d->generation==UINT32_MAX)return OCNEXT_ND_EXHAUSTED;
    }
    /* Every rejection above preserves records, IDs, ticket sequence and output.
     * Commit below cannot allocate, invoke a provider, or fail halfway through. */
    if(c.op<=OCNEXT_ND_DECLARE_QUEUE) {
        struct ocnext_nd_resource_info *r=&d->resources[free_resource];r->handle=produced;
        r->span=c.span;r->parent=c.parent;r->parent_offset=c.parent_offset;r->state=OCNEXT_ND_LIVE;
        if(parent>=0)++d->resources[parent].children;
        ++d->next_id;
    } else if(c.op==OCNEXT_ND_REVOKE)d->resources[index].state=OCNEXT_ND_REVOKED;
    else if(c.op==OCNEXT_ND_RELEASE) {
        if(c.target.kind==OCNEXT_ND_SUBMISSION)nd_zero(&d->submissions[index],sizeof(d->submissions[index]));
        else {
            if(c.target.kind==OCNEXT_ND_MAPPING) {int p=nd_find_resource(d,d->resources[index].parent.id);--d->resources[p].children;}
            nd_zero(&d->resources[index],sizeof(d->resources[index]));
        }
    } else if(c.op==OCNEXT_ND_SUBMIT) {
        struct nd_submission *s=&d->submissions[free_submission];s->handle=produced;
        s->queue=c.target.id;s->count=c.reference_count;s->state=OCNEXT_ND_PENDING;
        ++d->resources[index].in_flight;
        for(i=0;i<c.reference_count;++i) {
            s->edges[i].id=c.references[i].handle.id;s->edges[i].offset=c.references[i].offset;
            s->edges[i].bytes=c.references[i].bytes;s->edges[i].permissions=c.references[i].permissions;
            ++d->resources[ref_index[i]].in_flight;
        }
        ++d->next_id;
    } else if(c.op==OCNEXT_ND_COMPLETE) {
        if(c.evidence.outcome==OCNEXT_ND_PROVIDER_UNKNOWN) {
            d->submissions[index].state=OCNEXT_ND_UNKNOWN;d->state=OCNEXT_ND_QUARANTINED;
        } else nd_finish(d,&d->submissions[index],c.evidence.outcome==OCNEXT_ND_PROVEN_FINISHED ?
                       OCNEXT_ND_FINISHED : OCNEXT_ND_FINISHED_FAILED);
    } else if(c.op==OCNEXT_ND_BEGIN_QUIESCE)d->state=OCNEXT_ND_QUIESCING;
    else if(c.op==OCNEXT_ND_QUIESCE_RESULT) {
        if(c.evidence.outcome==OCNEXT_ND_PROVEN_FINISHED) {
            for(i=0;i<OCNEXT_ND_MAX_SUBMISSIONS;++i)if(d->submissions[i].handle.id && nd_pending(d->submissions[i].state))
                nd_finish(d,&d->submissions[i],OCNEXT_ND_CANCELLED);
            d->state=OCNEXT_ND_QUIESCED;
        } else d->state=OCNEXT_ND_QUARANTINED;
    } else {
        nd_zero(d->resources,sizeof(d->resources));nd_zero(d->submissions,sizeof(d->submissions));
        if(c.op==OCNEXT_ND_RESET) {++d->generation;d->state=OCNEXT_ND_ACTIVE;}
        else d->state=OCNEXT_ND_CLOSED;
    }
    ++d->events;
    if(c.op==OCNEXT_ND_RESET)d->sequence=1;else ++d->sequence;
    nd_zero(&reply,sizeof(reply));reply.result=OCNEXT_ND_OK;reply.state=d->state;
    reply.generation=d->generation;reply.handle=produced;reply.next_sequence=d->sequence;reply.events=d->events;
    nd_copy(out,&reply,sizeof(reply));return OCNEXT_ND_OK;
}
