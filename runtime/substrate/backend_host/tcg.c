#include "ocnext/backend_tcg.h"
#include "ocnext/sha256.h"

/* This is serialized native bookkeeping, not a callback sandbox. The seal
 * detects accidental state corruption; it is not an authority or a MAC. */
#define TCG_MAGIC UINT64_C(0x31474643544e584f)
#define TCG_PAGES UINT64_C(1024)
struct tcg_frame { uint64_t address,bytes,cookie; };
struct tcg_span { uintptr_t begin,end; };
struct tcg_state {
    uint64_t magic,self,seal;
    struct ocnext_backend_tcg_config config;
    struct ocnext_backend_tcg_provider provider;
    uintptr_t config_address,provider_address;
    struct ocnext_backend_heap_allocation uc,metadata;
    struct ocnext_backend_tcg_result view;
    uint64_t prologue_bytes,epilogue_offset,tb_bytes,search_offset,search_bytes;
    uint64_t next_cookie,active_frame,pending_frame,pending_dispatch,pending_reason;
    uint64_t metadata_state; /*0 none,1 live identity verified,2 retained UNKNOWN */
    struct tcg_frame frames[OCNEXT_BACKEND_TCG_MAX_FRAMES];
    uint64_t reserved[32];
};
_Static_assert(sizeof(void *)==8 && sizeof(size_t)==8 && sizeof(uintptr_t)==8,"native64 TCG");
_Static_assert(sizeof(struct tcg_state)==OCNEXT_BACKEND_TCG_STORAGE_BYTES,"opaque TCG1024");
_Static_assert(offsetof(struct tcg_state,seal)==16,"private diagnostic seal");

static void tc_copy(void *out,const void *in,size_t bytes)
{
    volatile uint8_t *d=out;const volatile uint8_t *s=in;
    while(bytes--)*d++=*s++;
}
static void tc_zero(void *out,size_t bytes)
{volatile uint8_t *p=out;while(bytes--)*p++=0;}
static int tc_empty(const void *in,size_t bytes)
{const volatile uint8_t *p=in;uint8_t b=0;while(bytes--)b|=*p++;return !b;}
static int tc_equal(const void *a,const void *b,size_t bytes)
{
    const volatile uint8_t *x=a,*y=b;uint8_t bits=0;
    while(bytes--)bits|=*x++^*y++;return !bits;
}
static int tc_span(const void *p,uint64_t bytes,uint64_t align,struct tcg_span *s)
{
    uintptr_t a=(uintptr_t)p;
    if(!a || !bytes || !align || a%align || bytes>UINTPTR_MAX-a)return 0;
    s->begin=a;s->end=a+(uintptr_t)bytes;return 1;
}
static int tc_overlap(struct tcg_span a,struct tcg_span b)
{return a.begin<b.end && b.begin<a.end;}
static int tc_power(uint64_t a,uint64_t low,uint64_t high)
{return a>=low && a<=high && !(a&(a-1));}
static uint64_t tc_seal(const struct tcg_state *s)
{
    const uint8_t *p=(const uint8_t *)s;uint64_t h=UINT64_C(14695981039346656037);
    for(size_t i=0;i<sizeof(*s);++i)if(i<16 || i>=24)h=(h^p[i])*UINT64_C(1099511628211);
    return h;
}
static void tc_store(void *storage,struct tcg_state *s)
{s->seal=tc_seal(s);tc_copy(storage,s,sizeof(*s));}
static int tc_config(const struct ocnext_backend_tcg_config *c)
{
    struct tcg_span code;
    return c->abi_version==1 && c->bytes==sizeof(*c) && !c->flags && !c->reserved0 &&
        c->owner_id && c->session_id && c->generation && !c->reserved1 &&
        c->code_bytes==OCNEXT_BACKEND_TCG_CODE_BYTES && tc_span(c->code_base,c->code_bytes,4096,&code);
}
static int tc_provider(const struct ocnext_backend_tcg_provider *p)
{
    struct tcg_span ctx;
    return p->abi_version==1 && p->bytes==sizeof(*p) && p->verify && p->transition &&
        p->lookup && p->allocate && p->release && p->context_bytes>=16 && p->context_bytes<=65536 &&
        tc_span(p->context,p->context_bytes,8,&ctx) && tc_empty(p->reserved,sizeof(p->reserved));
}
static int tc_retained(const struct tcg_state *s,struct tcg_span spans[5])
{
    if(!tc_span((const void *)(uintptr_t)s->self,1024,16,&spans[0]) ||
       !tc_span((const void *)s->config_address,64,8,&spans[1]) ||
       !tc_span((const void *)s->provider_address,96,8,&spans[2]) ||
       !tc_span(s->config.code_base,s->config.code_bytes,4096,&spans[3]) ||
       !tc_span(s->provider.context,s->provider.context_bytes,8,&spans[4]))return 0;
    for(unsigned i=0;i<5;++i)for(unsigned j=0;j<i;++j)
        if(tc_overlap(spans[i],spans[j]))return 0;
    return 1;
}
static int tc_descriptor(const struct ocnext_backend_heap_allocation *d)
{
    struct tcg_span p;
    return d->serial && tc_power(d->alignment,16,UINT64_C(1048576)) &&
        tc_span(d->native,d->requested_bytes,d->alignment,&p);
}
/* Numeric exclusions never read payload bytes, including after release UNKNOWN. */
static int tc_external(const struct tcg_state *s,const void *p,uint64_t bytes)
{
    struct tcg_span out,retained[5],other;
    if(!tc_span(p,bytes,8,&out) || !tc_retained(s,retained))return 0;
    for(unsigned i=0;i<5;++i)if(tc_overlap(out,retained[i]))return 0;
    if(s->uc.native && (!tc_span(s->uc.native,s->uc.requested_bytes,1,&other) || tc_overlap(out,other)))return 0;
    if(s->metadata.native) {
        if(tc_span(s->metadata.native,s->metadata.requested_bytes,1,&other)) {
            if(tc_overlap(out,other))return 0;
        } else if(s->metadata_state!=2 || s->view.phase!=OCNEXT_TCG_QUARANTINE)return 0;
        /* An UNKNOWN/invalid returned descriptor is retained as raw diagnostic
         * fields, not a native object or an accessibility claim. It may have
         * no representable span at all. Keep every representable exclusion,
         * but do not let tainted overflow/zero length make quarantine itself
         * unobservable. No payload read, callback or release follows here. */
    }
    return 1;
}
static int tc_candidate_external(const struct tcg_state *s,const void *native,uint64_t bytes,
    uint64_t alignment,const void *request,const void *out)
{
    struct tcg_span p,retained[5],other;
    if(!tc_span(native,bytes,alignment,&p) ||
       !tc_retained(s,retained))return 0;
    for(unsigned i=0;i<5;++i)if(tc_overlap(p,retained[i]))return 0;
    if(s->uc.native && (!tc_span(s->uc.native,s->uc.requested_bytes,1,&other) || tc_overlap(p,other)))return 0;
    if(request && (!tc_span(request,256,8,&other) || tc_overlap(p,other)))return 0;
    if(out && (!tc_span(out,320,8,&other) || tc_overlap(p,other)))return 0;
    return 1;
}
static int tc_allocation_external(const struct tcg_state *s,
    const struct ocnext_backend_heap_allocation *d,const void *request,const void *out)
{
    return tc_descriptor(d) && tc_candidate_external(s,d->native,d->requested_bytes,d->alignment,request,out);
}
static enum ocnext_backend_tcg_code tc_load(const void *storage,struct tcg_state *s)
{
    struct tcg_span retained[5];
    tc_copy(s,storage,sizeof(*s));
    if(s->magic!=TCG_MAGIC || s->self!=(uint64_t)(uintptr_t)storage || s->seal!=tc_seal(s) ||
       !tc_config(&s->config) || !tc_provider(&s->provider) || !tc_retained(s,retained) ||
       !tc_empty(s->reserved,sizeof(s->reserved)) || s->view.abi_version!=1 || s->view.bytes!=320 ||
       s->view.phase<OCNEXT_TCG_PREPARED || s->view.phase>OCNEXT_TCG_QUARANTINE ||
       s->view.owner_id!=s->config.owner_id || s->view.session_id!=s->config.session_id ||
       s->view.generation!=s->config.generation || s->view.code_base!=(uint64_t)(uintptr_t)s->config.code_base ||
       s->view.code_bytes!=s->config.code_bytes || !s->view.next_sequence || !s->next_cookie ||
       s->view.flags&~UINT32_C(63) || !tc_empty(s->view.reserved,sizeof(s->view.reserved)) ||
       s->view.frame_depth>4 || s->view.native_inflight>1 || s->view.metadata_pins>1 || s->metadata_state>2 ||
       s->view.metadata_native!=(uint64_t)(uintptr_t)s->metadata.native ||
       s->view.metadata_bytes!=s->metadata.requested_bytes || s->view.metadata_serial!=s->metadata.serial)
        return OCNEXT_TCG_STATE;
    if(s->view.phase==OCNEXT_TCG_PREPARED) {
        if(s->view.next_sequence!=1 || s->view.code_epoch || s->uc.native || s->view.frame_depth || s->metadata_state)
            return OCNEXT_TCG_STATE;
    } else if(!tc_descriptor(&s->uc))return OCNEXT_TCG_STATE;
    if(!s->metadata_state && !tc_empty(&s->metadata,sizeof(s->metadata)))return OCNEXT_TCG_STATE;
    if(s->metadata_state==1 && !tc_descriptor(&s->metadata))return OCNEXT_TCG_STATE;
    for(unsigned i=0;i<4;++i) {
        if(i<s->view.frame_depth) {
            struct tcg_span a,uc;
            if(!s->frames[i].cookie || s->frames[i].cookie>=s->next_cookie || s->frames[i].bytes!=256 ||
               !tc_span((const void *)(uintptr_t)s->frames[i].address,256,8,&a) ||
               !tc_span(s->uc.native,s->uc.requested_bytes,1,&uc) || a.begin<uc.begin || a.end>uc.end)
                return OCNEXT_TCG_STATE;
            for(unsigned j=0;j<i;++j) {
                struct tcg_span b;
                if(!tc_span((const void *)(uintptr_t)s->frames[j].address,256,8,&b) || tc_overlap(a,b) ||
                   s->frames[i].cookie==s->frames[j].cookie)return OCNEXT_TCG_STATE;
            }
        } else if(!tc_empty(&s->frames[i],sizeof(s->frames[i])))return OCNEXT_TCG_STATE;
    }
    if(s->view.frame_cookie!=(s->view.frame_depth?s->frames[s->view.frame_depth-1].cookie:0))return OCNEXT_TCG_STATE;
    if(s->view.phase==OCNEXT_TCG_QUARANTINE && s->view.flags)return OCNEXT_TCG_STATE;
    return OCNEXT_TCG_OK;
}
static enum ocnext_backend_tcg_code tc_quarantine(void *storage,struct tcg_state *s)
{
    s->view.phase=OCNEXT_TCG_QUARANTINE;s->view.flags=0;
    ++s->view.next_sequence;tc_store(storage,s);return OCNEXT_TCG_QUARANTINED;
}
static int tc_lookup(const struct tcg_state *s,const struct ocnext_backend_heap_allocation *d)
{
    struct ocnext_backend_heap_allocation actual;tc_zero(&actual,sizeof(actual));
    return s->provider.lookup(s->provider.context,d->native,&actual)==1 && tc_equal(&actual,d,sizeof(actual));
}
static int tc_verify(const struct tcg_state *s,uint32_t mode,uint64_t prefix)
{return s->provider.verify(s->provider.context,mode,prefix)==1;}
static int tc_transition_budget(const struct tcg_state *s,uint64_t steps)
{return steps<=UINT64_MAX-s->view.pte_epoch && steps*TCG_PAGES<=UINT64_MAX-s->view.local_invalidations;}
static enum ocnext_backend_tcg_code tc_transition(void *storage,struct tcg_state *s,
    uint32_t mode,uint64_t prefix,uint32_t previous_phase,unsigned prior_effects)
{
    int code;s->view.phase=OCNEXT_TCG_TRANSITION;tc_store(storage,s);
    code=s->provider.transition(s->provider.context,mode,prefix);
    if(code==OCNEXT_TCG_PROVIDER_NO_EFFECT && !prior_effects) {
        s->view.phase=previous_phase;tc_store(storage,s);return OCNEXT_TCG_PROVIDER;
    }
    if(code!=OCNEXT_TCG_PROVIDER_COMPLETED)return tc_quarantine(storage,s);
    ++s->view.pte_epoch;s->view.local_invalidations+=TCG_PAGES;tc_store(storage,s);
    if(!tc_verify(s,mode,prefix))return tc_quarantine(storage,s);
    return OCNEXT_TCG_OK;
}
static void tc_metadata_set(struct tcg_state *s,const struct ocnext_backend_heap_allocation *d,uint64_t state)
{
    tc_copy(&s->metadata,d,sizeof(*d));s->metadata_state=state;
    s->view.metadata_native=(uint64_t)(uintptr_t)d->native;
    s->view.metadata_bytes=d->requested_bytes;s->view.metadata_serial=d->serial;
    if(state==1)s->view.flags|=OCNEXT_TCG_FLAG_METADATA_KNOWN;
    else s->view.flags&=~OCNEXT_TCG_FLAG_METADATA_KNOWN;
}
static void tc_metadata_clear(struct tcg_state *s)
{
    tc_zero(&s->metadata,sizeof(s->metadata));s->metadata_state=0;
    s->view.metadata_native=0;s->view.metadata_bytes=0;s->view.metadata_serial=0;
    s->view.flags&=~OCNEXT_TCG_FLAG_METADATA_KNOWN;
}
static void tc_code_clear(struct tcg_state *s)
{
    s->view.prefix_bytes=0;s->view.prologue_offset=0;s->view.tb_offset=0;
    s->prologue_bytes=0;s->epilogue_offset=0;s->tb_bytes=0;s->search_offset=0;s->search_bytes=0;
    tc_zero(s->view.code_sha256,32);s->view.flags=0;
}
static void tc_fill(struct tcg_state *s)
{volatile uint8_t *p=s->config.code_base;for(uint64_t i=0;i<s->config.code_bytes;++i)p[i]=0xcc;}
static int tc_range(uint64_t offset,uint64_t bytes,uint64_t prefix)
{return bytes && offset<prefix && bytes<=prefix-offset;}
static int tc_commit_shape(const struct ocnext_backend_tcg_request *r)
{
    uint64_t p=r->payload.commit.prefix_bytes,a=r->payload.commit.prologue_offset;
    uint64_t an=r->payload.commit.prologue_bytes,b=r->payload.commit.tb_offset,bn=r->payload.commit.tb_bytes;
    uint64_t c=r->payload.commit.search_offset,cn=r->payload.commit.search_bytes,e=r->payload.commit.epilogue_offset;
    return p && !(p&4095) && p<=OCNEXT_BACKEND_TCG_CODE_BYTES && tc_range(a,an,p) &&
        e>=a && e-a<an && tc_range(b,bn,p) && b>=a+an && tc_range(c,cn,p) && c>=b+bn;
}
static int tc_request_shape(const struct ocnext_backend_tcg_request *r)
{
    uint32_t allowed=0;
    if(r->abi_version!=1 || r->bytes!=256 || r->flags || r->reserved0 ||
       !tc_empty(r->reserved,sizeof(r->reserved)))return 0;
    switch(r->operation) {
    case OCNEXT_TCG_BIND:case OCNEXT_TCG_ALLOC_METADATA:case OCNEXT_TCG_FRAME_REGISTER:
    case OCNEXT_TCG_METADATA_DONE:allowed=3;break;
    case OCNEXT_TCG_BEGIN:allowed=1;break;
    case OCNEXT_TCG_COMMIT:allowed=255;break;
    case OCNEXT_TCG_ENTER:case OCNEXT_TCG_LEAVE_NORMAL:allowed=7;break;
    case OCNEXT_TCG_MARK_UNWIND:case OCNEXT_TCG_LANDED:allowed=28;break;
    case OCNEXT_TCG_FRAME_EXIT:allowed=4;break;
    case OCNEXT_TCG_DETACH:case OCNEXT_TCG_RETIRE:case OCNEXT_TCG_ABORT_WRITE:case OCNEXT_TCG_CLOSE:break;
    default:return 0;
    }
    for(unsigned i=0;i<20;++i)if(!(allowed&(UINT32_C(1)<<i)) && r->payload.zero[i])return 0;
    return 1;
}

enum ocnext_backend_tcg_code ocnext_backend_tcg_prepare(void *storage,size_t bytes,
    const struct ocnext_backend_tcg_config *config,const struct ocnext_backend_tcg_provider *provider)
{
    struct tcg_state s;struct tcg_span a,b,c,retained[5];
    if(bytes!=1024 || !tc_span(storage,1024,16,&a) || !tc_span(config,64,8,&b) ||
       !tc_span(provider,96,8,&c))return OCNEXT_TCG_ARGUMENT;
    if(tc_overlap(a,b)||tc_overlap(a,c)||tc_overlap(b,c))return OCNEXT_TCG_ALIAS;
    tc_zero(&s,sizeof(s));tc_copy(&s.config,config,64);tc_copy(&s.provider,provider,96);
    s.self=(uint64_t)(uintptr_t)storage;s.config_address=(uintptr_t)config;s.provider_address=(uintptr_t)provider;
    if(!tc_config(&s.config)||!tc_provider(&s.provider))return OCNEXT_TCG_ARGUMENT;
    if(!tc_retained(&s,retained))return OCNEXT_TCG_ALIAS;
    if(!tc_empty(storage,1024))return OCNEXT_TCG_STATE;
    s.magic=TCG_MAGIC;s.next_cookie=1;s.view.abi_version=1;s.view.bytes=320;s.view.phase=OCNEXT_TCG_PREPARED;
    s.view.owner_id=s.config.owner_id;s.view.session_id=s.config.session_id;s.view.generation=s.config.generation;
    s.view.next_sequence=1;s.view.code_base=(uint64_t)(uintptr_t)s.config.code_base;s.view.code_bytes=s.config.code_bytes;
    tc_store(storage,&s);return OCNEXT_TCG_OK;
}

enum ocnext_backend_tcg_code ocnext_backend_tcg_observe(const void *storage,struct ocnext_backend_tcg_result *out)
{
    struct tcg_state s;struct tcg_span a,b;enum ocnext_backend_tcg_code rc;
    if(!tc_span(storage,1024,16,&a)||!tc_span(out,320,8,&b))return OCNEXT_TCG_ARGUMENT;
    if(tc_overlap(a,b))return OCNEXT_TCG_ALIAS;
    rc=tc_load(storage,&s);if(rc!=OCNEXT_TCG_OK)return rc;
    if(!tc_external(&s,out,320))return OCNEXT_TCG_ALIAS;
    tc_copy(out,&s.view,320);return OCNEXT_TCG_OK;
}

enum ocnext_backend_tcg_code ocnext_backend_tcg_execute(void *storage,
    const struct ocnext_backend_tcg_request *request,struct ocnext_backend_tcg_result *out)
{
    struct tcg_state s;struct ocnext_backend_tcg_request r;struct tcg_span a,b,c;
    enum ocnext_backend_tcg_code rc;uint32_t phase;uint64_t op;int code;
    if(!tc_span(storage,1024,16,&a)||!tc_span(request,256,8,&b)||!tc_span(out,320,8,&c))return OCNEXT_TCG_ARGUMENT;
    if(tc_overlap(a,b)||tc_overlap(a,c)||tc_overlap(b,c))return OCNEXT_TCG_ALIAS;
    rc=tc_load(storage,&s);if(rc!=OCNEXT_TCG_OK)return rc;
    if(!tc_external(&s,request,256)||!tc_external(&s,out,320))return OCNEXT_TCG_ALIAS;
    tc_copy(&r,request,256);if(!tc_request_shape(&r))return OCNEXT_TCG_ARGUMENT;
    if(r.owner_id!=s.config.owner_id || r.session_id!=s.config.session_id)return OCNEXT_TCG_BINDING;
    if(r.generation!=s.config.generation || r.code_epoch!=s.view.code_epoch || r.sequence!=s.view.next_sequence)
        return OCNEXT_TCG_STALE;
    if(s.view.phase==OCNEXT_TCG_QUARANTINE)return OCNEXT_TCG_QUARANTINED;
    if(s.view.phase==OCNEXT_TCG_CLOSED)return OCNEXT_TCG_STATE;
    if(s.view.phase==OCNEXT_TCG_TRANSITION)return OCNEXT_TCG_BUSY;
    if(s.view.next_sequence==UINT64_MAX)return OCNEXT_TCG_QUOTA;
    if(!tc_equal((const void *)s.config_address,&s.config,64) ||
       !tc_equal((const void *)s.provider_address,&s.provider,96))return OCNEXT_TCG_BINDING;
    op=r.operation;phase=s.view.phase;
    /* Complete argument/semantic preflight precedes provider callbacks. */
    switch(op) {
    case OCNEXT_TCG_BIND:
        if(phase!=OCNEXT_TCG_PREPARED)return OCNEXT_TCG_STATE;
        if(!r.payload.bind.native_engine || !r.payload.bind.native_engine_bytes)return OCNEXT_TCG_ARGUMENT;
        if(!tc_span((const void *)(uintptr_t)r.payload.bind.native_engine,r.payload.bind.native_engine_bytes,16,&a))
            return OCNEXT_TCG_BOUNDS;
        if(!tc_candidate_external(&s,(const void *)(uintptr_t)r.payload.bind.native_engine,
                r.payload.bind.native_engine_bytes,16,request,out))return OCNEXT_TCG_ALIAS;
        break;
    case OCNEXT_TCG_BEGIN:
        if(r.payload.begin.requested_bytes!=OCNEXT_BACKEND_TCG_CODE_BYTES)return OCNEXT_TCG_ARGUMENT;
        if(phase!=OCNEXT_TCG_IDLE)return OCNEXT_TCG_STATE;
        if(s.metadata_state || s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.code_epoch==UINT64_MAX || s.view.begins==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_ALLOC_METADATA:
        if(r.payload.allocation.bytes<16 || r.payload.allocation.bytes>4096 ||
           !tc_power(r.payload.allocation.alignment,16,64))return OCNEXT_TCG_ARGUMENT;
        if(phase!=OCNEXT_TCG_WRITING || s.metadata_state)return OCNEXT_TCG_STATE;
        if(s.view.allocations==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_COMMIT:
        if(!tc_commit_shape(&r))return OCNEXT_TCG_BOUNDS;
        if(phase!=OCNEXT_TCG_WRITING || s.metadata_state!=1 || s.view.flags&OCNEXT_TCG_FLAG_DETACHED)
            return OCNEXT_TCG_STATE;
        if(s.pending_frame || s.view.native_inflight || s.view.metadata_pins)return OCNEXT_TCG_BUSY;
        if(s.view.commits==UINT64_MAX || !tc_transition_budget(&s,2))return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_FRAME_REGISTER:
        if(phase==OCNEXT_TCG_PREPARED)return OCNEXT_TCG_STATE;
        if(r.payload.frame.bytes!=256 || !tc_span((const void *)(uintptr_t)r.payload.frame.address,256,8,&a))
            return OCNEXT_TCG_BOUNDS;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.frame_depth==4 || s.next_cookie==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        if(!tc_span(s.uc.native,s.uc.requested_bytes,1,&b) || a.begin<b.begin || a.end>b.end)return OCNEXT_TCG_BOUNDS;
        for(unsigned i=0;i<s.view.frame_depth;++i) {
            if(!tc_span((const void *)(uintptr_t)s.frames[i].address,256,8,&b)||tc_overlap(a,b))return OCNEXT_TCG_ALIAS;
        }
        break;
    case OCNEXT_TCG_ENTER:
        if(phase!=OCNEXT_TCG_PUBLISHED || !(s.view.flags&OCNEXT_TCG_FLAG_DIRECTORY))return OCNEXT_TCG_STATE;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(!s.view.frame_depth || r.payload.enter.frame_cookie!=s.view.frame_cookie)return OCNEXT_TCG_STALE;
        if(r.payload.enter.prologue_offset!=s.view.prologue_offset || r.payload.enter.tb_offset!=s.view.tb_offset)
            return OCNEXT_TCG_BINDING;
        if(s.view.enters==UINT64_MAX || s.next_cookie==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_LEAVE_NORMAL:
        if(!s.view.native_inflight || !s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_STATE;
        if(r.payload.leave.frame_cookie!=s.active_frame ||
           r.payload.leave.dispatch_cookie!=s.view.dispatch_cookie)return OCNEXT_TCG_STALE;
        if(s.view.normal_returns==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_MARK_UNWIND:
        if(!s.view.frame_depth || s.pending_frame || phase==OCNEXT_TCG_PREPARED)return OCNEXT_TCG_STATE;
        if(r.payload.frame.reason==0 || r.payload.frame.reason>INT32_MAX)return OCNEXT_TCG_ARGUMENT;
        if(r.payload.frame.frame_cookie!=s.view.frame_cookie ||
           r.payload.frame.dispatch_cookie!=(s.view.native_inflight?s.view.dispatch_cookie:0))return OCNEXT_TCG_STALE;
        break;
    case OCNEXT_TCG_LANDED:
        if(!s.pending_frame)return OCNEXT_TCG_STATE;
        if(s.view.landings==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_METADATA_DONE:
        if(s.view.native_inflight || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(!s.view.metadata_pins)return OCNEXT_TCG_STATE;
        if(r.payload.metadata.frame_cookie!=s.active_frame || r.payload.metadata.metadata_cookie!=s.view.metadata_cookie)
            return OCNEXT_TCG_STALE;
        break;
    case OCNEXT_TCG_DETACH:
        if((phase!=OCNEXT_TCG_WRITING && phase!=OCNEXT_TCG_PUBLISHED) || s.metadata_state!=1 ||
           s.view.flags&OCNEXT_TCG_FLAG_DETACHED)return OCNEXT_TCG_STATE;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.detaches==UINT64_MAX)return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_RETIRE:
        if(phase!=OCNEXT_TCG_PUBLISHED || s.metadata_state!=1 || !(s.view.flags&OCNEXT_TCG_FLAG_DETACHED))
            return OCNEXT_TCG_STATE;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.retires==UINT64_MAX || s.view.metadata_releases==UINT64_MAX || !tc_transition_budget(&s,2))
            return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_ABORT_WRITE:
        if(phase!=OCNEXT_TCG_WRITING || (s.metadata_state && !(s.view.flags&OCNEXT_TCG_FLAG_DETACHED)))
            return OCNEXT_TCG_STATE;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.aborts==UINT64_MAX || (s.metadata_state && s.view.metadata_releases==UINT64_MAX))return OCNEXT_TCG_QUOTA;
        break;
    case OCNEXT_TCG_FRAME_EXIT:
        if(!s.view.frame_depth || r.payload.frame.frame_cookie!=s.view.frame_cookie)return OCNEXT_TCG_STALE;
        if(s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        break;
    case OCNEXT_TCG_CLOSE:
        if(phase!=OCNEXT_TCG_IDLE || s.metadata_state)return OCNEXT_TCG_STATE;
        if(s.view.frame_depth || s.view.native_inflight || s.view.metadata_pins || s.pending_frame)return OCNEXT_TCG_BUSY;
        if(s.view.closes==UINT64_MAX || !tc_transition_budget(&s,1))return OCNEXT_TCG_QUOTA;
        break;
    default:return OCNEXT_TCG_ARGUMENT;
    }
    if(op!=OCNEXT_TCG_BIND && !tc_lookup(&s,&s.uc))return tc_quarantine(storage,&s);
    switch(op) {
    case OCNEXT_TCG_BIND: {
        struct ocnext_backend_heap_allocation found;tc_zero(&found,sizeof(found));
        if(s.provider.lookup(s.provider.context,(const void *)(uintptr_t)r.payload.bind.native_engine,&found)!=1)
            return OCNEXT_TCG_BINDING;
        if(!tc_descriptor(&found) || (uint64_t)(uintptr_t)found.native!=r.payload.bind.native_engine ||
           found.requested_bytes!=r.payload.bind.native_engine_bytes)return OCNEXT_TCG_BINDING;
        if(!tc_allocation_external(&s,&found,request,out))return OCNEXT_TCG_ALIAS;
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        tc_copy(&s.uc,&found,sizeof(found));s.view.phase=OCNEXT_TCG_IDLE;break;
    }
    case OCNEXT_TCG_BEGIN:
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        s.view.phase=OCNEXT_TCG_TRANSITION;tc_store(storage,&s);tc_fill(&s);tc_code_clear(&s);
        ++s.view.code_epoch;++s.view.begins;s.view.phase=OCNEXT_TCG_WRITING;s.view.flags=OCNEXT_TCG_FLAG_WRITE_LEASE;break;
    case OCNEXT_TCG_ALLOC_METADATA: {
        struct ocnext_backend_heap_allocation found;tc_zero(&found,sizeof(found));
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        s.view.phase=OCNEXT_TCG_TRANSITION;tc_store(storage,&s);
        code=s.provider.allocate(s.provider.context,r.payload.allocation.bytes,r.payload.allocation.alignment,&found);
        if(code==OCNEXT_TCG_PROVIDER_NO_EFFECT) {s.view.phase=phase;tc_store(storage,&s);return OCNEXT_TCG_PROVIDER;}
        /* Retain returned ownership before any lookup or post-allocation check.
         * UNKNOWN never licenses a speculative release or payload read. */
        tc_metadata_set(&s,&found,2);tc_store(storage,&s);
        if(code!=OCNEXT_TCG_PROVIDER_COMPLETED)return tc_quarantine(storage,&s);
        ++s.view.allocations;tc_store(storage,&s);
        if(found.requested_bytes!=r.payload.allocation.bytes || found.alignment!=r.payload.allocation.alignment ||
           !tc_allocation_external(&s,&found,request,out) || !tc_lookup(&s,&found))return tc_quarantine(storage,&s);
        tc_metadata_set(&s,&found,1);s.view.phase=OCNEXT_TCG_WRITING;break;
    }
    case OCNEXT_TCG_COMMIT:
        if(!tc_lookup(&s,&s.metadata))return tc_quarantine(storage,&s);
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        rc=tc_transition(storage,&s,OCNEXT_TCG_RO_NX,0,phase,0);if(rc!=OCNEXT_TCG_OK)return rc;
        s.view.prefix_bytes=r.payload.commit.prefix_bytes;s.view.prologue_offset=r.payload.commit.prologue_offset;
        s.prologue_bytes=r.payload.commit.prologue_bytes;s.epilogue_offset=r.payload.commit.epilogue_offset;
        s.view.tb_offset=r.payload.commit.tb_offset;s.tb_bytes=r.payload.commit.tb_bytes;
        s.search_offset=r.payload.commit.search_offset;s.search_bytes=r.payload.commit.search_bytes;
        if(ocnext_sha256_digest(s.config.code_base,(size_t)s.view.prefix_bytes,s.view.code_sha256)!=0)
            return tc_quarantine(storage,&s);
        rc=tc_transition(storage,&s,OCNEXT_TCG_RX_PREFIX,s.view.prefix_bytes,phase,1);if(rc!=OCNEXT_TCG_OK)return rc;
        s.view.phase=OCNEXT_TCG_PUBLISHED;s.view.flags=OCNEXT_TCG_FLAG_DIGEST_KNOWN|
            OCNEXT_TCG_FLAG_DIRECTORY|OCNEXT_TCG_FLAG_METADATA_KNOWN;++s.view.commits;break;
    case OCNEXT_TCG_FRAME_REGISTER: {
        struct tcg_frame *f=&s.frames[s.view.frame_depth++];
        f->address=r.payload.frame.address;f->bytes=256;f->cookie=s.next_cookie++;
        s.view.frame_cookie=f->cookie;break;
    }
    case OCNEXT_TCG_ENTER: {
        uint8_t digest[32];
        if(!tc_lookup(&s,&s.metadata))return tc_quarantine(storage,&s);
        if(!tc_verify(&s,OCNEXT_TCG_RX_PREFIX,s.view.prefix_bytes))return OCNEXT_TCG_BINDING;
        if(ocnext_sha256_digest(s.config.code_base,(size_t)s.view.prefix_bytes,digest)!=0 ||
           !tc_equal(digest,s.view.code_sha256,32))return OCNEXT_TCG_BINDING;
        s.active_frame=s.view.frame_cookie;s.view.dispatch_cookie=s.next_cookie++;s.view.metadata_cookie=s.view.dispatch_cookie;
        s.view.native_inflight=1;s.view.metadata_pins=1;++s.view.enters;break;
    }
    case OCNEXT_TCG_LEAVE_NORMAL:
        if(r.payload.leave.raw_return && r.payload.leave.raw_return!=((uint64_t)(uintptr_t)s.metadata.native|3))
            return tc_quarantine(storage,&s);
        s.view.native_inflight=0;++s.view.normal_returns;break;
    case OCNEXT_TCG_MARK_UNWIND:
        s.pending_frame=r.payload.frame.frame_cookie;s.pending_dispatch=r.payload.frame.dispatch_cookie;
        s.pending_reason=r.payload.frame.reason;s.view.flags|=OCNEXT_TCG_FLAG_UNWIND_PENDING;break;
    case OCNEXT_TCG_LANDED:
        if(r.payload.frame.frame_cookie!=s.pending_frame || r.payload.frame.dispatch_cookie!=s.pending_dispatch ||
           r.payload.frame.reason!=s.pending_reason)return tc_quarantine(storage,&s);
        if(s.pending_dispatch)s.view.native_inflight=0;
        s.pending_frame=0;s.pending_dispatch=0;s.pending_reason=0;
        s.view.flags&=~OCNEXT_TCG_FLAG_UNWIND_PENDING;++s.view.landings;break;
    case OCNEXT_TCG_METADATA_DONE:
        s.view.metadata_pins=0;s.view.metadata_cookie=0;s.view.dispatch_cookie=0;s.active_frame=0;break;
    case OCNEXT_TCG_DETACH:
        s.view.flags|=OCNEXT_TCG_FLAG_DETACHED;s.view.flags&=~OCNEXT_TCG_FLAG_DIRECTORY;++s.view.detaches;break;
    case OCNEXT_TCG_RETIRE:
        if(!tc_lookup(&s,&s.metadata))return tc_quarantine(storage,&s);
        if(!tc_verify(&s,OCNEXT_TCG_RX_PREFIX,s.view.prefix_bytes))return OCNEXT_TCG_BINDING;
        rc=tc_transition(storage,&s,OCNEXT_TCG_RO_NX,0,phase,0);if(rc!=OCNEXT_TCG_OK)return rc;
        rc=tc_transition(storage,&s,OCNEXT_TCG_RW_NX,0,phase,1);if(rc!=OCNEXT_TCG_OK)return rc;
        code=s.provider.release(s.provider.context,&s.metadata);
        if(code!=OCNEXT_TCG_PROVIDER_COMPLETED) {s.metadata_state=2;return tc_quarantine(storage,&s);}
        ++s.view.metadata_releases;tc_metadata_clear(&s);tc_code_clear(&s);
        s.view.phase=OCNEXT_TCG_IDLE;++s.view.retires;break;
    case OCNEXT_TCG_ABORT_WRITE:
        if(s.metadata_state && !tc_lookup(&s,&s.metadata))return tc_quarantine(storage,&s);
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        s.view.phase=OCNEXT_TCG_TRANSITION;tc_store(storage,&s);
        if(s.metadata_state) {
            code=s.provider.release(s.provider.context,&s.metadata);
            if(code==OCNEXT_TCG_PROVIDER_NO_EFFECT) {s.view.phase=phase;tc_store(storage,&s);return OCNEXT_TCG_PROVIDER;}
            if(code!=OCNEXT_TCG_PROVIDER_COMPLETED) {s.metadata_state=2;return tc_quarantine(storage,&s);}
            ++s.view.metadata_releases;tc_metadata_clear(&s);tc_store(storage,&s);
        }
        tc_fill(&s);tc_code_clear(&s);s.view.phase=OCNEXT_TCG_IDLE;++s.view.aborts;break;
    case OCNEXT_TCG_FRAME_EXIT:
        tc_zero(&s.frames[--s.view.frame_depth],sizeof(s.frames[0]));
        s.view.frame_cookie=s.view.frame_depth?s.frames[s.view.frame_depth-1].cookie:0;break;
    case OCNEXT_TCG_CLOSE:
        if(!tc_verify(&s,OCNEXT_TCG_RW_NX,0))return OCNEXT_TCG_BINDING;
        rc=tc_transition(storage,&s,OCNEXT_TCG_RO_NX,0,phase,0);if(rc!=OCNEXT_TCG_OK)return rc;
        s.view.phase=OCNEXT_TCG_CLOSED;++s.view.closes;break;
    default:return OCNEXT_TCG_ARGUMENT;
    }
    ++s.view.next_sequence;tc_store(storage,&s);tc_copy(out,&s.view,320);return OCNEXT_TCG_OK;
}
