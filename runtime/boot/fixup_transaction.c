#include "ocnext/fixup_transaction.h"
#include "ocnext/sha256.h"

#define SIZE(type,bytes) _Static_assert(sizeof(struct type)==bytes,"fixup " #type " ABI1 size")
#define OFFSET(type,field,bytes) _Static_assert(offsetof(struct type,field)==bytes,"fixup " #type " " #field " offset")
SIZE(ocnext_fixup_segment,40);SIZE(ocnext_fixup_candidate,64);SIZE(ocnext_fixup_image,48);
SIZE(ocnext_fixup_request,32);SIZE(ocnext_fixup_capability,160);SIZE(ocnext_fixup_state,112);
SIZE(ocnext_fixup_sign_snapshot,272);SIZE(ocnext_fixup_prepared,48);SIZE(ocnext_fixup_provider,32);
SIZE(ocnext_fixup_result,80);
_Static_assert(sizeof(union ocnext_fixup_workspace)==16384,"fixup workspace ABI1 size");
OFFSET(ocnext_fixup_segment,page_bytes,32);OFFSET(ocnext_fixup_candidate,segment_index,40);
OFFSET(ocnext_fixup_candidate,reserved64,56);OFFSET(ocnext_fixup_image,segments,24);
OFFSET(ocnext_fixup_image,segment_count,32);OFFSET(ocnext_fixup_request,owner_id,8);
OFFSET(ocnext_fixup_capability,bank,32);OFFSET(ocnext_fixup_capability,geometry,144);
OFFSET(ocnext_fixup_state,original_sha256,32);OFFSET(ocnext_fixup_state,working_sha256,64);
OFFSET(ocnext_fixup_state,abi_version,96);OFFSET(ocnext_fixup_sign_snapshot,candidate,160);
OFFSET(ocnext_fixup_sign_snapshot,request,224);OFFSET(ocnext_fixup_sign_snapshot,candidate_index,256);
OFFSET(ocnext_fixup_prepared,candidate_index,32);OFFSET(ocnext_fixup_result,working_sha256,32);
OFFSET(ocnext_fixup_result,abi_version,64);
OFFSET(ocnext_fixup_segment,file_offset,0);OFFSET(ocnext_fixup_segment,file_bytes,8);
OFFSET(ocnext_fixup_segment,image_vm_offset,16);OFFSET(ocnext_fixup_segment,vm_bytes,24);OFFSET(ocnext_fixup_segment,pointer_format,36);
OFFSET(ocnext_fixup_candidate,file_offset,0);OFFSET(ocnext_fixup_candidate,original_word,8);
OFFSET(ocnext_fixup_candidate,resolved_pointer,16);OFFSET(ocnext_fixup_candidate,modifier,24);OFFSET(ocnext_fixup_candidate,image_vm_offset,32);
OFFSET(ocnext_fixup_candidate,flags,44);OFFSET(ocnext_fixup_candidate,key_index,48);OFFSET(ocnext_fixup_candidate,reserved,52);
OFFSET(ocnext_fixup_image,original,0);OFFSET(ocnext_fixup_image,working,8);OFFSET(ocnext_fixup_image,bytes,16);
OFFSET(ocnext_fixup_image,abi_version,36);OFFSET(ocnext_fixup_image,profile,40);OFFSET(ocnext_fixup_image,reserved,44);
OFFSET(ocnext_fixup_request,abi_version,0);OFFSET(ocnext_fixup_request,candidate_count,4);
OFFSET(ocnext_fixup_request,expected_epoch,16);OFFSET(ocnext_fixup_request,expected_key_generation,24);
OFFSET(ocnext_fixup_capability,abi_version,0);OFFSET(ocnext_fixup_capability,profile,4);OFFSET(ocnext_fixup_capability,flags,8);
OFFSET(ocnext_fixup_capability,reserved,12);OFFSET(ocnext_fixup_capability,owner_id,16);OFFSET(ocnext_fixup_capability,key_generation,24);
OFFSET(ocnext_fixup_state,owner_id,0);OFFSET(ocnext_fixup_state,epoch,8);OFFSET(ocnext_fixup_state,commits,16);
OFFSET(ocnext_fixup_state,image_bytes,24);OFFSET(ocnext_fixup_state,profile,100);OFFSET(ocnext_fixup_state,reserved,104);
OFFSET(ocnext_fixup_sign_snapshot,capability,0);OFFSET(ocnext_fixup_sign_snapshot,reserved,260);
OFFSET(ocnext_fixup_prepared,pointer,0);OFFSET(ocnext_fixup_prepared,owner_id,8);OFFSET(ocnext_fixup_prepared,epoch,16);
OFFSET(ocnext_fixup_prepared,key_generation,24);OFFSET(ocnext_fixup_prepared,abi_version,36);OFFSET(ocnext_fixup_prepared,completed,40);OFFSET(ocnext_fixup_prepared,reserved,44);
OFFSET(ocnext_fixup_provider,abi_version,0);OFFSET(ocnext_fixup_provider,bytes,4);OFFSET(ocnext_fixup_provider,prepare,8);
OFFSET(ocnext_fixup_provider,context,16);OFFSET(ocnext_fixup_provider,context_bytes,24);
OFFSET(ocnext_fixup_result,owner_id,0);OFFSET(ocnext_fixup_result,before_epoch,8);OFFSET(ocnext_fixup_result,after_epoch,16);
OFFSET(ocnext_fixup_result,key_generation,24);OFFSET(ocnext_fixup_result,patch_count,68);OFFSET(ocnext_fixup_result,committed_bytes,72);OFFSET(ocnext_fixup_result,reserved,76);

struct span { uintptr_t first,last; };
struct patch { uint64_t offset;uint8_t bytes[8]; };
struct workspace {
    struct ocnext_fixup_state state;
    struct ocnext_fixup_image image;
    struct ocnext_fixup_request request;
    struct ocnext_fixup_capability capability;
    struct ocnext_fixup_provider provider;
    struct ocnext_fixup_segment segments[OCNEXT_FIXUP_MAX_SEGMENTS];
    struct ocnext_fixup_candidate candidates[OCNEXT_FIXUP_MAX_CANDIDATES];
    struct patch patches[OCNEXT_FIXUP_MAX_CANDIDATES];
    struct ocnext_fixup_sign_snapshot snapshot,before_snapshot;
    struct ocnext_fixup_prepared prepared,expected;
    _Alignas(max_align_t) uint8_t context[OCNEXT_FIXUP_MAX_CONTEXT];
    uint8_t before_context[OCNEXT_FIXUP_MAX_CONTEXT];
};
_Static_assert(sizeof(struct workspace)<=OCNEXT_FIXUP_WORKSPACE_BYTES,"fixup bounded internal workspace");
_Static_assert(_Alignof(struct workspace)<=_Alignof(union ocnext_fixup_workspace),"fixup workspace alignment");

static int span_make(const void *p,size_t n,size_t alignment,struct span *out)
{
    uintptr_t first=(uintptr_t)p;
    if(!p || !n || first%alignment || n>UINTPTR_MAX-first)return 0;
    out->first=first;out->last=first+n;return 1;
}
static int disjoint(const struct span *s,size_t n)
{
    size_t i,j;for(i=0;i<n;i++)for(j=i+1;j<n;j++)
        if(s[i].first<s[j].last && s[j].first<s[i].last)return 0;
    return 1;
}
static void copy(void *d,const void *s,size_t n)
{uint8_t *a=d;const uint8_t *b=s;size_t i;for(i=0;i<n;i++)a[i]=b[i];}
static int equal(const void *a,const void *b,size_t n)
{const uint8_t *x=a,*y=b;size_t i;for(i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static void clear(void *p,size_t n)
{volatile uint8_t *b=p;size_t i;for(i=0;i<n;i++)b[i]=0;}
static int zero(const void *p,size_t n)
{const uint8_t *b=p;size_t i;for(i=0;i<n;i++)if(b[i])return 0;return 1;}
static uint64_t read64(const uint8_t *p)
{uint64_t value=0;unsigned i;for(i=0;i<8;i++)value|=(uint64_t)p[i]<<(8*i);return value;}
static void write64(uint8_t *p,uint64_t value)
{unsigned i;for(i=0;i<8;i++)p[i]=(uint8_t)(value>>(8*i));}
static int digest(const uint8_t *p,size_t bytes,const uint8_t expected[32])
{uint8_t actual[32];return ocnext_sha256_digest(p,bytes,actual)==0 && equal(actual,expected,32);}
static int state_valid(const struct ocnext_fixup_state *s)
{
    return s->abi_version==OCNEXT_FIXUP_TRANSACTION_ABI && s->profile==OCNEXT_FIXUP_SYNTHETIC_FORMAT8 &&
        !s->reserved[0] && !s->reserved[1] && s->owner_id && s->epoch &&
        s->commits==s->epoch-1 && s->image_bytes && s->image_bytes<=OCNEXT_FIXUP_MAX_IMAGE_BYTES;
}
static int capability_valid(const struct ocnext_fixup_capability *c)
{
    return c->abi_version==OCNEXT_FIXUP_TRANSACTION_ABI && c->profile==OCNEXT_FIXUP_SYNTHETIC_FORMAT8 &&
        c->flags==(OCNEXT_FIXUP_CAP_SYNTHETIC_SIGNER|OCNEXT_FIXUP_CAP_GEOMETRY_KNOWN) && !c->reserved &&
        c->owner_id && c->key_generation && ocnext_pac_keys_valid(&c->bank) &&
        c->bank.profile==OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC && c->bank.owner_id==c->owner_id &&
        c->bank.generation==c->key_generation && ocnext_pac_pointer_config_valid(&c->geometry);
}

enum ocnext_fixup_code ocnext_fixup_init(
    struct ocnext_fixup_state *state,uint64_t owner,const uint8_t *original,
    uint8_t *working,size_t bytes,const uint8_t expected[32])
{
    struct span s[4];struct ocnext_fixup_state next;
    if(!owner || !bytes || bytes>OCNEXT_FIXUP_MAX_IMAGE_BYTES ||
       !span_make(state,sizeof(*state),_Alignof(struct ocnext_fixup_state),s) ||
       !span_make(original,bytes,1,s+1) || !span_make(working,bytes,1,s+2) ||
       !span_make(expected,32,1,s+3) || !disjoint(s,4))return OCNEXT_FIXUP_ARGUMENT;
    if(!zero(state,sizeof(*state)))return OCNEXT_FIXUP_STALE;
    if(!digest(original,bytes,expected) || !digest(working,bytes,expected))return OCNEXT_FIXUP_DIGEST;
    clear(&next,sizeof(next));next.owner_id=owner;next.epoch=1;next.image_bytes=bytes;
    next.abi_version=OCNEXT_FIXUP_TRANSACTION_ABI;next.profile=OCNEXT_FIXUP_SYNTHETIC_FORMAT8;
    copy(next.original_sha256,expected,32);copy(next.working_sha256,expected,32);
    copy(state,&next,sizeof(next));return OCNEXT_FIXUP_OK;
}

enum ocnext_fixup_code ocnext_fixup_prepare_synthetic(
    const void *context,size_t context_bytes,const struct ocnext_fixup_sign_snapshot *s,
    struct ocnext_fixup_prepared *out)
{
    struct span spans[2];struct ocnext_pac_pointer_request r;struct ocnext_pac_pointer_output signed_value;
    struct ocnext_fixup_prepared next;
    if(context || context_bytes || !span_make(s,sizeof(*s),_Alignof(struct ocnext_fixup_sign_snapshot),spans) ||
       !span_make(out,sizeof(*out),_Alignof(struct ocnext_fixup_prepared),spans+1) || !disjoint(spans,2))return OCNEXT_FIXUP_ARGUMENT;
    if(!capability_valid(&s->capability) || s->request.abi_version!=OCNEXT_FIXUP_TRANSACTION_ABI ||
       !s->request.candidate_count || s->request.candidate_count>OCNEXT_FIXUP_MAX_CANDIDATES ||
       s->candidate_index>=s->request.candidate_count || !zero(s->reserved,sizeof(s->reserved)) ||
       s->candidate.flags!=7u || s->candidate.key_index>OCNEXT_PAC_KEY_DB || s->candidate.reserved || s->candidate.reserved64 ||
       !(s->candidate.original_word>>63) || s->candidate.key_index!=((s->candidate.original_word>>49)&3u))return OCNEXT_FIXUP_UNSUPPORTED;
    if(s->request.owner_id!=s->capability.owner_id ||
       s->request.expected_key_generation!=s->capability.key_generation || !s->request.expected_epoch)return OCNEXT_FIXUP_STALE;
    clear(&r,sizeof(r));r.pointer=s->candidate.resolved_pointer;r.modifier=s->candidate.modifier;
    r.owner_id=s->capability.owner_id;r.generation=s->capability.key_generation;
    r.operation=OCNEXT_PAC_POINTER_SIGN;r.key_index=s->candidate.key_index;r.current_el=1;r.key_enabled=1;
    if(ocnext_pac_pointer_execute(&s->capability.bank,&s->capability.geometry,&r,&signed_value)!=OCNEXT_PAC_POINTER_OK ||
       signed_value.outcome!=OCNEXT_PAC_POINTER_SIGNED || signed_value.esr || signed_value.reserved)return OCNEXT_FIXUP_UNSUPPORTED;
    clear(&next,sizeof(next));next.pointer=signed_value.pointer;next.owner_id=s->request.owner_id;
    next.epoch=s->request.expected_epoch;next.key_generation=s->capability.key_generation;
    next.candidate_index=s->candidate_index;next.abi_version=OCNEXT_FIXUP_TRANSACTION_ABI;next.completed=1;
    copy(out,&next,sizeof(next));return OCNEXT_FIXUP_OK;
}

static enum ocnext_fixup_code metadata(struct workspace *w)
{
    uint32_t i,j;uint64_t bytes=w->image.bytes;
    for(i=0;i<w->image.segment_count;i++){
        const struct ocnext_fixup_segment *s=w->segments+i;
        if((s->page_bytes!=4096 && s->page_bytes!=16384) || s->pointer_format!=8 ||
           !s->vm_bytes || s->file_bytes>s->vm_bytes || s->file_offset>bytes ||
           s->file_bytes>bytes-s->file_offset || s->vm_bytes>UINT64_MAX-s->image_vm_offset)return OCNEXT_FIXUP_BOUNDS;
        for(j=0;j<i;j++){
            const struct ocnext_fixup_segment *b=w->segments+j;
            if((s->file_bytes && b->file_bytes && s->file_offset<b->file_offset+b->file_bytes && b->file_offset<s->file_offset+s->file_bytes) ||
               (s->image_vm_offset<b->image_vm_offset+b->vm_bytes && b->image_vm_offset<s->image_vm_offset+s->vm_bytes))return OCNEXT_FIXUP_METADATA;
        }
    }
    for(i=0;i<w->request.candidate_count;i++){
        const struct ocnext_fixup_candidate *c=w->candidates+i;
        const struct ocnext_fixup_segment *s;uint64_t within,current,next;
        if(c->reserved || c->reserved64 || c->segment_index>=w->image.segment_count ||
           (i && (c->file_offset<=w->candidates[i-1].file_offset || c->file_offset-w->candidates[i-1].file_offset<8)))return OCNEXT_FIXUP_METADATA;
        s=w->segments+c->segment_index;
        if(c->file_offset<s->file_offset)return OCNEXT_FIXUP_BOUNDS;
        within=c->file_offset-s->file_offset;current=within%s->page_bytes;next=(c->original_word>>51)&4095u;
        if(within%4 || s->file_bytes<8 || within>s->file_bytes-8 || within>s->vm_bytes-8 ||
           c->image_vm_offset!=s->image_vm_offset+within)return OCNEXT_FIXUP_BOUNDS;
        if(current>s->page_bytes-4 || (current>s->page_bytes-8 && next) ||
           (next && (next*4>s->page_bytes-4-current || within+next*4>s->file_bytes-8 || within+next*4>s->vm_bytes-8)))return OCNEXT_FIXUP_METADATA;
        if(read64(w->image.original+(size_t)c->file_offset)!=c->original_word ||
           read64(w->image.working+(size_t)c->file_offset)!=c->original_word)return OCNEXT_FIXUP_METADATA;
        if(c->original_word>>63){
            if(c->flags!=7u || c->key_index!=((c->original_word>>49)&3u) ||
               !(w->capability.bank.known_mask&(1u<<c->key_index)))return OCNEXT_FIXUP_UNSUPPORTED;
        }else if(c->flags!=OCNEXT_FIXUP_POINTER_KNOWN || c->modifier || c->key_index)return OCNEXT_FIXUP_UNSUPPORTED;
        w->patches[i].offset=c->file_offset;
        if(!(c->original_word>>63))write64(w->patches[i].bytes,c->resolved_pointer);
        else{
            enum ocnext_fixup_code code;
            clear(&w->snapshot,sizeof(w->snapshot));copy(&w->snapshot.capability,&w->capability,sizeof(w->capability));
            copy(&w->snapshot.candidate,c,sizeof(*c));copy(&w->snapshot.request,&w->request,sizeof(w->request));
            w->snapshot.candidate_index=i;
            code=ocnext_fixup_prepare_synthetic(NULL,0,&w->snapshot,&w->expected);
            if(code!=OCNEXT_FIXUP_OK)return code;
            write64(w->patches[i].bytes,w->expected.pointer);
        }
    }
    return OCNEXT_FIXUP_OK;
}

enum ocnext_fixup_code ocnext_fixup_execute(
    struct ocnext_fixup_state *state,const struct ocnext_fixup_image *image,
    const struct ocnext_fixup_candidate *candidates,const struct ocnext_fixup_request *request,
    const struct ocnext_fixup_capability *capability,const struct ocnext_fixup_provider *provider,
    union ocnext_fixup_workspace *workspace,struct ocnext_fixup_result *result)
{
    struct span spans[13];size_t n=8;struct workspace *w;
    enum ocnext_fixup_code code;uint32_t i;struct ocnext_sha256 prospective;
    struct ocnext_fixup_result next_result;struct ocnext_fixup_state next_state;size_t cursor;
    if(!span_make(state,sizeof(*state),_Alignof(struct ocnext_fixup_state),spans) ||
       !span_make(image,sizeof(*image),_Alignof(struct ocnext_fixup_image),spans+1) ||
       !span_make(request,sizeof(*request),_Alignof(struct ocnext_fixup_request),spans+2) ||
       !span_make(capability,sizeof(*capability),_Alignof(struct ocnext_fixup_capability),spans+3) ||
       !span_make(provider,sizeof(*provider),_Alignof(struct ocnext_fixup_provider),spans+4) ||
       !span_make(workspace,sizeof(*workspace),_Alignof(union ocnext_fixup_workspace),spans+5) ||
       !span_make(result,sizeof(*result),_Alignof(struct ocnext_fixup_result),spans+6) || !disjoint(spans,7))return OCNEXT_FIXUP_ARGUMENT;
    if(!request->candidate_count || request->candidate_count>OCNEXT_FIXUP_MAX_CANDIDATES ||
       !image->segment_count || image->segment_count>OCNEXT_FIXUP_MAX_SEGMENTS || !image->bytes || image->bytes>OCNEXT_FIXUP_MAX_IMAGE_BYTES ||
       provider->context_bytes>OCNEXT_FIXUP_MAX_CONTEXT || (!provider->context!=!provider->context_bytes))return OCNEXT_FIXUP_ARGUMENT;
    if(!span_make(candidates,(size_t)request->candidate_count*sizeof(*candidates),_Alignof(struct ocnext_fixup_candidate),spans+7) ||
       !span_make(image->original,image->bytes,1,spans+8) || !span_make(image->working,image->bytes,1,spans+9) ||
       !span_make(image->segments,(size_t)image->segment_count*sizeof(*image->segments),_Alignof(struct ocnext_fixup_segment),spans+10))return OCNEXT_FIXUP_ARGUMENT;
    n=11;if(provider->context_bytes && !span_make(provider->context,provider->context_bytes,1,spans+n++))return OCNEXT_FIXUP_ARGUMENT;
    if(!disjoint(spans,n))return OCNEXT_FIXUP_ARGUMENT;
    if(!state_valid(state) || request->abi_version!=OCNEXT_FIXUP_TRANSACTION_ABI ||
       image->abi_version!=OCNEXT_FIXUP_TRANSACTION_ABI || image->reserved ||
       provider->abi_version!=OCNEXT_FIXUP_TRANSACTION_ABI || provider->bytes!=sizeof(*provider))return OCNEXT_FIXUP_ARGUMENT;
    if(image->profile!=OCNEXT_FIXUP_SYNTHETIC_FORMAT8 || !capability_valid(capability) || !provider->prepare)return OCNEXT_FIXUP_UNSUPPORTED;
    if(request->owner_id!=state->owner_id || request->expected_epoch!=state->epoch ||
       request->owner_id!=capability->owner_id || request->expected_key_generation!=capability->key_generation ||
       image->bytes!=state->image_bytes)return OCNEXT_FIXUP_STALE;
    if(state->epoch==UINT64_MAX || state->commits==UINT64_MAX)return OCNEXT_FIXUP_OVERFLOW;
    if(!digest(image->original,image->bytes,state->original_sha256) ||
       !digest(image->working,image->bytes,state->working_sha256))return OCNEXT_FIXUP_DIGEST;
    w=(struct workspace *)(void *)workspace->bytes;clear(w,sizeof(*w));
    copy(&w->state,state,sizeof(*state));copy(&w->image,image,sizeof(*image));copy(&w->request,request,sizeof(*request));
    copy(&w->capability,capability,sizeof(*capability));copy(&w->provider,provider,sizeof(*provider));
    copy(w->segments,image->segments,image->segment_count*sizeof(*image->segments));
    copy(w->candidates,candidates,request->candidate_count*sizeof(*candidates));
    if(provider->context_bytes){copy(w->context,provider->context,provider->context_bytes);copy(w->before_context,provider->context,provider->context_bytes);}
    code=metadata(w);if(code!=OCNEXT_FIXUP_OK)return code;
    for(i=0;i<w->request.candidate_count;i++)if(w->candidates[i].flags&OCNEXT_FIXUP_AUTHENTICATED){
        clear(&w->snapshot,sizeof(w->snapshot));copy(&w->snapshot.capability,&w->capability,sizeof(w->capability));
        copy(&w->snapshot.candidate,w->candidates+i,sizeof(w->snapshot.candidate));
        copy(&w->snapshot.request,&w->request,sizeof(w->request));w->snapshot.candidate_index=i;
        copy(&w->before_snapshot,&w->snapshot,sizeof(w->snapshot));clear(&w->prepared,sizeof(w->prepared));
        /* Whole-list semantic/SIGN preflight above precedes every provider.
         * Reconstruct its exact bound result from the independent staged MAC. */
        clear(&w->expected,sizeof(w->expected));w->expected.pointer=read64(w->patches[i].bytes);
        w->expected.owner_id=w->request.owner_id;w->expected.epoch=w->request.expected_epoch;
        w->expected.key_generation=w->capability.key_generation;w->expected.candidate_index=i;
        w->expected.abi_version=OCNEXT_FIXUP_TRANSACTION_ABI;w->expected.completed=1;
        code=w->provider.prepare(w->provider.context_bytes?w->context:NULL,w->provider.context_bytes,&w->snapshot,&w->prepared);
        if(!equal(&w->snapshot,&w->before_snapshot,sizeof(w->snapshot)) ||
           !equal(w->context,w->before_context,w->provider.context_bytes))return OCNEXT_FIXUP_SIGNER_FAILED;
        if(code!=OCNEXT_FIXUP_OK)return code==OCNEXT_FIXUP_UNSUPPORTED?code:OCNEXT_FIXUP_SIGNER_FAILED;
        if(!equal(&w->prepared,&w->expected,sizeof(w->prepared)))return OCNEXT_FIXUP_SIGNER_FAILED;
        write64(w->patches[i].bytes,w->prepared.pointer);
    }
    if(!equal(state,&w->state,sizeof(*state)) || !equal(image,&w->image,sizeof(*image)) ||
       !equal(request,&w->request,sizeof(*request)) || !equal(capability,&w->capability,sizeof(*capability)) ||
       !equal(provider,&w->provider,sizeof(*provider)) || !equal(candidates,w->candidates,request->candidate_count*sizeof(*candidates)) ||
       !equal(image->segments,w->segments,image->segment_count*sizeof(*image->segments)) ||
       (provider->context_bytes && !equal(provider->context,w->before_context,provider->context_bytes)))return OCNEXT_FIXUP_SIGNER_FAILED;
    if(!digest(image->original,image->bytes,state->original_sha256) || !digest(image->working,image->bytes,state->working_sha256))return OCNEXT_FIXUP_SIGNER_FAILED;
    clear(&next_result,sizeof(next_result));cursor=0;
    if(ocnext_sha256_init(&prospective))return OCNEXT_FIXUP_DIGEST;
    for(i=0;i<request->candidate_count;i++){
        size_t offset=(size_t)w->patches[i].offset;
        if(ocnext_sha256_update(&prospective,image->working+cursor,offset-cursor) ||
           ocnext_sha256_update(&prospective,w->patches[i].bytes,8))return OCNEXT_FIXUP_DIGEST;
        cursor=offset+8;
    }
    if(ocnext_sha256_update(&prospective,image->working+cursor,image->bytes-cursor) ||
       ocnext_sha256_final(&prospective,next_result.working_sha256))return OCNEXT_FIXUP_DIGEST;
    next_result.owner_id=state->owner_id;next_result.before_epoch=state->epoch;next_result.after_epoch=state->epoch+1;
    next_result.key_generation=capability->key_generation;next_result.abi_version=OCNEXT_FIXUP_TRANSACTION_ABI;
    next_result.patch_count=request->candidate_count;next_result.committed_bytes=request->candidate_count*8u;
    copy(&next_state,state,sizeof(next_state));next_state.epoch++;next_state.commits++;
    copy(next_state.working_sha256,next_result.working_sha256,32);
    /* Sole logical publication. Every callback/hash/preflight completed above.
     * Serialized valid ordinary native RAM makes these stores non-fallible. */
    for(i=0;i<request->candidate_count;i++)copy(image->working+(size_t)w->patches[i].offset,w->patches[i].bytes,8);
    copy(state,&next_state,sizeof(next_state));copy(result,&next_result,sizeof(next_result));
    return OCNEXT_FIXUP_OK;
}
