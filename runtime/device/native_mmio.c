#include "ocnext/native_mmio.h"
static void nm_copy(void *v,const void *s,size_t n){uint8_t *p=v;const uint8_t *q=s;while(n--)*p++=*q++;}
static void nm_zero(void *v,size_t n){uint8_t *p=v;while(n--)*p++=0;}
static int nm_equal(const void *v,const void *s,size_t n){const uint8_t *p=v,*q=s;while(n--)if(*p++!=*q++)return 0;return 1;}
static int nm_zeroed(const void *v,size_t n){const uint8_t *p=v;while(n--)if(*p++)return 0;return 1;}
static int nm_span(const void *v,size_t n){uintptr_t p=(uintptr_t)v;return v&&!(p&7u)&&n<=UINTPTR_MAX-p;}
static int nm_overlap(const void *a,size_t n,const void *b,size_t m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m&&y<x+n;}
static enum ocnext_native_mmio_status nm_spans(const void *const *p,const size_t *n,unsigned count){
    unsigned i,j;for(i=0;i<count;i++)if(!nm_span(p[i],n[i]))return OCNEXT_MMIO_ARGUMENT;
    for(i=0;i<count;i++)for(j=0;j<i;j++)if(nm_overlap(p[i],n[i],p[j],n[j]))return OCNEXT_MMIO_ALIAS;
    return OCNEXT_MMIO_OK;
}
static uint32_t nm_le32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int nm_binding(const struct ocnext_native_mmio_binding *b){
    const struct ocnext_pci_identity *i=&b->identity;
    return i->abi==1&&i->source_id&&i->capture_id&&i->domain_id&&i->owner_id&&i->session_id&&i->instance_id&&i->generation&&
        !i->segment&&!i->bus&&i->device==5&&!i->function&&i->source_kind==OCNEXT_PCI_SOURCE_QEMU&&!i->reserved&&
        b->channel_id&&b->source_epoch&&b->authority_epoch&&b->issuer_nonce&&b->native_pa&&!(b->native_pa&4095u)&&
        b->native_pa<=UINT32_MAX-4095u&&b->aperture_bytes==OCNEXT_NATIVE_MMIO_APERTURE&&
        b->abi==1&&b->profile==OCNEXT_MMIO_QEMU_TESTDEV&&b->rights==OCNEXT_MMIO_ALL_RIGHTS&&b->cache_policy==OCNEXT_MMIO_CACHE_UC&&
        !nm_zeroed(b->capture_sha256,32)&&!nm_zeroed(b->qemu_source_sha256,32)&&
        !nm_zeroed(b->qemu_binary_sha256,32)&&!nm_zeroed(b->manifest_sha256,32);
}
static int nm_capture(const struct ocnext_native_mmio_claim *c,struct ocnext_pci_snapshot *view){
    const struct ocnext_pci_capture_record *r=c->capture;
    if(ocnext_pci_capture_snapshot(r,view)!=OCNEXT_PCI_CAPTURE_OK)return 0;
    return r->config_bytes==256&&nm_equal(&r->identity,&c->binding.identity,64)&&r->channel_id==c->binding.channel_id&&
        r->source_epoch==c->binding.source_epoch&&nm_equal(r->sha256,c->binding.capture_sha256,32)&&
        r->raw[0]==0x36&&r->raw[1]==0x1b&&r->raw[2]==5&&!r->raw[3]&&!r->raw[14]&&
        (r->raw[4]&2u)&&!(nm_le32(r->raw+16)&15u)&&(uint64_t)nm_le32(r->raw+16)==c->binding.native_pa;
}
enum ocnext_native_mmio_status ocnext_native_mmio_init(const struct ocnext_native_mmio_claim *claim,
    const struct ocnext_native_mmio_issuer *issuer,struct ocnext_native_mmio_workspace *work,
    struct ocnext_native_mmio_state *state){
    const void *p[5]={claim,issuer,work,state,0};
    size_t n[5]={sizeof(*claim),sizeof(*issuer),sizeof(*work),sizeof(*state),sizeof(struct ocnext_pci_capture_record)};
    struct ocnext_native_mmio_issuer authority;enum ocnext_native_mmio_status s;
    s=nm_spans(p,n,4);if(s)return s;p[4]=claim->capture;s=nm_spans(p,n,5);if(s)return s;
    if(claim->abi!=1||claim->reserved||issuer->abi!=1||issuer->profile!=OCNEXT_MMIO_QEMU_TESTDEV||issuer->reserved||
       !issuer->context||!issuer->authorize||!nm_binding(&claim->binding))return OCNEXT_MMIO_ARGUMENT;
    if(!nm_zeroed(state,sizeof(*state)))return OCNEXT_MMIO_STATE;
    if(claim->operation_limit<2||claim->operation_limit>OCNEXT_NATIVE_MMIO_MAX_OPERATIONS||
       claim->callback_limit<70||claim->callback_limit>OCNEXT_NATIVE_MMIO_MAX_CALLBACKS)return OCNEXT_MMIO_QUOTA;
    nm_copy(&authority,issuer,sizeof(authority));nm_copy(&work->claim,claim,sizeof(*claim));
    if(!nm_capture(&work->claim,&work->snapshot))return OCNEXT_MMIO_CAPTURE;
    nm_zero(&work->issued,sizeof(work->issued));
    if(authority.authorize(authority.context,&work->claim,&work->issued)!=1)return OCNEXT_MMIO_AUTHORITY;
    if(!nm_equal(&work->claim,claim,sizeof(*claim))||!nm_equal(issuer,&authority,sizeof(authority))||
       !nm_equal(&work->issued,&claim->binding,sizeof(work->issued))||!nm_zeroed(state,sizeof(*state))||
       !nm_capture(claim,&work->snapshot))return OCNEXT_MMIO_AUTHORITY;
    nm_zero(&work->staged,sizeof(work->staged));nm_copy(&work->staged.binding,&work->issued,sizeof(work->issued));
    work->staged.abi=1;work->staged.phase=OCNEXT_MMIO_READY;work->staged.lease_retained=1;
    work->staged.next_sequence=1;work->staged.operation_limit=claim->operation_limit;work->staged.callback_limit=claim->callback_limit;
    nm_copy(state,&work->staged,sizeof(*state));return OCNEXT_MMIO_OK;
}
static int nm_state(const struct ocnext_native_mmio_state *s){
    return s->abi==1&&nm_binding(&s->binding)&&!s->reserved&&s->phase>=OCNEXT_MMIO_READY&&s->phase<=OCNEXT_MMIO_QUARANTINED&&
        s->counter_known<=1&&s->counter<=OCNEXT_NATIVE_MMIO_MAX_COUNT&&s->lease_retained<=1&&
        s->operation_limit>=2&&s->operation_limit<=OCNEXT_NATIVE_MMIO_MAX_OPERATIONS&&s->callback_limit>=70&&
        s->callback_limit<=OCNEXT_NATIVE_MMIO_MAX_CALLBACKS&&s->used_operations<=s->operation_limit&&
        s->callback_attempts<=s->callback_limit&&s->read_attempts<=s->callback_attempts&&s->write_attempts<=s->callback_attempts&&
        s->read_attempts<=s->callback_attempts-s->write_attempts&&s->successful_operations<=s->used_operations&&
        s->next_sequence==(uint64_t)s->used_operations+1&&s->committed_sequence<s->next_sequence&&
        ((s->phase==OCNEXT_MMIO_CLOSED&&!s->lease_retained&&!s->counter_known)||
         (s->phase!=OCNEXT_MMIO_CLOSED&&s->lease_retained))&&
        (s->phase!=OCNEXT_MMIO_READY||(!s->counter_known&&!s->used_operations&&!s->callback_attempts))&&
        (s->phase!=OCNEXT_MMIO_ARMED||s->counter_known)&&
        (s->phase!=OCNEXT_MMIO_QUARANTINED||!s->counter_known);
}
static enum ocnext_native_mmio_status nm_fail(struct ocnext_native_mmio_state *s,uint64_t raw,
    enum ocnext_native_mmio_status result){s->phase=OCNEXT_MMIO_QUARANTINED;s->lease_retained=1;s->counter_known=0;s->last_status=raw;return result;}
static int nm_observe(struct ocnext_native_mmio_state *state,const struct ocnext_native_mmio_provider *bus,
    struct ocnext_native_mmio_workspace *work){
    int r;nm_zero(&work->observed,sizeof(work->observed));work->raw_status=0;state->callback_attempts++;
    r=bus->observe(bus->context,&work->observed,&work->raw_status);
    if(r!=1||work->raw_status)return 0;
    return nm_equal(&work->observed,&work->staged.binding,sizeof(work->observed))?1:-1;
}
static int nm_header(const uint8_t *h,uint32_t count,int closed){
    static const uint8_t fixed[32]={0,1,0,0,0,8,0,0,0xfa,0,0,0,0,0,0,0,
        'm','m','i','o','-','n','o','-','e','v','e','n','t','f','d',0};
    unsigned i;if(closed)return nm_zeroed(h,32);
    for(i=0;i<32;i++)if((i<12||i>=16)&&h[i]!=fixed[i])return 0;
    return nm_le32(h+12)==count;
}
enum ocnext_native_mmio_status ocnext_native_mmio_execute(struct ocnext_native_mmio_state *state,
    const struct ocnext_native_mmio_request *request,const struct ocnext_native_mmio_provider *provider,
    struct ocnext_native_mmio_workspace *work,struct ocnext_native_mmio_result *out){
    const void *p[5]={state,request,provider,work,out};
    const size_t n[5]={sizeof(*state),sizeof(*request),sizeof(*provider),sizeof(*work),sizeof(*out)};
    struct ocnext_native_mmio_provider bus;enum ocnext_native_mmio_status s;uint32_t needed,expected,op;unsigned i;int r,writing;
    s=nm_spans(p,n,5);if(s)return s;
    if(!nm_state(state))return OCNEXT_MMIO_STATE;
    if(provider->abi!=1||provider->profile!=OCNEXT_MMIO_QEMU_TESTDEV||!provider->context||!provider->observe||!provider->read8||!provider->write8)
        return OCNEXT_MMIO_ARGUMENT;
    if(request->reserved[0]||request->reserved[1])return OCNEXT_MMIO_ARGUMENT;
    if(request->owner_id!=state->binding.identity.owner_id||request->session_id!=state->binding.identity.session_id||
       request->instance_id!=state->binding.identity.instance_id||request->generation!=state->binding.identity.generation||
       request->authority_epoch!=state->binding.authority_epoch)return OCNEXT_MMIO_STALE;
    if(request->sequence!=state->next_sequence||request->sequence==UINT64_MAX)return OCNEXT_MMIO_SEQUENCE;
    op=request->operation;
    if(state->phase==OCNEXT_MMIO_CLOSED||state->phase==OCNEXT_MMIO_QUARANTINED)return OCNEXT_MMIO_STATE;
    if(op<OCNEXT_MMIO_ARM||op>OCNEXT_MMIO_CLOSE)return OCNEXT_MMIO_ARGUMENT;
    if((op==OCNEXT_MMIO_ARM)!=(state->phase==OCNEXT_MMIO_READY))return OCNEXT_MMIO_STATE;
    writing=op!=OCNEXT_MMIO_OBSERVE;needed=writing?35u:34u;
    if(state->used_operations>=state->operation_limit||needed>state->callback_limit-state->callback_attempts)return OCNEXT_MMIO_QUOTA;
    if(op!=OCNEXT_MMIO_CLOSE&&(state->used_operations+1>=state->operation_limit||
       needed+35u>state->callback_limit-state->callback_attempts))return OCNEXT_MMIO_QUOTA;
    if(op==OCNEXT_MMIO_MATCH&&state->counter>=OCNEXT_NATIVE_MMIO_MAX_COUNT)return OCNEXT_MMIO_QUOTA;
    expected=op==OCNEXT_MMIO_ARM||op==OCNEXT_MMIO_CLOSE?0u:state->counter+(op==OCNEXT_MMIO_MATCH?1u:0u);
    nm_copy(&bus,provider,sizeof(bus));nm_copy(&work->request,request,sizeof(*request));nm_copy(&work->staged,state,sizeof(*state));
    nm_zero(&work->result,sizeof(work->result));nm_zero(work->header,sizeof(work->header));
    state->next_sequence++;state->used_operations++;
    r=nm_observe(state,&bus,work);if(r!=1)return nm_fail(state,work->raw_status,r<0?OCNEXT_MMIO_BINDING:OCNEXT_MMIO_PROVIDER);
    if(writing){uint32_t offset=op==OCNEXT_MMIO_ARM||op==OCNEXT_MMIO_CLOSE?0u:2048u;
        uint8_t value=op==OCNEXT_MMIO_MATCH?0xfau:op==OCNEXT_MMIO_CLOSE?255u:0u;
        work->raw_status=0;state->callback_attempts++;state->write_attempts++;
        r=bus.write8(bus.context,offset,value,&work->raw_status);
        if(r!=1||work->raw_status)return nm_fail(state,work->raw_status,OCNEXT_MMIO_PROVIDER);
        state->committed_sequence=work->request.sequence;
    }
    for(i=0;i<32;i++){work->raw_status=0;state->callback_attempts++;state->read_attempts++;
        r=bus.read8(bus.context,i,&work->header[i],&work->raw_status);
        if(r!=1||work->raw_status)return nm_fail(state,work->raw_status,OCNEXT_MMIO_PROVIDER);
    }
    r=nm_observe(state,&bus,work);if(r!=1)return nm_fail(state,work->raw_status,r<0?OCNEXT_MMIO_BINDING:OCNEXT_MMIO_PROVIDER);
    if(!nm_equal(request,&work->request,sizeof(*request))||!nm_equal(provider,&bus,sizeof(bus)))return nm_fail(state,0,OCNEXT_MMIO_PROVIDER);
    if(!nm_header(work->header,expected,op==OCNEXT_MMIO_CLOSE))return nm_fail(state,0,OCNEXT_MMIO_DEVICE);
    state->phase=op==OCNEXT_MMIO_CLOSE?OCNEXT_MMIO_CLOSED:OCNEXT_MMIO_ARMED;
    state->lease_retained=op!=OCNEXT_MMIO_CLOSE;state->counter=expected;state->counter_known=op!=OCNEXT_MMIO_CLOSE;
    state->successful_operations++;state->last_status=0;
    work->result.owner_id=work->request.owner_id;work->result.session_id=work->request.session_id;
    work->result.instance_id=work->request.instance_id;work->result.authority_epoch=work->request.authority_epoch;
    work->result.sequence=work->request.sequence;work->result.generation=work->request.generation;
    work->result.operation=op;work->result.phase=state->phase;
    work->result.flags=OCNEXT_MMIO_F_PRIVATE_QEMU|OCNEXT_MMIO_F_ACTUAL_READBACK|
        (writing?OCNEXT_MMIO_F_WRITE_ACKNOWLEDGED:0u)|(state->lease_retained?OCNEXT_MMIO_F_LEASE_RETAINED:OCNEXT_MMIO_F_LOGICAL_CLOSED);
    work->result.callback_attempts=state->callback_attempts-work->staged.callback_attempts;
    work->result.read_attempts=state->read_attempts-work->staged.read_attempts;
    work->result.write_attempts=state->write_attempts-work->staged.write_attempts;
    work->result.observed_counter=state->counter;work->result.counter_known=state->counter_known;
    nm_copy(out,&work->result,sizeof(*out));return OCNEXT_MMIO_OK;
}
