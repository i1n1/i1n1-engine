#include "ocnext/pci_capture.h"
#include "ocnext/sha256.h"
static void cap_zero(void *v,size_t n){uint8_t *p=v;while(n--)*p++=0;}
static void cap_copy(void *v,const void *s,size_t n){uint8_t *p=v;const uint8_t *q=s;while(n--)*p++=*q++;}
static int cap_equal(const void *a,const void *b,size_t n){const uint8_t *p=a,*q=b;while(n--)if(*p++!=*q++)return 0;return 1;}
static int cap_span(const void *v,size_t n,size_t alignment){uintptr_t a=(uintptr_t)v;return v&&!(a%alignment)&&n<=UINTPTR_MAX-a;}
static int cap_overlap(const void *a,size_t n,const void *b,size_t m){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<y+m&&y<x+n;}
static int cap_identity(const struct ocnext_pci_identity *i){
    return i->abi==1&&i->source_id&&i->capture_id&&i->domain_id&&i->owner_id&&i->session_id&&i->instance_id&&i->generation&&
        i->device<=31&&i->function<=7&&i->source_kind==OCNEXT_PCI_SOURCE_QEMU&&!i->reserved;
}
static enum ocnext_pci_capture_result cap_finish(struct ocnext_pci_capture_trace *out,
    struct ocnext_pci_capture_trace *value,enum ocnext_pci_capture_result result){
    value->result=(uint32_t)result;cap_copy(out,value,sizeof(*out));return result;
}
enum ocnext_pci_capture_result ocnext_pci_capture_run(
    const struct ocnext_pci_capture_request *request,const struct ocnext_pci_capture_provider *provider,
    struct ocnext_pci_capture_workspace *work,struct ocnext_pci_capture_record *out,
    struct ocnext_pci_capture_trace *trace){
    const void *objects[5]={request,provider,work,out,trace};
    const size_t sizes[5]={sizeof(*request),sizeof(*provider),sizeof(*work),sizeof(*out),sizeof(*trace)};
    struct ocnext_pci_capture_request req;struct ocnext_pci_capture_provider bus;
    struct ocnext_pci_capture_trace value;struct ocnext_pci_capture_binding observed;
    unsigned i,j,pass;uint32_t offset,completed,needed;uint64_t status;int result;
    for(i=0;i<5;i++)if(!cap_span(objects[i],sizes[i],8))return OCNEXT_PCI_CAPTURE_ARGUMENT;
    for(i=0;i<5;i++)for(j=0;j<i;j++)if(cap_overlap(objects[i],sizes[i],objects[j],sizes[j]))return OCNEXT_PCI_CAPTURE_ALIAS;
    cap_copy(&req,request,sizeof(req));cap_copy(&bus,provider,sizeof(bus));
    if(req.abi!=1||(req.config_bytes!=256&&req.config_bytes!=4096)||bus.abi!=1||
       bus.profile!=OCNEXT_PCI_CAPTURE_QEMU_READONLY||!bus.context||!bus.read||!bus.observe)
        return OCNEXT_PCI_CAPTURE_ARGUMENT;
    if(!cap_identity(&req.binding.identity)||!req.binding.channel_id||!req.binding.source_epoch)return OCNEXT_PCI_CAPTURE_IDENTITY;
    needed=2u*req.config_bytes/OCNEXT_PCI_CAPTURE_CHUNK;
    if(req.max_read_calls>OCNEXT_PCI_CAPTURE_MAX_READ_CALLS||req.max_read_bytes>OCNEXT_PCI_CAPTURE_MAX_READ_BYTES)
        return OCNEXT_PCI_CAPTURE_ARGUMENT;
    if(req.max_read_calls<needed||req.max_read_bytes<2u*req.config_bytes)return OCNEXT_PCI_CAPTURE_QUOTA;
    cap_zero(&value,sizeof(value));value.abi=1;value.profile=bus.profile;value.source_generation=req.binding.identity.generation;
    cap_zero(work,sizeof(*work));cap_zero(&observed,sizeof(observed));status=0;
    value.observations=1;result=bus.observe(bus.context,&observed,&status);value.provider_status=status;
    if(result!=1||status)return cap_finish(trace,&value,result==0||status?OCNEXT_PCI_CAPTURE_PROVIDER_FAILED:OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
    if(!cap_equal(&observed,&req.binding,sizeof(observed)))return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_BINDING_CHANGED);
    value.flags|=OCNEXT_PCI_CAPTURE_T_BINDING_BEFORE;
    for(pass=0;pass<2;pass++)for(offset=0;offset<req.config_bytes;offset+=OCNEXT_PCI_CAPTURE_CHUNK){
        uint8_t *destination=(pass?work->verify:work->staged.raw)+offset;
        completed=OCNEXT_PCI_CAPTURE_COMPLETED_UNKNOWN;status=0;
        value.failed_pass=pass+1;value.failed_offset=offset;value.requested_bytes=OCNEXT_PCI_CAPTURE_CHUNK;
        value.read_calls++;value.flags|=OCNEXT_PCI_CAPTURE_T_READ_ATTEMPTED;
        result=bus.read(bus.context,offset,destination,OCNEXT_PCI_CAPTURE_CHUNK,&completed,&status);
        value.provider_status=status;value.completed_bytes=completed;
        if(completed==OCNEXT_PCI_CAPTURE_COMPLETED_UNKNOWN)value.flags|=OCNEXT_PCI_CAPTURE_T_PARTIAL_UNKNOWN;
        else if(completed>OCNEXT_PCI_CAPTURE_CHUNK)return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
        else value.read_bytes+=completed;
        if(result!=1||status)return cap_finish(trace,&value,result==0||status?OCNEXT_PCI_CAPTURE_PROVIDER_FAILED:OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
        if(completed!=OCNEXT_PCI_CAPTURE_CHUNK)return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
    }
    value.failed_pass=value.failed_offset=value.requested_bytes=value.completed_bytes=0;value.provider_status=0;
    cap_zero(&observed,sizeof(observed));status=0;value.observations=2;
    result=bus.observe(bus.context,&observed,&status);value.provider_status=status;
    if(result!=1||status)return cap_finish(trace,&value,result==0||status?OCNEXT_PCI_CAPTURE_PROVIDER_FAILED:OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
    if(!cap_equal(&observed,&req.binding,sizeof(observed)))return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_BINDING_CHANGED);
    value.flags|=OCNEXT_PCI_CAPTURE_T_BINDING_AFTER;
    if(!cap_equal(work->staged.raw,work->verify,req.config_bytes))return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_UNSTABLE);
    value.flags|=OCNEXT_PCI_CAPTURE_T_STABLE;
    if(work->staged.raw[0]==255&&work->staged.raw[1]==255)return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_NO_DEVICE);
    if((work->staged.raw[14]&127)>1)return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_UNSUPPORTED_HEADER);
    if(ocnext_sha256_digest(work->staged.raw,req.config_bytes,work->staged.sha256))
        return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL);
    value.flags|=OCNEXT_PCI_CAPTURE_T_DIGEST;
    work->staged.identity=req.binding.identity;work->staged.channel_id=req.binding.channel_id;work->staged.source_epoch=req.binding.source_epoch;
    work->staged.abi=1;work->staged.config_bytes=req.config_bytes;work->staged.profile=bus.profile;work->staged.known_mask=7;
    work->staged.read_calls=value.read_calls;work->staged.read_bytes=value.read_bytes;
    work->staged.binding_observations=2;work->staged.stability_passes=2;
    cap_copy(out,&work->staged,sizeof(*out));return cap_finish(trace,&value,OCNEXT_PCI_CAPTURE_OK);
}
enum ocnext_pci_capture_result ocnext_pci_capture_snapshot(
    const struct ocnext_pci_capture_record *record,struct ocnext_pci_snapshot *out){
    struct ocnext_pci_snapshot value;uint8_t digest[32];unsigned i;
    if(!cap_span(record,sizeof(*record),8)||!cap_span(out,sizeof(*out),8))return OCNEXT_PCI_CAPTURE_ARGUMENT;
    if(cap_overlap(record,sizeof(*record),out,sizeof(*out)))return OCNEXT_PCI_CAPTURE_ALIAS;
    if(record->abi!=1||record->profile!=OCNEXT_PCI_CAPTURE_QEMU_READONLY||record->known_mask!=7||
       (record->config_bytes!=256&&record->config_bytes!=4096)||!cap_identity(&record->identity)||
       !record->channel_id||!record->source_epoch||record->binding_observations!=2||record->stability_passes!=2||
       record->read_calls!=2u*record->config_bytes/OCNEXT_PCI_CAPTURE_CHUNK||record->read_bytes!=2u*record->config_bytes)
        return OCNEXT_PCI_CAPTURE_BAD_RECORD;
    for(i=record->config_bytes;i<4096;i++)if(record->raw[i])return OCNEXT_PCI_CAPTURE_BAD_RECORD;
    if(ocnext_sha256_digest(record->raw,record->config_bytes,digest)||!cap_equal(digest,record->sha256,32))return OCNEXT_PCI_CAPTURE_DIGEST_MISMATCH;
    if(record->raw[0]==255&&record->raw[1]==255)return OCNEXT_PCI_CAPTURE_NO_DEVICE;
    if((record->raw[14]&127)>1)return OCNEXT_PCI_CAPTURE_UNSUPPORTED_HEADER;
    cap_zero(&value,sizeof(value));value.bytes=record->raw;value.length=record->config_bytes;value.identity=record->identity;
    cap_copy(value.expected_sha256,record->sha256,32);cap_copy(out,&value,sizeof(value));return OCNEXT_PCI_CAPTURE_OK;
}
