#include "ocnext/ram.h"
static int native_range(const void *p,size_t n) {return p && n && n<=UINTPTR_MAX-(uintptr_t)p;}
static int overlaps(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an && bn && (x<=y ? y-x<an : x-y<bn);
}
static void copy(void *out,const void *in,size_t n)
{uint8_t *a=out;const uint8_t *b=in;while(n--)*a++=*b++;}
static void zero(void *out,size_t n) {uint8_t *p=out;while(n--)*p++=0;}
static int config_valid(const struct ocnext_ram *r,const struct ocnext_ram *owner)
{
    size_t i,j;
    if(!native_range(r,sizeof(*r)) || r->abi_version!=OCNEXT_RAM_ABI_VERSION || r->reserved ||
       !r->region_count || r->region_count>OCNEXT_RAM_MAX_REGIONS ||
       !r->scratch_bytes || r->scratch_bytes>OCNEXT_RAM_MAX_TRANSFER ||
       !native_range(r->scratch,r->scratch_bytes) ||
       overlaps(owner,sizeof(*owner),r->scratch,r->scratch_bytes))return 0;
    for(i=0;i<r->region_count;++i) {
        const struct ocnext_ram_region *a=&r->regions[i];
        if(!native_range(a->backing,a->bytes) || a->guest_base>UINT64_MAX-a->bytes ||
           a->reserved || !a->permissions || (a->permissions&~7u) ||
           overlaps(a->backing,a->bytes,owner,sizeof(*owner)) ||
           overlaps(a->backing,a->bytes,r->scratch,r->scratch_bytes) ||
           (i && a->guest_base<r->regions[i-1].guest_base+r->regions[i-1].bytes))return 0;
        for(j=0;j<i;++j)if(overlaps(a->backing,a->bytes,r->regions[j].backing,r->regions[j].bytes))return 0;
    }
    return 1;
}
enum ocnext_ram_result ocnext_ram_init(struct ocnext_ram *out,
    const struct ocnext_ram_region *regions,size_t count,uint8_t *scratch,size_t bytes)
{
    struct ocnext_ram staged;size_t i;
    if(!native_range(out,sizeof(*out)) || !regions || !count || count>OCNEXT_RAM_MAX_REGIONS ||
       !native_range(regions,count*sizeof(*regions)))return OCNEXT_RAM_ARGUMENT;
    zero(&staged,sizeof(staged));
    for(i=0;i<count;++i)copy(&staged.regions[i],&regions[i],sizeof(*regions));
    staged.region_count=count;staged.scratch=scratch;staged.scratch_bytes=bytes;
    staged.abi_version=OCNEXT_RAM_ABI_VERSION;
    if(!config_valid(&staged,out))return OCNEXT_RAM_ARGUMENT;
    copy(out,&staged,sizeof(staged));return OCNEXT_RAM_OK;
}
static const struct ocnext_ram_region *find(const struct ocnext_ram *r,uint64_t address)
{
    size_t i;for(i=0;i<r->region_count;++i) {
        const struct ocnext_ram_region *p=&r->regions[i];
        if(address>=p->guest_base && address-p->guest_base<p->bytes)return p;
    }
    return NULL;
}
enum ocnext_ram_result ocnext_ram_probe(const struct ocnext_ram *r,uint64_t at,size_t n,unsigned perm)
{
    if(!config_valid(r,r) || !n || n>OCNEXT_RAM_MAX_TRANSFER || at>UINT64_MAX-n ||
       !perm || (perm&~7u))return OCNEXT_RAM_ARGUMENT;
    while(n) {
        const struct ocnext_ram_region *p=find(r,at);size_t chunk;
        if(!p)return OCNEXT_RAM_UNMAPPED;
        if((p->permissions&perm)!=perm)return OCNEXT_RAM_PERMISSION;
        chunk=p->bytes-(size_t)(at-p->guest_base);if(chunk>n)chunk=n;
        at+=chunk;n-=chunk;
    }
    return OCNEXT_RAM_OK;
}
static int control_alias(const struct ocnext_ram *r,const void *p,size_t n)
{return overlaps(p,n,r,sizeof(*r)) || overlaps(p,n,r->scratch,r->scratch_bytes);}
static int backing_alias(const struct ocnext_ram *r,const void *p,size_t n)
{size_t i;for(i=0;i<r->region_count;++i)if(overlaps(p,n,r->regions[i].backing,r->regions[i].bytes))return 1;return 0;}
enum ocnext_ram_result ocnext_ram_read(struct ocnext_ram *r,uint64_t at,uint8_t *out,size_t n,unsigned perm)
{
    enum ocnext_ram_result result=ocnext_ram_probe(r,at,n,perm);
    if(result!=OCNEXT_RAM_OK)return result;
    if(perm!=OCNEXT_RAM_READ && perm!=OCNEXT_RAM_EXECUTE)return OCNEXT_RAM_ARGUMENT;
    if(!native_range(out,n) || control_alias(r,out,n) || backing_alias(r,out,n))return OCNEXT_RAM_ARGUMENT;
    if(r->successful_reads==UINT64_MAX)return OCNEXT_RAM_EXHAUSTED;
    while(n) {
        const struct ocnext_ram_region *p=find(r,at);size_t off=(size_t)(at-p->guest_base),chunk=p->bytes-off;
        if(chunk>n)chunk=n;
        copy(out,p->backing+off,chunk);at+=chunk;out+=chunk;n-=chunk;
    }
    ++r->successful_reads;return OCNEXT_RAM_OK;
}
enum ocnext_ram_result ocnext_ram_writev(struct ocnext_ram *r,const struct ocnext_ram_write *input,size_t count)
{
    struct ocnext_ram_write writes[OCNEXT_RAM_MAX_WRITES];size_t i,total=0,offset=0;
    if(!config_valid(r,r) || !count || count>OCNEXT_RAM_MAX_WRITES ||
       !native_range(input,count*sizeof(*input)) || control_alias(r,input,count*sizeof(*input)) ||
       backing_alias(r,input,count*sizeof(*input)))return OCNEXT_RAM_ARGUMENT;
    for(i=0;i<count;++i) {
        enum ocnext_ram_result result;
        copy(&writes[i],&input[i],sizeof(writes[i]));
        if(!native_range(writes[i].source,writes[i].bytes) ||
           control_alias(r,writes[i].source,writes[i].bytes) ||
           writes[i].bytes>r->scratch_bytes-total)return OCNEXT_RAM_ARGUMENT;
        result=ocnext_ram_probe(r,writes[i].guest_address,writes[i].bytes,OCNEXT_RAM_WRITE);
        if(result!=OCNEXT_RAM_OK)return result;
        total+=writes[i].bytes;
    }
    if(r->write_transactions==UINT64_MAX || total>UINT64_MAX-r->written_bytes)return OCNEXT_RAM_EXHAUSTED;
    for(i=0;i<count;++i) {copy(r->scratch+offset,writes[i].source,writes[i].bytes);offset+=writes[i].bytes;}
    offset=0;
    for(i=0;i<count;++i) {
        uint64_t at=writes[i].guest_address;size_t remaining=writes[i].bytes;
        while(remaining) {
            const struct ocnext_ram_region *p=find(r,at);size_t off=(size_t)(at-p->guest_base),chunk=p->bytes-off;
            if(chunk>remaining)chunk=remaining;
            copy(p->backing+off,r->scratch+offset,chunk);offset+=chunk;at+=chunk;remaining-=chunk;
        }
    }
    ++r->write_transactions;r->written_bytes+=total;return OCNEXT_RAM_OK;
}
int ocnext_ram_mmu_probe(void *r,uint64_t at,size_t n,enum ocnext_a64_access access)
{
    unsigned perm=access==OCNEXT_A64_ACCESS_FETCH?OCNEXT_RAM_EXECUTE:access==OCNEXT_A64_ACCESS_READ?OCNEXT_RAM_READ:OCNEXT_RAM_WRITE;
    if((access!=OCNEXT_A64_ACCESS_FETCH && access!=OCNEXT_A64_ACCESS_READ && access!=OCNEXT_A64_ACCESS_WRITE) ||
       n>OCNEXT_MMU_MAX_TRANSFER)return -1;
    return ocnext_ram_probe(r,at,n,perm)==OCNEXT_RAM_OK?0:-1;
}
int ocnext_ram_mmu_read(void *r,uint64_t at,uint8_t *out,size_t n)
{return n<=OCNEXT_MMU_MAX_TRANSFER && ocnext_ram_read(r,at,out,n,OCNEXT_RAM_READ)==OCNEXT_RAM_OK?0:-1;}
int ocnext_ram_mmu_writev(void *r,const struct ocnext_mmu_span *spans,size_t count,const uint8_t *source,size_t total)
{
    struct ocnext_ram_write writes[OCNEXT_MMU_MAX_SPANS];size_t i,offset=0;
    if(!spans || !source || !count || count>OCNEXT_MMU_MAX_SPANS || !total || total>OCNEXT_MMU_MAX_TRANSFER ||
       !native_range(source,total) || !native_range(spans,count*sizeof(*spans)))return -1;
    for(i=0;i<count;++i) {
        if(!spans[i].bytes || spans[i].offset!=offset || spans[i].bytes>total-offset)return -1;
        writes[i].guest_address=spans[i].pa;writes[i].source=source+offset;writes[i].bytes=spans[i].bytes;
        offset+=spans[i].bytes;
    }
    return offset==total && ocnext_ram_writev(r,writes,count)==OCNEXT_RAM_OK?0:-1;
}
int ocnext_ram_proxy_probe(void *r,uint64_t at,size_t n,unsigned write)
{return write<=1 && n<=OCNEXT_PROXY_MAX_TRANSFER && ocnext_ram_probe(r,at,n,write?OCNEXT_RAM_WRITE:OCNEXT_RAM_READ)==OCNEXT_RAM_OK?1:0;}
int ocnext_ram_proxy_read(void *r,uint64_t at,uint8_t *out,size_t n)
{return n<=OCNEXT_PROXY_MAX_TRANSFER && ocnext_ram_read(r,at,out,n,OCNEXT_RAM_READ)==OCNEXT_RAM_OK?1:0;}
int ocnext_ram_proxy_writev(void *r,const struct ocnext_proxy_write *input,size_t count)
{
    struct ocnext_ram_write writes[OCNEXT_PROXY_MAX_BATCH];size_t i;
    if(!input || !count || count>OCNEXT_PROXY_MAX_BATCH || !native_range(input,count*sizeof(*input)))return 0;
    for(i=0;i<count;++i) {
        if(!input[i].bytes || input[i].bytes>OCNEXT_PROXY_MAX_TRANSFER)return 0;
        writes[i].guest_address=input[i].address;writes[i].source=input[i].data;writes[i].bytes=input[i].bytes;
    }
    return ocnext_ram_writev(r,writes,count)==OCNEXT_RAM_OK?1:0;
}
