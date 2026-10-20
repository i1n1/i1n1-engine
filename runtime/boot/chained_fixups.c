#include "ocnext/chained_fixups.h"
#include "ocnext/sha256.h"
#include <limits.h>

struct range { uint32_t begin, end; };
struct work {
    struct ocnext_chained_segment segments[32];
    struct range ranges[32];
    struct ocnext_chained_summary summary;
    uint32_t segment_count, range_count, command_end, reserved[3];
};
struct span { uintptr_t base; size_t bytes; };
_Static_assert(sizeof(void *)==8,"native64");
_Static_assert(sizeof(struct work)==2312,"workspace");
_Static_assert(sizeof(struct ocnext_chained_snapshot)==72,"snapshot");
_Static_assert(sizeof(struct ocnext_chained_segment)==48,"segment");
_Static_assert(sizeof(struct ocnext_chained_slot)==48,"slot");
_Static_assert(sizeof(struct ocnext_chained_summary)==496,"summary");
_Static_assert(sizeof(struct ocnext_chained_window)==32,"window");
_Static_assert(sizeof(struct ocnext_chained_catalog)==24,"catalog ABI1");
_Static_assert(sizeof(struct ocnext_chained_workspace)==2312,"workspace POD");
#define OFFSET(type,field,n) _Static_assert(offsetof(struct type,field)==n,"chained native ABI offset")
OFFSET(ocnext_chained_snapshot,expected_sha256,16);OFFSET(ocnext_chained_snapshot,source_id,48);
OFFSET(ocnext_chained_snapshot,abi_version,64);OFFSET(ocnext_chained_segment,name,32);
OFFSET(ocnext_chained_slot,segment_index,24);OFFSET(ocnext_chained_slot,target_offset,36);
OFFSET(ocnext_chained_slot,diversity,40);OFFSET(ocnext_chained_slot,key_selector,44);
OFFSET(ocnext_chained_summary,image_sha256,32);OFFSET(ocnext_chained_summary,total,96);
OFFSET(ocnext_chained_summary,key_counts,160);OFFSET(ocnext_chained_summary,segment_counts,224);
OFFSET(ocnext_chained_summary,abi_version,480);OFFSET(ocnext_chained_window,capacity,16);
OFFSET(ocnext_chained_window,abi_version,24);
OFFSET(ocnext_chained_catalog,capacity,8);OFFSET(ocnext_chained_catalog,count,12);
OFFSET(ocnext_chained_catalog,abi_version,16);OFFSET(ocnext_chained_catalog,reserved,20);
static void copy(void *d,const void *s,size_t n) {
    uint8_t *a=d; const uint8_t *b=s; for(size_t i=0;i<n;i++)a[i]=b[i];
}
static void zero(void *d,size_t n) {uint8_t *a=d;for(size_t i=0;i<n;i++)a[i]=0;}
static int equal(const uint8_t *a,const uint8_t *b,size_t n) {
    uint8_t x=0;for(size_t i=0;i<n;i++)x|=a[i]^b[i];return x==0;
}
static uint16_t u16(const uint8_t *p){return (uint16_t)((uint16_t)p[0]|((uint16_t)p[1]<<8));}
static uint32_t u32(const uint8_t *p){return (uint32_t)u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t *p){return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32);}
static int bounded(uint64_t n,uint64_t off,uint64_t bytes){return off<=n&&bytes<=n-off;}
static int intersect(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return n&&m&&a<b+m&&b<a+n;
}
static int add_span(struct span *s,unsigned *count,const void *p,size_t n,unsigned align) {
    uintptr_t b=(uintptr_t)p;
    if(!p||!n||(b&(align-1u))||n>UINTPTR_MAX-b)return 0;
    for(unsigned i=0;i<*count;i++)if(intersect(b,n,s[i].base,s[i].bytes))return 0;
    s[*count].base=b;s[*count].bytes=n;(*count)++;return 1;
}
static size_t scratch_required(uint64_t bytes,uint32_t capacity,uint32_t limit) {
    if(bytes<32||bytes>OCNEXT_CHAINED_MAX_IMAGE||capacity>limit)return 0;
    return (size_t)((((bytes+31u)/32u)+7u)&~UINT64_C(7)) +8192u+(size_t)capacity*48u;
}
size_t ocnext_chained_scratch_bytes(uint64_t bytes,uint32_t capacity) {
    return scratch_required(bytes,capacity,OCNEXT_CHAINED_MAX_WINDOW);
}
size_t ocnext_chained_catalog_scratch_bytes(uint64_t bytes,uint32_t capacity) {
    return scratch_required(bytes,capacity,OCNEXT_CHAINED_MAX_SLOTS);
}
static int bit(const uint8_t *p,uint64_t i){return (p[i/8]>>(i%8))&1;}
static void setbit(uint8_t *p,uint64_t i){p[i/8]|=(uint8_t)(1u<<(i%8));}
static int macho(const uint8_t *p,uint64_t n,struct work *w) {
    if(u32(p)!=UINT32_C(0xfeedfacf)||u32(p+4)!=UINT32_C(0x0100000c)||
       u32(p+12)!=12||u32(p+28))return OCNEXT_CHAINED_MACHO;
    uint32_t commands=u32(p+16),bytes=u32(p+20),pos=32,payloads=0;
    if(!commands||commands>1024||bytes<8||bytes>1048576||!bounded(n,32,bytes))return OCNEXT_CHAINED_MACHO;
    uint32_t end=32+bytes;w->command_end=end;w->summary.load_commands=commands;
    w->summary.root_vm_base=UINT64_MAX;
    for(uint32_t c=0;c<commands;c++) {
        if(!bounded(end,pos,8))return OCNEXT_CHAINED_MACHO;
        uint32_t cmd=u32(p+pos),size=u32(p+pos+4);
        if(size<8||(size&7)||!bounded(end,pos,size))return OCNEXT_CHAINED_MACHO;
        if(cmd==0x19) {
            if(size<72||w->segment_count==32||size!=72u+(uint64_t)u32(p+pos+64)*80u)return OCNEXT_CHAINED_SEGMENT;
            struct ocnext_chained_segment *s=&w->segments[w->segment_count++];
            copy(s->name,p+pos+8,16);s->vmaddr=u64(p+pos+24);s->vmsize=u64(p+pos+32);
            s->fileoff=u64(p+pos+40);s->filesize=u64(p+pos+48);
            if(!s->vmsize||s->filesize>s->vmsize||s->vmsize>UINT64_MAX-s->vmaddr||
               (s->fileoff&3)||!bounded(n,s->fileoff,s->filesize))return OCNEXT_CHAINED_SEGMENT;
            if(s->vmaddr<w->summary.root_vm_base)w->summary.root_vm_base=s->vmaddr;
        } else if(cmd==UINT32_C(0x80000034)) {
            if(size!=16||++payloads!=1)return OCNEXT_CHAINED_METADATA;
            w->summary.payload_file_offset=u32(p+pos+8);w->summary.payload_bytes=u32(p+pos+12);
            if(w->summary.payload_bytes<28||w->summary.payload_bytes>1048576||
               !bounded(n,w->summary.payload_file_offset,w->summary.payload_bytes))return OCNEXT_CHAINED_METADATA;
        } else if(cmd==UINT32_C(0x80000035)) {
            if(size<32)return OCNEXT_CHAINED_MACHO;
            uint32_t no=u32(p+pos+24);
            if(u32(p+pos+28)||!bounded(n,u64(p+pos+16),32)||no<32||no>=size)return OCNEXT_CHAINED_MACHO;
            uint32_t j=no;while(j<size&&p[pos+j])j++;
            if(j==size)return OCNEXT_CHAINED_MACHO;
            w->summary.fileset_entries++;
        }
        pos+=size;
    }
    if(pos!=end||payloads!=1||!w->segment_count)return OCNEXT_CHAINED_MACHO;
    for(unsigned i=0;i<w->segment_count;i++)for(unsigned j=i+1;j<w->segment_count;j++) {
        const struct ocnext_chained_segment *a=&w->segments[i],*b=&w->segments[j];
        if(intersect(a->vmaddr,a->vmsize,b->vmaddr,b->vmsize)||
           intersect(a->fileoff,a->filesize,b->fileoff,b->filesize))return OCNEXT_CHAINED_OVERLAP;
    }
    w->summary.root_segments=w->segment_count;return OCNEXT_CHAINED_OK;
}
static int chain(const uint8_t *p,struct work *w,uint8_t *occupied,uint8_t *divs,
                 struct ocnext_chained_slot *staged,uint64_t first,uint32_t cap,
                 unsigned si,uint32_t pi,uint32_t page,uint32_t current) {
    const struct ocnext_chained_segment *s=&w->segments[si];
    for(;;) {
        if((current&3)||current>page-4)return OCNEXT_CHAINED_SLOT;
        uint64_t within=(uint64_t)pi*page+current;
        if(!bounded(s->vmsize,within,8)||!bounded(s->filesize,within,8))return OCNEXT_CHAINED_SLOT;
        uint64_t off=s->fileoff+within;
        if(intersect(off,8,0,w->command_end)||intersect(off,8,w->summary.payload_file_offset,w->summary.payload_bytes))return OCNEXT_CHAINED_OVERLAP;
        if(bit(occupied,off/4)||bit(occupied,off/4+1))return OCNEXT_CHAINED_OVERLAP;
        if(w->summary.total>=OCNEXT_CHAINED_MAX_SLOTS)return OCNEXT_CHAINED_BUDGET;
        uint64_t word=u64(p+off);
        struct ocnext_chained_slot slot;
        slot.file_offset=off;slot.image_vm_offset=s->vmaddr-w->summary.root_vm_base+within;slot.encoded_word=word;
        slot.segment_index=si;slot.page_index=pi;slot.page_size=page;slot.target_offset=(uint32_t)(word&UINT64_C(0x3fffffff));
        slot.diversity=(uint16_t)(word>>32);slot.next_units=(uint16_t)((word>>51)&4095);
        slot.key_selector=(uint8_t)((word>>49)&3);slot.cache_level=(uint8_t)((word>>30)&3);
        slot.address_diversity=(uint8_t)((word>>48)&1);slot.authenticated=(uint8_t)(word>>63);
        if(current>page-8&&slot.next_units)return OCNEXT_CHAINED_SLOT;
        setbit(occupied,off/4);setbit(occupied,off/4+1);
        uint64_t index=w->summary.total;
        if(index>=first&&index-first<cap)copy(&staged[index-first],&slot,sizeof(slot));
        w->summary.total++;w->summary.segment_counts[si]++;w->summary.cache_counts[slot.cache_level]++;
        if(current>page-8)w->summary.cross_page_terminal++;
        if(slot.authenticated) {
            w->summary.authenticated++;w->summary.key_counts[slot.key_selector]++;
            if(slot.address_diversity)w->summary.address_diverse++;else w->summary.not_address_diverse++;
            if(!bit(divs,slot.diversity)){setbit(divs,slot.diversity);w->summary.distinct_diversity++;}
        } else {w->summary.unauthenticated++;if(slot.diversity||slot.key_selector||slot.address_diversity)w->summary.unauth_unused_nonzero++;}
        if(!slot.next_units)return OCNEXT_CHAINED_OK;
        current+=(uint32_t)slot.next_units*4u;
    }
}
static int walk(const uint8_t *image,struct work *w,uint8_t *bits,uint8_t *divs,
                struct ocnext_chained_slot *slots,uint64_t first,uint32_t cap) {
    const uint8_t *p=image+w->summary.payload_file_offset;
    uint32_t n=(uint32_t)w->summary.payload_bytes;
    if(u32(p)||u32(p+4)!=28||u32(p+8)!=n||u32(p+12)!=n||u32(p+16)||u32(p+20)!=1||u32(p+24))return OCNEXT_CHAINED_METADATA;
    if(!bounded(n,28,4)||u32(p+28)!=w->segment_count||!bounded(n,32,w->segment_count*4u))return OCNEXT_CHAINED_METADATA;
    uint32_t table_end=32+w->segment_count*4u;
    for(unsigned si=0;si<w->segment_count;si++) {
        uint32_t rel=u32(p+32+si*4u);if(!rel)continue;
        if((rel&3)||rel>UINT32_MAX-28)return OCNEXT_CHAINED_METADATA;
        uint32_t off=28+rel;if(off<table_end||!bounded(n,off,22))return OCNEXT_CHAINED_METADATA;
        const uint8_t *info=p+off;uint32_t size=u32(info);uint32_t page=u16(info+4),pages=u16(info+20);
        const struct ocnext_chained_segment *s=&w->segments[si];
        if(!bounded(n,off,size)||size<22||((size-22)&1)||
           (page!=4096&&page!=16384)||u16(info+6)!=8||u32(info+16)||!pages||
           22u+pages*2u>size||u64(info+8)!=s->vmaddr-w->summary.root_vm_base||
           (s->vmsize-1)/page+1!=pages)return OCNEXT_CHAINED_METADATA;
        for(unsigned j=0;j<w->range_count;j++)if(intersect(off,size,w->ranges[j].begin,w->ranges[j].end-w->ranges[j].begin))return OCNEXT_CHAINED_OVERLAP;
        w->ranges[w->range_count].begin=off;w->ranges[w->range_count++].end=off+size;
        uint32_t words=(size-22)/2;
        for(uint32_t pi=0;pi<pages;pi++) {
            uint32_t raw=u16(info+22+pi*2);if(raw==65535)continue;
            if(raw&32768) {
                uint32_t at=raw&32767,chains=0;
                if(at<pages)return OCNEXT_CHAINED_METADATA;
                for(;;) {
                    if(at>=words||chains++>=page/4)return OCNEXT_CHAINED_METADATA;
                    uint32_t v=u16(info+22+at++*2);
                    int r=chain(image,w,bits,divs,slots,first,cap,si,pi,page,v&32767);if(r)return r;
                    if(v&32768)break;
                }
            } else {int r=chain(image,w,bits,divs,slots,first,cap,si,pi,page,raw);if(r)return r;}
        }
    }
    return OCNEXT_CHAINED_OK;
}
static int scan(const struct ocnext_chained_snapshot *input,
    struct ocnext_chained_workspace *workspace,void *scratch,size_t bytes,
    struct ocnext_chained_summary *output,struct ocnext_chained_segment *segments,
    struct ocnext_chained_window *window,struct ocnext_chained_catalog *catalog) {
    struct span spans[8];unsigned ns=0;
    if(!add_span(spans,&ns,input,sizeof(*input),8)||
       !add_span(spans,&ns,workspace,sizeof(*workspace),8)||
       !add_span(spans,&ns,output,sizeof(*output),8)||
       !add_span(spans,&ns,segments,sizeof(*segments)*32u,8))return OCNEXT_CHAINED_ARGUMENT;
    if(input->abi_version!=1||input->reserved||!input->source_id||!input->source_epoch)return OCNEXT_CHAINED_ARGUMENT;
    uint32_t cap=0;uint64_t first=0;
    if(window&&catalog)return OCNEXT_CHAINED_ARGUMENT;
    if(window) {
        if(!add_span(spans,&ns,window,sizeof(*window),8)||window->abi_version!=1||window->reserved||window->count||
           window->capacity>4096||window->first_index>1000000)return OCNEXT_CHAINED_ARGUMENT;
        cap=window->capacity;first=window->first_index;
        if(!cap&&(window->slots||first))return OCNEXT_CHAINED_ARGUMENT;
        if(cap&&!add_span(spans,&ns,window->slots,(size_t)cap*48u,8))return OCNEXT_CHAINED_ARGUMENT;
    }
    if(catalog) {
        if(!add_span(spans,&ns,catalog,sizeof(*catalog),8)||
           catalog->abi_version!=OCNEXT_CHAINED_CATALOG_ABI_VERSION||catalog->reserved||catalog->count||
           catalog->capacity>OCNEXT_CHAINED_MAX_SLOTS)return OCNEXT_CHAINED_ARGUMENT;
        cap=catalog->capacity;
        if(!cap&&catalog->slots)return OCNEXT_CHAINED_ARGUMENT;
        if(cap&&!add_span(spans,&ns,catalog->slots,(size_t)cap*48u,8))return OCNEXT_CHAINED_ARGUMENT;
    }
    size_t required=catalog?ocnext_chained_catalog_scratch_bytes(input->byte_count,cap):
        ocnext_chained_scratch_bytes(input->byte_count,cap);
    if(!required||bytes<required||!add_span(spans,&ns,scratch,bytes,8)||
       !add_span(spans,&ns,input->bytes,(size_t)input->byte_count,1))return OCNEXT_CHAINED_ARGUMENT;
    uint8_t digest[32];
    if(ocnext_sha256_digest(input->bytes,(size_t)input->byte_count,digest)||!equal(digest,input->expected_sha256,32))return OCNEXT_CHAINED_DIGEST;
    struct work *w=(struct work *)(void *)workspace;zero(w,sizeof(*w));zero(scratch,required);
    w->summary.abi_version=1;w->summary.image_bytes=input->byte_count;copy(w->summary.image_sha256,digest,32);
    int r=macho(input->bytes,input->byte_count,w);if(r)return r;
    size_t bitmap=required-8192u-(size_t)cap*48u;
    uint8_t *bits=scratch,*divs=bits+bitmap;
    struct ocnext_chained_slot *staged=(struct ocnext_chained_slot *)(void *)(divs+8192u);
    r=walk(input->bytes,w,bits,divs,staged,first,cap);if(r)return r;
    if(catalog&&w->summary.total>cap)return OCNEXT_CHAINED_BUDGET;
    if(first>w->summary.total)return OCNEXT_CHAINED_WINDOW;
    if(ocnext_sha256_digest(input->bytes+w->summary.payload_file_offset,(size_t)w->summary.payload_bytes,w->summary.payload_sha256))return OCNEXT_CHAINED_ARGUMENT;
    /* Serialized immutable caller contract; no provider can mutate between
     * digest and parse. Publish only after full image walk and final checks. */
    copy(output,&w->summary,sizeof(*output));copy(segments,w->segments,32u*sizeof(*segments));
    if(window) {
        uint64_t remain=w->summary.total-first;uint32_t count=remain<cap?(uint32_t)remain:cap;
        if(count)copy(window->slots,staged,(size_t)count*48u);window->count=count;
    }
    if(catalog) {
        uint32_t count=(uint32_t)w->summary.total;
        if(count)copy(catalog->slots,staged,(size_t)count*48u);
        catalog->count=count;
    }
    return OCNEXT_CHAINED_OK;
}
int ocnext_chained_scan(const struct ocnext_chained_snapshot *input,
    struct ocnext_chained_workspace *workspace,void *scratch,size_t bytes,
    struct ocnext_chained_summary *output,struct ocnext_chained_segment *segments,
    struct ocnext_chained_window *window) {
    return scan(input,workspace,scratch,bytes,output,segments,window,NULL);
}
int ocnext_chained_collect(const struct ocnext_chained_snapshot *input,
    struct ocnext_chained_workspace *workspace,void *scratch,size_t bytes,
    struct ocnext_chained_summary *output,struct ocnext_chained_segment *segments,
    struct ocnext_chained_catalog *catalog) {
    if(!catalog)return OCNEXT_CHAINED_ARGUMENT;
    return scan(input,workspace,scratch,bytes,output,segments,NULL,catalog);
}
