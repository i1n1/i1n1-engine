#include "ocnext/elf_module.h"
#include "ocnext/sha256.h"

#define EM_PAGE UINT64_C(4096)
#define EM_R 4u
#define EM_W 2u
#define EM_X 1u
struct em_span { uintptr_t base; uint64_t bytes; };
struct em_phdr { uint32_t type,flags; uint64_t off,va,pa,filesz,memsz,align; };
struct em_work {
    struct ocnext_elf_module_image image;
    struct em_phdr dynamic,relro;
    uint64_t phoff,phnum,entry;
    uint64_t rela,relasz,relaent,relacount,symtab,syment,strtab,strsz,gnu_hash,hash;
    uint32_t seen,has_dynamic,has_relro,has_phdr,has_stack;
};
_Static_assert(sizeof(struct em_work)<=sizeof(struct ocnext_elf_module_workspace),"ELF bounded scratch");
static void em_copy(void *d,const void *s,uint64_t n)
{volatile uint8_t *a=d;const volatile uint8_t *b=s;while(n--)*a++=*b++;}
static void em_zero(void *d,uint64_t n)
{volatile uint8_t *a=d;while(n--)*a++=0;}
static int em_equal(const uint8_t*a,const uint8_t*b,size_t n)
{uint8_t different=0;for(size_t i=0;i<n;i++)different|=a[i]^b[i];return !different;}
static uint16_t em_u16(const uint8_t*p)
{return (uint16_t)p[0]|(uint16_t)((uint16_t)p[1]<<8);}
static uint32_t em_u32(const uint8_t*p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t em_u64(const uint8_t*p)
{return (uint64_t)em_u32(p)|((uint64_t)em_u32(p+4)<<32);}
static void em_put64(uint8_t*p,uint64_t n)
{for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(8*i));}
static int em_range(uint64_t base,uint64_t n)
{return base&&n&&base<=UINTPTR_MAX&&n<=UINTPTR_MAX-base;}
static int em_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{return n&&m&&(a<=b?b-a<n:a-b<m);}
static int em_inside(uint64_t base,uint64_t n,uint64_t at,uint64_t bytes)
{return at>=base&&at-base<=n&&bytes<=n-(at-base);}
static int em_native(const void*p,uint64_t n,uint64_t align)
{return em_range((uintptr_t)p,n)&&!((uintptr_t)p&(align-1));}
static int em_align(uint64_t n)
{return n<=1||(!(n&(n-1))&&n<=4096);}
static uint64_t em_ceil(uint64_t n)
{return (n+4095)&~UINT64_C(4095);}
static void em_ph(const struct ocnext_elf_module_request*r,const struct em_work*w,unsigned i,struct em_phdr*p)
{
    const uint8_t*b=r->file+w->phoff+(uint64_t)i*56;
    p->type=em_u32(b);p->flags=em_u32(b+4);p->off=em_u64(b+8);p->va=em_u64(b+16);
    p->pa=em_u64(b+24);p->filesz=em_u64(b+32);p->memsz=em_u64(b+40);p->align=em_u64(b+48);
}
/* Convert only a complete, uniquely file-backed readable LOAD span. */
static int em_file_span(const struct em_work*w,uint64_t va,uint64_t bytes,uint64_t*out)
{
    for(uint32_t i=0;i<w->image.segment_count;i++){
        const struct ocnext_elf_module_segment*s=&w->image.segments[i];
        if((s->flags&EM_R)&&em_inside(s->rva,s->file_bytes,va,bytes)){
            *out=s->file_offset+(va-s->rva);return 1;
        }
    }
    return 0;
}
static int em_write_span(const struct em_work*w,uint64_t va,uint64_t bytes)
{
    for(uint32_t i=0;i<w->image.segment_count;i++){
        const struct ocnext_elf_module_segment*s=&w->image.segments[i];
        if(s->flags==(EM_R|EM_W)&&em_inside(s->rva,s->memory_bytes,va,bytes))return 1;
    }
    return 0;
}
static int em_internal_addend(const struct em_work*w,uint64_t addend)
{
    for(uint32_t i=0;i<w->image.segment_count;i++){
        const struct ocnext_elf_module_segment*s=&w->image.segments[i];
        if(em_inside(s->rva,s->memory_bytes,addend,0))return 1;
    }
    return 0;
}
static enum ocnext_elf_module_status em_headers(const struct ocnext_elf_module_request*r,struct em_work*w)
{
    const uint8_t*b=r->file;
    if(em_u32(b)!=UINT32_C(0x464c457f))return OCNEXT_ELF_MODULE_FORMAT;
    if(b[4]!=2||b[5]!=1||b[6]!=1||b[7]||b[8]||em_u16(b+16)!=3||em_u16(b+18)!=62)
        return OCNEXT_ELF_MODULE_UNSUPPORTED;
    for(unsigned i=9;i<16;i++)if(b[i])return OCNEXT_ELF_MODULE_UNSUPPORTED;
    if(em_u32(b+20)!=1||em_u32(b+48)||em_u16(b+52)!=64||em_u16(b+54)!=56)
        return OCNEXT_ELF_MODULE_FORMAT;
    w->phoff=em_u64(b+32);w->phnum=em_u16(b+56);w->entry=em_u64(b+24);
    if(!w->phnum||w->phnum>32)return OCNEXT_ELF_MODULE_QUOTA;
    if(w->phoff<64||!em_inside(0,r->file_bytes,w->phoff,w->phnum*56))return OCNEXT_ELF_MODULE_BOUNDS;
    uint64_t shoff=em_u64(b+40),shnum=em_u16(b+60),shent=em_u16(b+58),shstr=em_u16(b+62);
    if(shoff){
        if(!shnum||shnum>8192||shstr>=shnum||shent!=64)return OCNEXT_ELF_MODULE_UNSUPPORTED;
        if(!em_inside(0,r->file_bytes,shoff,shnum*64))return OCNEXT_ELF_MODULE_BOUNDS;
    }else if(shnum||shent||shstr)return OCNEXT_ELF_MODULE_FORMAT;
    return OCNEXT_ELF_MODULE_OK;
}
static enum ocnext_elf_module_status em_loads(const struct ocnext_elf_module_request*r,struct em_work*w)
{
    for(unsigned i=0;i<w->phnum;i++){
        struct em_phdr p;em_ph(r,w,i,&p);
        if(p.type!=1)continue;
        unsigned n=w->image.segment_count;
        if(n==8)return OCNEXT_ELF_MODULE_QUOTA;
        if(!p.memsz||p.filesz>p.memsz||!em_align(p.align)||
           (p.flags!=4&&p.flags!=5&&p.flags!=6)||(p.off&4095)!=(p.va&4095)||
           (p.align>1&&((p.off&(p.align-1))!=(p.va&(p.align-1)))))return OCNEXT_ELF_MODULE_FORMAT;
        if(!em_inside(0,r->file_bytes,p.off,p.filesz)||!em_inside(0,OCNEXT_ELF_MODULE_MAX_BYTES,p.va,p.memsz))
            return OCNEXT_ELF_MODULE_BOUNDS;
        uint64_t page=p.va&~UINT64_C(4095),end=em_ceil(p.va+p.memsz);
        if(end>r->backing_bytes)return OCNEXT_ELF_MODULE_BOUNDS;
        if(!n){
            if(p.va||p.off||p.filesz<w->phoff+w->phnum*56)return OCNEXT_ELF_MODULE_FORMAT;
        }else{
            const struct ocnext_elf_module_segment*last=&w->image.segments[n-1];
            if(page<last->page_rva+last->page_bytes)return OCNEXT_ELF_MODULE_FORMAT;
        }
        for(unsigned j=0;j<n;j++){
            const struct ocnext_elf_module_segment*s=&w->image.segments[j];
            if(em_overlap(s->file_offset,s->file_bytes,p.off,p.filesz))return OCNEXT_ELF_MODULE_FORMAT;
        }
        struct ocnext_elf_module_segment*s=&w->image.segments[n];
        s->file_offset=p.off;s->file_bytes=p.filesz;s->rva=p.va;s->memory_bytes=p.memsz;
        s->page_rva=page;s->page_bytes=end-page;s->flags=p.flags;
        w->image.segment_count++;w->image.image_bytes=end;
    }
    if(!w->image.segment_count)return OCNEXT_ELF_MODULE_FORMAT;
    for(unsigned i=0;i<w->image.segment_count;i++){
        const struct ocnext_elf_module_segment*s=&w->image.segments[i];
        if(s->flags==5&&em_inside(s->rva,s->file_bytes,w->entry,1)){
            w->image.entry_rva=w->entry;return OCNEXT_ELF_MODULE_OK;
        }
    }
    return OCNEXT_ELF_MODULE_FORMAT;
}
static enum ocnext_elf_module_status em_extra(const struct ocnext_elf_module_request*r,struct em_work*w)
{
    int seen_load=0;
    for(unsigned i=0;i<w->phnum;i++){
        struct em_phdr p;uint64_t file;em_ph(r,w,i,&p);
        if(p.type==1){seen_load=1;continue;}
        if(p.type==0)continue; /* Defined unused header; other fields unspecified. */
        if(!em_align(p.align)||!em_inside(0,r->file_bytes,p.off,p.filesz))return OCNEXT_ELF_MODULE_BOUNDS;
        if(p.type==2){
            if(w->has_dynamic++||p.flags!=6||!p.filesz||p.filesz>4096||p.filesz%16||p.filesz!=p.memsz||
               !em_file_span(w,p.va,p.filesz,&file)||file!=p.off||!em_write_span(w,p.va,p.memsz))return OCNEXT_ELF_MODULE_FORMAT;
            w->dynamic=p;w->image.dynamic_file_offset=p.off;w->image.dynamic_bytes=p.filesz;
        }else if(p.type==6){
            if(w->has_phdr++||seen_load||p.flags!=4||p.off!=w->phoff||p.filesz!=w->phnum*56||
               p.memsz!=p.filesz||!em_file_span(w,p.va,p.filesz,&file)||file!=p.off)return OCNEXT_ELF_MODULE_FORMAT;
        }else if(p.type==UINT32_C(0x6474e551)){
            if(w->has_stack++||p.flags!=6||p.filesz||p.memsz)return OCNEXT_ELF_MODULE_UNSUPPORTED;
        }else if(p.type==UINT32_C(0x6474e552)){
            if(w->has_relro++||p.flags!=4||!p.memsz||p.filesz>p.memsz||
               !em_write_span(w,p.va,p.memsz)||!em_file_span(w,p.va,p.filesz,&file)||file!=p.off)
                return OCNEXT_ELF_MODULE_FORMAT;
            w->relro=p;
        }else if(p.type==4||p.type==UINT32_C(0x6474e550)){
            if(p.flags!=4||!p.filesz||p.filesz!=p.memsz||
               !em_file_span(w,p.va,p.filesz,&file)||file!=p.off)return OCNEXT_ELF_MODULE_FORMAT;
        }else return OCNEXT_ELF_MODULE_UNSUPPORTED;
    }
    if(w->has_dynamic!=1)return OCNEXT_ELF_MODULE_FORMAT;
    if(w->has_relro){
        uint64_t start=w->relro.va&~UINT64_C(4095),end=em_ceil(w->relro.va+w->relro.memsz);int found=0;
        for(unsigned i=0;i<w->image.segment_count;i++){
            const struct ocnext_elf_module_segment*s=&w->image.segments[i];
            if(s->flags==6&&em_inside(s->page_rva,s->page_bytes,start,end-start))found=1;
        }
        if(!found)return OCNEXT_ELF_MODULE_FORMAT;
        w->image.relro_rva=start;w->image.relro_bytes=end-start;
    }
    return OCNEXT_ELF_MODULE_OK;
}
static int em_tag_index(uint64_t tag)
{
    static const uint64_t tags[]={UINT64_C(0x6ffffffb),21,7,8,9,UINT64_C(0x6ffffff9),6,11,5,10,
        UINT64_C(0x6ffffef5),4,30};
    for(unsigned i=0;i<sizeof(tags)/sizeof(tags[0]);i++)if(tags[i]==tag)return (int)i;
    return -1;
}
static enum ocnext_elf_module_status em_dynamic(const struct ocnext_elf_module_request*r,struct em_work*w)
{
    int ended=0;
    for(uint64_t at=0;at<w->dynamic.filesz;at+=16){
        const uint8_t*b=r->file+w->dynamic.off+at;uint64_t tag=em_u64(b),value=em_u64(b+8);
        if(ended){if(tag||value)return OCNEXT_ELF_MODULE_FORMAT;continue;}
        if(!tag){if(value)return OCNEXT_ELF_MODULE_FORMAT;ended=1;continue;}
        int index=em_tag_index(tag);if(index<0)return OCNEXT_ELF_MODULE_UNSUPPORTED;
        uint32_t bit=UINT32_C(1)<<(unsigned)index;
        if(w->seen&bit)return OCNEXT_ELF_MODULE_FORMAT;w->seen|=bit;
        switch(index){
        case 0:if(value!=UINT64_C(0x08000000))return OCNEXT_ELF_MODULE_UNSUPPORTED;break;
        case 1:if(value)return OCNEXT_ELF_MODULE_UNSUPPORTED;break;
        case 2:w->rela=value;break;case 3:w->relasz=value;break;case 4:w->relaent=value;break;
        case 5:w->relacount=value;break;case 6:w->symtab=value;break;case 7:w->syment=value;break;
        case 8:w->strtab=value;break;case 9:w->strsz=value;break;case 10:w->gnu_hash=value;break;
        case 11:w->hash=value;break;case 12:if(value!=8)return OCNEXT_ELF_MODULE_UNSUPPORTED;break;
        default:return OCNEXT_ELF_MODULE_UNSUPPORTED;
        }
    }
    /* All required table descriptors and FLAGS_1; DEBUG/RELACOUNT/hash kinds optional. */
    const uint32_t required=(1u<<0)|(1u<<2)|(1u<<3)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<8)|(1u<<9);
    if(!ended||(w->seen&required)!=required||w->relaent!=24||w->syment!=24||!w->strsz||
       !w->relasz||w->relasz%24)return OCNEXT_ELF_MODULE_FORMAT;
    uint64_t count=w->relasz/24,off;
    if(count>OCNEXT_ELF_MODULE_MAX_RELOCATIONS)return OCNEXT_ELF_MODULE_QUOTA;
    if((w->seen&(1u<<5))&&w->relacount!=count)return OCNEXT_ELF_MODULE_RELOCATION;
    if(!em_file_span(w,w->rela,w->relasz,&off))return OCNEXT_ELF_MODULE_BOUNDS;
    w->image.relocation_count=count;w->image.rela_file_offset=off;w->image.rela_bytes=w->relasz;
    if(!em_file_span(w,w->symtab,24,&off)||!em_file_span(w,w->strtab,w->strsz,&off))return OCNEXT_ELF_MODULE_BOUNDS;
    if((w->seen&(1u<<10))&&!em_file_span(w,w->gnu_hash,16,&off))return OCNEXT_ELF_MODULE_BOUNDS;
    if((w->seen&(1u<<11))&&!em_file_span(w,w->hash,8,&off))return OCNEXT_ELF_MODULE_BOUNDS;
    return OCNEXT_ELF_MODULE_OK;
}
static enum ocnext_elf_module_status em_relocations(const struct ocnext_elf_module_request*r,struct em_work*w)
{
    uint64_t previous=0;
    for(uint64_t i=0;i<w->image.relocation_count;i++){
        const uint8_t*b=r->file+w->image.rela_file_offset+24*i;
        uint64_t target=em_u64(b),info=em_u64(b+8),addend=em_u64(b+16);
        if(info!=8||(target&7)||(i&&target<=previous)||!em_write_span(w,target,8)||
           (addend>>63)||!em_internal_addend(w,addend)||addend>UINTPTR_MAX-(uintptr_t)r->backing||
           em_overlap(target,8,0,64)||em_overlap(target,8,w->phoff,w->phnum*56)||
           em_overlap(target,8,w->dynamic.va,w->dynamic.memsz)||em_overlap(target,8,w->rela,w->relasz))
            return OCNEXT_ELF_MODULE_RELOCATION;
        previous=target;
    }
    return OCNEXT_ELF_MODULE_OK;
}
static enum ocnext_elf_module_status em_preflight(const struct ocnext_elf_module_request*r,
    struct ocnext_elf_module_workspace*scratch,struct ocnext_elf_module_image*out,struct em_work**work)
{
    if(!em_native(r,sizeof(*r),8)||!em_native(scratch,sizeof(*scratch),8)||!em_native(out,sizeof(*out),8))
        return OCNEXT_ELF_MODULE_ARGUMENT;
    struct em_span spans[5]={{(uintptr_t)r,sizeof(*r)},{(uintptr_t)scratch,sizeof(*scratch)},
        {(uintptr_t)out,sizeof(*out)},{0,0},{0,0}};
    for(unsigned i=0;i<3;i++)for(unsigned j=0;j<i;j++)
        if(em_overlap(spans[i].base,spans[i].bytes,spans[j].base,spans[j].bytes))return OCNEXT_ELF_MODULE_ALIAS;
    if(r->abi_version!=1||r->bytes!=112||!r->owner_id||!r->generation||r->reserved[0]||r->reserved[1]||r->reserved[2])
        return OCNEXT_ELF_MODULE_ARGUMENT;
    if(r->file_bytes<64||r->file_bytes>OCNEXT_ELF_MODULE_MAX_BYTES||r->backing_bytes<4096||
       r->backing_bytes>OCNEXT_ELF_MODULE_MAX_BYTES||(r->backing_bytes&4095))return OCNEXT_ELF_MODULE_BOUNDS;
    if(!em_native(r->file,r->file_bytes,1)||!em_native(r->backing,r->backing_bytes,4096))return OCNEXT_ELF_MODULE_ARGUMENT;
    spans[3]=(struct em_span){(uintptr_t)r->file,r->file_bytes};spans[4]=(struct em_span){(uintptr_t)r->backing,r->backing_bytes};
    for(unsigned i=3;i<5;i++)for(unsigned j=0;j<i;j++)
        if(em_overlap(spans[i].base,spans[i].bytes,spans[j].base,spans[j].bytes))return OCNEXT_ELF_MODULE_ALIAS;
    struct em_work*w=(struct em_work *)(void *)scratch;em_zero(w,sizeof(*w));*work=w;
    if(ocnext_sha256_digest(r->file,(size_t)r->file_bytes,w->image.file_sha256)||
       !em_equal(w->image.file_sha256,r->expected_file_sha256,32))return OCNEXT_ELF_MODULE_DIGEST;
    enum ocnext_elf_module_status status=em_headers(r,w);if(status)return status;
    status=em_loads(r,w);if(status)return status;
    status=em_extra(r,w);if(status)return status;
    status=em_dynamic(r,w);if(status)return status;
    status=em_relocations(r,w);if(status)return status;
    w->image.abi_version=1;w->image.bytes=704;w->image.flags=3;
    w->image.owner_id=r->owner_id;w->image.generation=r->generation;
    w->image.native_base=(uintptr_t)r->backing;w->image.file_bytes=r->file_bytes;
    return OCNEXT_ELF_MODULE_OK;
}
enum ocnext_elf_module_status ocnext_elf_module_plan(const struct ocnext_elf_module_request*r,
    struct ocnext_elf_module_workspace*w,struct ocnext_elf_module_image*out)
{
    struct em_work*work;enum ocnext_elf_module_status status=em_preflight(r,w,out,&work);
    if(status)return status;em_copy(out,&work->image,sizeof(*out));return OCNEXT_ELF_MODULE_OK;
}
enum ocnext_elf_module_status ocnext_elf_module_stage(const struct ocnext_elf_module_request*r,
    struct ocnext_elf_module_workspace*w,struct ocnext_elf_module_image*out)
{
    struct em_work*work;enum ocnext_elf_module_status status=em_preflight(r,w,out,&work);
    if(status)return status;
    em_zero(r->backing,work->image.image_bytes);
    for(unsigned i=0;i<work->image.segment_count;i++){
        const struct ocnext_elf_module_segment*s=&work->image.segments[i];
        em_copy(r->backing+s->rva,r->file+s->file_offset,s->file_bytes);
    }
    for(uint64_t i=0;i<work->image.relocation_count;i++){
        const uint8_t*b=r->file+work->image.rela_file_offset+24*i;
        em_put64(r->backing+em_u64(b),(uintptr_t)r->backing+em_u64(b+16));
    }
    /* Preflight bounded/disjoint pointers and <=8MiB length make SHA failure
     * an internal invariant violation, not a recoverable partial transaction. */
    if(ocnext_sha256_digest(r->backing,(size_t)work->image.image_bytes,work->image.image_sha256))__builtin_trap();
    work->image.flags=15;em_copy(out,&work->image,sizeof(*out));return OCNEXT_ELF_MODULE_OK;
}
