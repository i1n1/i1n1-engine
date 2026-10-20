#include "ocnext/fixup_index.h"
#include "ocnext/sha256.h"
#include <limits.h>
struct span {uintptr_t base;size_t bytes;};
struct inner {uint64_t off,vm;};
struct range {uint64_t off,n;};
struct event {uint64_t position;uint32_t flags;uint16_t owner;uint8_t prot;int8_t direction;uint64_t vm_delta;};
_Static_assert(sizeof(struct event)==24,"event bytes");
struct build_work {
 struct ocnext_chained_workspace scanner;
 struct ocnext_chained_summary summary;
 struct ocnext_chained_segment raw_segments[32];
 struct ocnext_fixup_index_segment segments[32];
 struct inner inners[1024];
 struct ocnext_fixup_index_segment current[32];
 struct range sections[256];
 struct ocnext_chained_catalog catalog;
 struct ocnext_fixup_index_state state;
 uint64_t work,quota;uint32_t inner_count,commands,section_count,global_unknown;
 uint32_t event_count,event_cursor,flag_counts[3],prot_counts[8],owner_count,owner_xor;uint16_t owners[1025];uint32_t active_segments,reserved;uint64_t vm_delta_xor;
};
struct adapter_work {
 struct ocnext_fixup_candidate candidates[128];
 struct ocnext_fixup_segment segments[32];
 struct ocnext_fixup_index_adapter_result result;
};
union work {struct build_work build;struct adapter_work adapt;};
_Static_assert(sizeof(void*)==8,"native64");
_Static_assert(sizeof(union work)<=32768,"caller workspace");
#define SZ(t,n) _Static_assert(sizeof(struct t)==n,"index ABI size")
#define OF(t,f,n) _Static_assert(offsetof(struct t,f)==n,"index ABI offset")
SZ(ocnext_fixup_index_entry,64);SZ(ocnext_fixup_index_segment,64);
SZ(ocnext_fixup_index_storage,32);SZ(ocnext_fixup_index_request,48);
SZ(ocnext_fixup_index_state,256);SZ(ocnext_fixup_index_read_request,48);
SZ(ocnext_fixup_index_lease,112);SZ(ocnext_fixup_index_resolution,96);
SZ(ocnext_fixup_index_adapter_result,32);
OF(ocnext_fixup_index_entry,classification,48);OF(ocnext_fixup_index_entry,root_initprot,52);
OF(ocnext_fixup_index_entry,inner_owner,54);OF(ocnext_fixup_index_entry,walk_ordinal,56);
OF(ocnext_fixup_index_segment,maxprot,48);OF(ocnext_fixup_index_segment,pointer_format,60);
OF(ocnext_fixup_index_storage,capacity,8);OF(ocnext_fixup_index_storage,segments,16);
OF(ocnext_fixup_index_request,class_work_quota,24);OF(ocnext_fixup_index_request,slot_quota,32);
OF(ocnext_fixup_index_state,source_sha256,80);OF(ocnext_fixup_index_state,entries_sha256,112);
OF(ocnext_fixup_index_state,segments_sha256,144);OF(ocnext_fixup_index_state,abi_version,176);
OF(ocnext_fixup_index_state,classification_counts,192);OF(ocnext_fixup_index_read_request,first_ordinal,32);
OF(ocnext_fixup_index_read_request,count,40);OF(ocnext_fixup_index_lease,owner_id,32);
OF(ocnext_fixup_index_lease,image_bytes,64);OF(ocnext_fixup_index_lease,abi_version,88);
OF(ocnext_fixup_index_resolution,resolved_pointer,48);OF(ocnext_fixup_index_resolution,geometry,64);
OF(ocnext_fixup_index_resolution,abi_version,80);OF(ocnext_fixup_index_adapter_result,count,24);
static void cp(void*d,const void*s,size_t n){uint8_t*a=d;const uint8_t*b=s;for(size_t i=0;i<n;i++)a[i]=b[i];}
static void z(void*d,size_t n){uint8_t*p=d;for(size_t i=0;i<n;i++)p[i]=0;}
static int eq(const void*a,const void*b,size_t n){const uint8_t*x=a,*y=b;uint8_t v=0;for(size_t i=0;i<n;i++)v|=x[i]^y[i];return !v;}
static int iszero(const void*p,size_t n){const uint8_t*x=p;uint8_t v=0;for(size_t i=0;i<n;i++)v|=x[i];return !v;}
static uint16_t u16(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t*p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t*p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static void p16(uint8_t*p,uint16_t x){p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);}
static void p32(uint8_t*p,uint32_t x){p16(p,(uint16_t)x);p16(p+2,(uint16_t)(x>>16));}
static void p64(uint8_t*p,uint64_t x){p32(p,(uint32_t)x);p32(p+4,(uint32_t)(x>>32));}
static int bound(uint64_t n,uint64_t off,uint64_t bytes){return off<=n&&bytes<=n-off;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&a<b+m&&b<a+n;}
static int span(struct span*s,unsigned*count,const void*p,size_t n,unsigned align){uintptr_t b=(uintptr_t)p;if(!p||!n||(b&(align-1u))||n>UINTPTR_MAX-b)return 0;for(unsigned i=0;i<*count;i++)if(overlap(b,n,s[i].base,s[i].bytes))return 0;s[*count].base=b;s[*count].bytes=n;(*count)++;return 1;}
size_t ocnext_fixup_index_scratch_bytes(uint64_t n,uint32_t cap){
 size_t base=ocnext_chained_catalog_scratch_bytes(n,cap);if(!base||!cap)return 0;
 return base+(size_t)cap*64u+16384u*sizeof(struct event);
}
static void entry_bytes(const struct ocnext_fixup_index_entry*e,uint8_t b[64]){
 const struct ocnext_chained_slot*s=&e->slot;p64(b,s->file_offset);p64(b+8,s->image_vm_offset);p64(b+16,s->encoded_word);
 p32(b+24,s->segment_index);p32(b+28,s->page_index);p32(b+32,s->page_size);p32(b+36,s->target_offset);
 p16(b+40,s->diversity);p16(b+42,s->next_units);b[44]=s->key_selector;b[45]=s->cache_level;b[46]=s->address_diversity;b[47]=s->authenticated;
 p32(b+48,e->classification);b[52]=e->root_initprot;b[53]=e->inner_initprot;p16(b+54,e->inner_owner);p64(b+56,e->walk_ordinal);
}
static void segment_bytes(const struct ocnext_fixup_index_segment*s,uint8_t b[64]){
 p64(b,s->segment.vmaddr);p64(b+8,s->segment.vmsize);p64(b+16,s->segment.fileoff);p64(b+24,s->segment.filesize);cp(b+32,s->segment.name,16);
 p32(b+48,s->maxprot);p32(b+52,s->initprot);p32(b+56,s->page_bytes);p32(b+60,s->pointer_format);
}
static int hash_entries(const struct ocnext_fixup_index_entry*e,uint64_t n,uint8_t out[32]){struct ocnext_sha256 h;uint8_t b[64];if(ocnext_sha256_init(&h))return 0;for(uint64_t i=0;i<n;i++){entry_bytes(e+i,b);if(ocnext_sha256_update(&h,b,64))return 0;}return !ocnext_sha256_final(&h,out);}
static int hash_segments(const struct ocnext_fixup_index_segment*s,uint8_t out[32]){struct ocnext_sha256 h;uint8_t b[64];if(ocnext_sha256_init(&h))return 0;for(unsigned i=0;i<32;i++){segment_bytes(s+i,b);if(ocnext_sha256_update(&h,b,64))return 0;}return !ocnext_sha256_final(&h,out);}
#define MF_META 1u
#define MF_EXEC 2u
#define MF_UNKNOWN 4u
#define MF_INNER 8u
#define MF_READ 16u
#define MF_WRITE 32u
#define MF_CONFLICT 64u
static int charge(struct build_work*w,uint64_t n){if(n>w->quota-w->work)return OCNEXT_FIXUP_INDEX_QUOTA;w->work+=n;return 0;}
static int mark(struct build_work*w,struct event*events,uint64_t n,uint64_t off,uint64_t bytes,uint8_t flags,uint16_t owner,uint32_t prot,uint64_t vm_delta){
 if(!bound(n,off,bytes))return OCNEXT_FIXUP_INDEX_STRUCTURE;if(!bytes)return 0;
 if(w->event_count>16384-2)return OCNEXT_FIXUP_INDEX_QUOTA;int code=charge(w,2);if(code)return code;
 struct event *a=events+w->event_count,*b=a+1;a->position=(off/4)*4;a->flags=flags;a->owner=owner;a->prot=(uint8_t)prot;a->direction=1;a->vm_delta=vm_delta;
 cp(b,a,sizeof(*a));b->position=((off+bytes+3)/4)*4;b->direction=-1;w->event_count+=2;return 0;
}
static int meta(struct build_work*w,struct event*events,uint64_t n,uint64_t p,uint64_t count,uint64_t stride){if(stride&&count>UINT64_MAX/stride)return OCNEXT_FIXUP_INDEX_STRUCTURE;return mark(w,events,n,p,count*stride,MF_META,0,0,0);}
static int nameeq(const uint8_t*p,const char*s){unsigned i=0;while(i<16&&s[i]){if(p[i]!=(uint8_t)s[i])return 0;i++;}while(i<16){if(p[i])return 0;i++;}return 1;}
static int parse_header(const uint8_t*p,uint64_t n,uint64_t at,uint64_t entry_vm,unsigned owner,struct build_work*w,struct event*events){
 if(!bound(n,at,32)||u32(p+at)!=UINT32_C(0xfeedfacf)||u32(p+at+4)!=UINT32_C(0x0100000c)||u32(p+at+28))return OCNEXT_FIXUP_INDEX_STRUCTURE;
 uint32_t type=u32(p+at+12),commands=u32(p+at+16),cmdbytes=u32(p+at+20);
 if((!owner&&type!=12)||(owner&&type!=2&&type!=11)||!commands||commands>1024||cmdbytes<8||cmdbytes>1048576||!bound(n,at+32,cmdbytes)||commands>65536-w->commands)return OCNEXT_FIXUP_INDEX_STRUCTURE;
 w->commands+=commands;uint64_t end=at+32+cmdbytes,pos=at+32;unsigned ns=0;uint32_t sym_count=0;int got_sym=0,unknown=0,entry_contained=!owner;
 int r=meta(w,events,n,at,32+cmdbytes,1);if(r)return r;
 z(w->current,sizeof(w->current));
 for(unsigned c=0;c<commands;c++){
  if((r=charge(w,1)))return r;
  if(!bound(end,pos,8))return OCNEXT_FIXUP_INDEX_STRUCTURE;uint32_t cmd=u32(p+pos),size=u32(p+pos+4);
  if(size<8||(size&7)||!bound(end,pos,size))return OCNEXT_FIXUP_INDEX_STRUCTURE;
  if(cmd==0x19){
   if(size<72||ns==32||size!=72u+(uint64_t)u32(p+pos+64)*80u)return OCNEXT_FIXUP_INDEX_STRUCTURE;
   struct ocnext_fixup_index_segment*s=&w->current[ns++];cp(s->segment.name,p+pos+8,16);s->segment.vmaddr=u64(p+pos+24);s->segment.vmsize=u64(p+pos+32);s->segment.fileoff=u64(p+pos+40);s->segment.filesize=u64(p+pos+48);s->maxprot=u32(p+pos+56);s->initprot=u32(p+pos+60);
   if(s->maxprot>7||s->initprot>7||(s->initprot&~s->maxprot)||s->segment.filesize>s->segment.vmsize||s->segment.vmsize>UINT64_MAX-s->segment.vmaddr||!bound(n,s->segment.fileoff,s->segment.filesize))return OCNEXT_FIXUP_INDEX_STRUCTURE;
   if(!owner&&(!s->segment.vmsize||(s->segment.fileoff&3)))return OCNEXT_FIXUP_INDEX_STRUCTURE;
   if(owner&&bound(s->segment.filesize,at-s->segment.fileoff,32)&&at>=s->segment.fileoff&&entry_vm==s->segment.vmaddr+(at-s->segment.fileoff))entry_contained=1;
   for(unsigned j=0;j+1<ns;j++)if(overlap(s->segment.fileoff,s->segment.filesize,w->current[j].segment.fileoff,w->current[j].segment.filesize)||overlap(s->segment.vmaddr,s->segment.vmsize,w->current[j].segment.vmaddr,w->current[j].segment.vmsize))return OCNEXT_FIXUP_INDEX_STRUCTURE;
   if(u32(p+pos+68)&~4u){r=mark(w,events,n,s->segment.fileoff,s->segment.filesize,MF_UNKNOWN,0,0,0);if(r)return r;}
   if(owner){r=mark(w,events,n,s->segment.fileoff,s->segment.filesize,0,(uint16_t)owner,s->initprot,s->segment.vmaddr-s->segment.fileoff);if(r)return r;}
   if(nameeq(s->segment.name,"__LINKEDIT")||nameeq(s->segment.name,"__LINKINFO")){r=meta(w,events,n,s->segment.fileoff,s->segment.filesize,1);if(r)return r;}
   uint32_t count=u32(p+pos+64);if(count>256||count>8192-w->section_count)return OCNEXT_FIXUP_INDEX_STRUCTURE;w->section_count+=count;
   for(uint32_t j=0;j<count;j++){
    if((r=charge(w,1)))return r;
    const uint8_t*q=p+pos+72u+j*80u;uint64_t addr=u64(q+32),bytes=u64(q+40);uint32_t off=u32(q+48),flags=u32(q+64),kind=flags&255u;
    if(addr<s->segment.vmaddr||!bound(s->segment.vmsize,addr-s->segment.vmaddr,bytes)||u32(q+52)>31||!eq(q+16,s->segment.name,16))return OCNEXT_FIXUP_INDEX_STRUCTURE;
    if((r=meta(w,events,n,u32(q+56),u32(q+60),8)))return r;
    if(kind==1||kind==12||kind==18){w->sections[j].off=0;w->sections[j].n=0;continue;}
    if(bytes&&(!bound(n,off,bytes)||off<s->segment.fileoff||!bound(s->segment.filesize,off-s->segment.fileoff,bytes)||addr-s->segment.vmaddr!=(uint64_t)off-s->segment.fileoff))return OCNEXT_FIXUP_INDEX_STRUCTURE;
    for(uint32_t k=0;k<j;k++)if(overlap(off,bytes,w->sections[k].off,w->sections[k].n))return OCNEXT_FIXUP_INDEX_STRUCTURE;
    w->sections[j].off=off;w->sections[j].n=bytes;
    uint8_t f=0;if(flags&(UINT32_C(0x80000000)|UINT32_C(0x00000400)))f|=MF_EXEC;if(kind>22||(flags&~UINT32_C(0xfe0007ff)))f|=MF_UNKNOWN;
    if(f&&(r=mark(w,events,n,off,bytes,f,0,0,0)))return r;
   }
  }else if(cmd==UINT32_C(0x80000035)){
   if(owner||size<32||w->inner_count==1024)return OCNEXT_FIXUP_INDEX_STRUCTURE;uint32_t no=u32(p+pos+24);uint64_t off=u64(p+pos+16),vm=u64(p+pos+8);
   if(u32(p+pos+28)||!bound(n,off,32)||no<32||no>=size)return OCNEXT_FIXUP_INDEX_STRUCTURE;uint32_t k=no;while(k<size&&p[pos+k])k++;if(k==size)return OCNEXT_FIXUP_INDEX_STRUCTURE;
   for(unsigned j=0;j<w->inner_count;j++)if(w->inners[j].off==off||w->inners[j].vm==vm)return OCNEXT_FIXUP_INDEX_STRUCTURE;
   w->inners[w->inner_count].off=off;w->inners[w->inner_count++].vm=vm;
  }else if(cmd==UINT32_C(0x80000034)||cmd==0x26||cmd==0x29||cmd==0x1d||cmd==0x1e||cmd==0x2b||cmd==0x2e){if(size!=16)return OCNEXT_FIXUP_INDEX_STRUCTURE;if((r=meta(w,events,n,u32(p+pos+8),u32(p+pos+12),1)))return r;
  }else if(cmd==2){if(size!=24||got_sym++)return OCNEXT_FIXUP_INDEX_STRUCTURE;sym_count=u32(p+pos+12);if((r=meta(w,events,n,u32(p+pos+8),sym_count,16))||(r=meta(w,events,n,u32(p+pos+16),u32(p+pos+20),1)))return r;
  }else if(cmd==11){if(size!=80)return OCNEXT_FIXUP_INDEX_STRUCTURE;/* indices checked after all commands */
   static const uint8_t strides[6]={8,56,4,4,8,8};for(unsigned j=0;j<6;j++)if((r=meta(w,events,n,u32(p+pos+32+j*8),u32(p+pos+36+j*8),strides[j])))return r;
  }else if(cmd==0x1b){if(size!=24)return OCNEXT_FIXUP_INDEX_STRUCTURE;
  }else if(cmd==0x2a){if(size!=16)return OCNEXT_FIXUP_INDEX_STRUCTURE;
  }else if(cmd==0x32){if(size<24||size!=24u+(uint64_t)u32(p+pos+20)*8u)return OCNEXT_FIXUP_INDEX_STRUCTURE;
  }else if(cmd==5||cmd==4){if(size<16)return OCNEXT_FIXUP_INDEX_STRUCTURE;uint32_t q=8;while(q<size){if(size-q<8)return OCNEXT_FIXUP_INDEX_STRUCTURE;uint32_t words=u32(p+pos+q+4);uint64_t bytes=8u+(uint64_t)words*4u;if(bytes>size-q)return OCNEXT_FIXUP_INDEX_STRUCTURE;q+=(uint32_t)bytes;}if(q!=size)return OCNEXT_FIXUP_INDEX_STRUCTURE;
  }else unknown=1;
  pos+=size;
 }
 if(pos!=end||!ns||!entry_contained)return OCNEXT_FIXUP_INDEX_STRUCTURE;
 pos=at+32;for(unsigned c=0;c<commands;c++){uint32_t cmd=u32(p+pos),size=u32(p+pos+4);if(cmd==11){if(!got_sym)return OCNEXT_FIXUP_INDEX_STRUCTURE;for(unsigned j=0;j<3;j++)if(!bound(sym_count,u32(p+pos+8+j*8),u32(p+pos+12+j*8)))return OCNEXT_FIXUP_INDEX_STRUCTURE;}pos+=size;}
 if(!owner){for(unsigned j=0;j<ns;j++){if(!eq(&w->current[j].segment,&w->raw_segments[j],48))return OCNEXT_FIXUP_INDEX_STRUCTURE;cp(w->segments+j,w->current+j,64);}if(ns!=w->summary.root_segments)return OCNEXT_FIXUP_INDEX_STRUCTURE;}
 if(unknown){w->global_unknown=1;/* unknown command may refer outside own segment */}
 return 0;
}
static void swap(struct ocnext_fixup_index_entry*a,struct ocnext_fixup_index_entry*b){uint8_t t[64];cp(t,a,64);cp(a,b,64);cp(b,t,64);}
static int sift(struct build_work*w,struct ocnext_fixup_index_entry*p,uint64_t root,uint64_t n){for(;;){if(root>=n/2)return 0;uint64_t child=root*2+1;if(child>=n)return 0;int code=charge(w,1);if(code)return code;if(child+1<n&&p[child].slot.file_offset<p[child+1].slot.file_offset)child++;if((code=charge(w,1)))return code;if(p[root].slot.file_offset>=p[child].slot.file_offset)return 0;swap(p+root,p+child);root=child;}}
static int sort(struct build_work*w,struct ocnext_fixup_index_entry*p,uint64_t n){if(n<2)return 0;int code;for(uint64_t i=n/2;i;i--)if((code=sift(w,p,i-1,n)))return code;for(uint64_t i=n-1;i;i--){swap(p,p+i);if((code=sift(w,p,0,i)))return code;}return 0;}
static void event_swap(struct event*a,struct event*b){struct event t=*a;*a=*b;*b=t;}
static int event_sift(struct build_work*w,struct event*p,unsigned root,unsigned n){for(;;){if(root>=n/2)return 0;unsigned child=root*2+1;if(child>=n)return 0;int code=charge(w,1);if(code)return code;if(child+1<n&&p[child].position<p[child+1].position)child++;if((code=charge(w,1)))return code;if(p[root].position>=p[child].position)return 0;event_swap(p+root,p+child);root=child;}}
static int event_sort(struct build_work*w,struct event*p){unsigned n=w->event_count;if(n<2)return 0;int code;for(unsigned i=n/2;i;i--)if((code=event_sift(w,p,i-1,n)))return code;for(unsigned i=n-1;i;i--){event_swap(p,p+i);if((code=event_sift(w,p,0,i)))return code;}return 0;}
static int observe(struct build_work*w,const struct event*events,uint64_t position,uint8_t*flags,uint16_t*owner,uint64_t*vm_delta){
 int code=charge(w,1);if(code)return code;
 while(w->event_cursor<w->event_count&&events[w->event_cursor].position<=position){
  if((code=charge(w,1)))return code;const struct event*e=events+w->event_cursor++;int delta=e->direction;
  for(unsigned bit=0;bit<3;bit++)if(e->flags&(1u<<bit)){if(delta<0&&!w->flag_counts[bit])return OCNEXT_FIXUP_INDEX_STRUCTURE;w->flag_counts[bit]=(uint32_t)(w->flag_counts[bit]+delta);}
  if(e->owner){if(e->owner>1024||e->prot>7)return OCNEXT_FIXUP_INDEX_STRUCTURE;uint16_t old=w->owners[e->owner];if(delta<0&&(!old||!w->prot_counts[e->prot]))return OCNEXT_FIXUP_INDEX_STRUCTURE;w->owners[e->owner]=(uint16_t)(old+delta);if(!old&&delta>0){w->owner_count++;w->owner_xor^=e->owner;}if(old==1&&delta<0){w->owner_count--;w->owner_xor^=e->owner;}w->prot_counts[e->prot]=(uint32_t)(w->prot_counts[e->prot]+delta);w->active_segments=(uint32_t)(w->active_segments+delta);w->vm_delta_xor^=e->vm_delta;}
 }
 uint8_t f=0;for(unsigned i=0;i<3;i++)if(w->flag_counts[i])f|=(uint8_t)(1u<<i);unsigned known_prots=0;for(unsigned i=0;i<8;i++)if(w->prot_counts[i]){known_prots++;if(i&1)f|=MF_READ;if(i&2)f|=MF_WRITE;if(i&4)f|=MF_EXEC;}
 if(w->owner_count)f|=MF_INNER;uint16_t o=w->owner_count==1?(uint16_t)w->owner_xor:w->owner_count?65535:0;
 if(w->owner_count>1||known_prots>1||w->active_segments!=w->owner_count){f|=MF_UNKNOWN|MF_CONFLICT;o=65535;}*flags=f;*owner=o;*vm_delta=w->vm_delta_xor;return 0;
}
enum ocnext_fixup_index_code ocnext_fixup_index_build(const struct ocnext_chained_snapshot*s,const struct ocnext_fixup_index_request*r,const struct ocnext_fixup_index_storage*storage,struct ocnext_fixup_index_state*out,union ocnext_fixup_index_workspace*workspace,void*scratch,size_t scratch_bytes){
 struct span spans[9];unsigned ns=0;
 if(!span(spans,&ns,s,sizeof(*s),8)||!span(spans,&ns,r,sizeof(*r),8)||!span(spans,&ns,storage,sizeof(*storage),8)||!span(spans,&ns,out,sizeof(*out),8)||!span(spans,&ns,workspace,sizeof(*workspace),_Alignof(union ocnext_fixup_index_workspace)))return OCNEXT_FIXUP_INDEX_ARGUMENT;
 if(s->abi_version!=1||s->reserved||!s->source_id||!s->source_epoch||r->abi_version!=1||r->reserved||!r->owner_id||r->source_id!=s->source_id||r->source_epoch!=s->source_epoch||(r->profile!=1&&r->profile!=2)||!r->slot_quota||r->slot_quota>1000000||!r->class_work_quota||r->class_work_quota>1000000000||storage->reserved||storage->capacity!=r->slot_quota)return OCNEXT_FIXUP_INDEX_ARGUMENT;
 size_t required=ocnext_fixup_index_scratch_bytes(s->byte_count,r->slot_quota);
 if(!required||scratch_bytes<required||!span(spans,&ns,storage->entries,(size_t)storage->capacity*64u,8)||!span(spans,&ns,storage->segments,32u*64u,8)||!span(spans,&ns,scratch,scratch_bytes,8)||!span(spans,&ns,s->bytes,(size_t)s->byte_count,1))return OCNEXT_FIXUP_INDEX_ARGUMENT;
 if(!iszero(out,sizeof(*out)))return OCNEXT_FIXUP_INDEX_STALE;
 struct build_work*w=&((union work*)(void*)workspace)->build;z(w,sizeof(*w));w->quota=r->class_work_quota;
 size_t collector_bytes=ocnext_chained_catalog_scratch_bytes(s->byte_count,r->slot_quota);
 uint8_t*raw=scratch;struct ocnext_fixup_index_entry*entries=(void*)(raw+collector_bytes);
 struct event*events=(void*)(entries+r->slot_quota);
 /* Collector requires its published slot array disjoint from its scratch. Use
  * final entry staging space for raw slots, then expand backwards in place. */
 w->catalog.slots=(struct ocnext_chained_slot*)(void*)entries;w->catalog.capacity=r->slot_quota;w->catalog.abi_version=1;
 int code=ocnext_chained_collect(s,&w->scanner,raw,collector_bytes,&w->summary,w->raw_segments,&w->catalog);
 if(code)return code==OCNEXT_CHAINED_BUDGET?OCNEXT_FIXUP_INDEX_QUOTA:code==OCNEXT_CHAINED_DIGEST?OCNEXT_FIXUP_INDEX_DIGEST:OCNEXT_FIXUP_INDEX_STRUCTURE;
 uint64_t count=w->catalog.count;
 for(uint64_t i=count;i;i--){struct ocnext_chained_slot slot;cp(&slot,(const uint8_t*)(void*)entries+(i-1)*48u,48);z(entries+i-1,64);cp(&entries[i-1].slot,&slot,48);entries[i-1].walk_ordinal=i-1;}
 code=parse_header(s->bytes,s->byte_count,0,0,0,w,events);if(code)return code;
 /* Page geometry belongs to validated starts metadata even when a segment has
  * zero slots. Do not infer unknown geometry from stored zero entry counts. */
 const uint8_t*payload=s->bytes+w->summary.payload_file_offset;
 for(unsigned i=0;i<w->summary.root_segments;i++){uint32_t rel=u32(payload+32+i*4);if(rel){w->segments[i].page_bytes=u16(payload+28+rel+4);w->segments[i].pointer_format=8;}}
 for(unsigned i=0;i<w->inner_count;i++){code=parse_header(s->bytes,s->byte_count,w->inners[i].off,w->inners[i].vm,i+1,w,events);if(code)return code;}
 if((code=sort(w,entries,count))||(code=event_sort(w,events)))return code;
 for(uint64_t i=0;i<count;i++){
  if((code=charge(w,1)))return code;
  struct ocnext_fixup_index_entry*e=entries+i;uint8_t f,g;uint16_t a,b;uint64_t av,bv;
  if((code=observe(w,events,e->slot.file_offset,&f,&a,&av))||(code=observe(w,events,e->slot.file_offset+4,&g,&b,&bv)))return code;f|=g;uint16_t owner=a==b?a:65535;
  const struct ocnext_fixup_index_segment*seg=&w->segments[e->slot.segment_index];e->root_initprot=(uint8_t)seg->initprot;e->inner_initprot=(uint8_t)(((f&MF_READ)?1:0)|((f&MF_WRITE)?2:0)|((f&MF_EXEC)?4:0));e->inner_owner=owner;
  uint32_t flags=0;if(f&MF_META)flags|=1;if((f&MF_EXEC)||(seg->initprot&4))flags|=2;if((f&(MF_UNKNOWN|MF_CONFLICT))||w->global_unknown||owner==65535||(w->inner_count&&!(f&MF_INNER))||((f&MF_INNER)&&(e->root_initprot!=e->inner_initprot||av!=bv||av!=seg->segment.vmaddr-seg->segment.fileoff)))flags|=8;
  if(seg->initprot&1)flags|=16;if(seg->initprot&2)flags|=32;if(f&MF_INNER)flags|=64;
  if(e->slot.file_offset%4||!bound(s->byte_count,e->slot.file_offset,8))return OCNEXT_FIXUP_INDEX_STRUCTURE;
  if(e->slot.file_offset-seg->segment.fileoff-(uint64_t)e->slot.page_index*e->slot.page_size>e->slot.page_size-8)flags|=128;
  if(!(flags&(1|2|8))&&(flags&16))flags|=4;e->classification=flags;
  if(seg->page_bytes&&seg->page_bytes!=e->slot.page_size)return OCNEXT_FIXUP_INDEX_STRUCTURE;w->segments[e->slot.segment_index].page_bytes=e->slot.page_size;w->segments[e->slot.segment_index].pointer_format=8;
  for(unsigned j=0;j<8;j++)if(flags&(1u<<j))w->state.classification_counts[j]++;
 }
 for(uint64_t i=1;i<count;i++)if(entries[i].slot.file_offset<entries[i-1].slot.file_offset+8)return OCNEXT_FIXUP_INDEX_STRUCTURE;
 struct ocnext_fixup_index_state*state=&w->state;state->source=s->bytes;state->entries=storage->entries;state->segments=storage->segments;state->image_bytes=s->byte_count;state->count=count;state->capacity=storage->capacity;state->source_id=s->source_id;state->source_epoch=s->source_epoch;state->owner_id=r->owner_id;state->index_epoch=1;cp(state->source_sha256,w->summary.image_sha256,32);
 if(!hash_entries(entries,count,state->entries_sha256)||!hash_segments(w->segments,state->segments_sha256))return OCNEXT_FIXUP_INDEX_OVERFLOW;
 state->abi_version=1;state->profile=r->profile;state->lifecycle=1;
 /* All fallible work completed. Unused output capacity remains untouched. */
 cp(storage->entries,entries,(size_t)count*64u);cp(storage->segments,w->segments,32u*64u);cp(out,state,sizeof(*out));return 0;
}
static int state_valid(const struct ocnext_fixup_index_state*s){return s->abi_version==1&&!s->reserved&&s->lifecycle==1&&(s->profile==1||s->profile==2)&&s->owner_id&&s->source_id&&s->source_epoch&&s->index_epoch&&s->count<=s->capacity&&s->capacity&&s->capacity<=1000000&&s->image_bytes>=32&&s->image_bytes<=OCNEXT_CHAINED_MAX_IMAGE;}
static int request_valid(const struct ocnext_fixup_index_state*s,const struct ocnext_fixup_index_read_request*r,int opening){return r->abi_version==1&&r->owner_id==s->owner_id&&r->source_id==s->source_id&&r->source_epoch==s->source_epoch&&r->index_epoch==s->index_epoch&&(opening?(!r->count&&!r->first_ordinal):(r->count&&r->count<=128&&bound(s->count,r->first_ordinal,r->count)));}
static enum ocnext_fixup_index_code spans_state(struct span*spans,unsigned*ns,const struct ocnext_fixup_index_state*s){if(!state_valid(s))return OCNEXT_FIXUP_INDEX_STALE;if(!span(spans,ns,s->source,(size_t)s->image_bytes,1)||!span(spans,ns,s->entries,(size_t)s->capacity*64u,8)||!span(spans,ns,s->segments,32u*64u,8))return OCNEXT_FIXUP_INDEX_ARGUMENT;return 0;}
static enum ocnext_fixup_index_code verify(const struct ocnext_chained_snapshot*s,const struct ocnext_fixup_index_state*state){if(s->abi_version!=1||s->reserved||s->bytes!=state->source||s->byte_count!=state->image_bytes||s->source_id!=state->source_id||s->source_epoch!=state->source_epoch||!eq(s->expected_sha256,state->source_sha256,32))return OCNEXT_FIXUP_INDEX_STALE;uint8_t d[32];if(ocnext_sha256_digest(state->source,(size_t)state->image_bytes,d)||!eq(d,state->source_sha256,32)||!hash_entries(state->entries,state->count,d)||!eq(d,state->entries_sha256,32)||!hash_segments(state->segments,d)||!eq(d,state->segments_sha256,32))return OCNEXT_FIXUP_INDEX_DIGEST;return 0;}
static int selected(const struct ocnext_fixup_index_state*s,const struct ocnext_fixup_index_read_request*r){for(uint64_t i=r->first_ordinal;i<r->first_ordinal+r->count;i++){const struct ocnext_fixup_index_entry*e=s->entries+i;const struct ocnext_chained_slot*t=&e->slot;if(t->segment_index>=32||e->classification&~255u||e->root_initprot>7||e->inner_initprot>7||e->walk_ordinal>=s->count||!bound(s->image_bytes,t->file_offset,8)||(t->file_offset&3)||u64(s->source+t->file_offset)!=t->encoded_word||t->target_offset!=(t->encoded_word&UINT64_C(0x3fffffff))||t->next_units!=((t->encoded_word>>51)&4095)||t->key_selector!=((t->encoded_word>>49)&3)||t->diversity!=(uint16_t)(t->encoded_word>>32)||t->cache_level!=((t->encoded_word>>30)&3)||t->address_diversity!=((t->encoded_word>>48)&1)||t->authenticated!=(t->encoded_word>>63))return 0;const struct ocnext_fixup_index_segment*g=s->segments+t->segment_index;
 if((t->page_size!=4096&&t->page_size!=16384)||g->page_bytes!=t->page_size||g->pointer_format!=8||e->root_initprot!=g->initprot||t->file_offset<g->segment.fileoff)return 0;
 uint64_t within=t->file_offset-g->segment.fileoff,current=within%t->page_size;
 if(t->page_index!=within/t->page_size||current>t->page_size-4||(current>t->page_size-8&&t->next_units)||!bound(g->segment.vmsize,within,8)||((e->classification&128)!=0)!=(current>t->page_size-8)||((e->classification&16)!=0)!=((g->initprot&1)!=0)||((e->classification&32)!=0)!=((g->initprot&2)!=0)||(e->classification&4&&(e->classification&11)))return 0;
 if(t->next_units){uint64_t next=current+(uint64_t)t->next_units*4;if(next>t->page_size-4||!bound(g->segment.filesize,within-current+next,8))return 0;}
 if(t->file_offset<g->segment.fileoff||!bound(g->segment.filesize,t->file_offset-g->segment.fileoff,8)||t->image_vm_offset!=g->segment.vmaddr-s->segments[0].segment.vmaddr+t->file_offset-g->segment.fileoff){/* root VM minimum may not be segment0 */uint64_t base=UINT64_MAX;for(unsigned j=0;j<32;j++)if(s->segments[j].segment.vmsize&&s->segments[j].segment.vmaddr<base)base=s->segments[j].segment.vmaddr;if(t->file_offset<g->segment.fileoff||!bound(g->segment.filesize,t->file_offset-g->segment.fileoff,8)||t->image_vm_offset!=g->segment.vmaddr-base+t->file_offset-g->segment.fileoff)return 0;}if((i&&s->entries[i-1].slot.file_offset+8>t->file_offset)||(i+1<s->count&&t->file_offset+8>s->entries[i+1].slot.file_offset))return 0;}return 1;}
enum ocnext_fixup_index_code ocnext_fixup_index_read(const struct ocnext_chained_snapshot*s,const struct ocnext_fixup_index_state*state,const struct ocnext_fixup_index_read_request*r,struct ocnext_fixup_index_entry*out){struct span spans[7];unsigned ns=0;if(!span(spans,&ns,s,sizeof(*s),8)||!span(spans,&ns,state,sizeof(*state),8)||!span(spans,&ns,r,sizeof(*r),8))return 1;enum ocnext_fixup_index_code c=spans_state(spans,&ns,state);if(c)return c;if(!request_valid(state,r,0))return OCNEXT_FIXUP_INDEX_STALE;if(!span(spans,&ns,out,(size_t)r->count*64u,8))return 1;if((c=verify(s,state)))return c;if(!selected(state,r))return OCNEXT_FIXUP_INDEX_STRUCTURE;cp(out,state->entries+r->first_ordinal,(size_t)r->count*64u);return 0;}
enum ocnext_fixup_index_code ocnext_fixup_index_invalidate(struct ocnext_fixup_index_state*s,uint64_t owner,uint64_t epoch){struct span spans[4];unsigned ns=0;if(!span(spans,&ns,s,sizeof(*s),8))return 1;enum ocnext_fixup_index_code c=spans_state(spans,&ns,s);if(c)return c;if(owner!=s->owner_id||epoch!=s->index_epoch)return OCNEXT_FIXUP_INDEX_STALE;if(epoch==UINT64_MAX)return OCNEXT_FIXUP_INDEX_OVERFLOW;s->index_epoch++;s->lifecycle=2;return 0;}
enum ocnext_fixup_index_code ocnext_fixup_index_open(const struct ocnext_chained_snapshot*s,const struct ocnext_fixup_index_state*state,const struct ocnext_fixup_index_read_request*r,struct ocnext_fixup_index_lease*out){struct span spans[7];unsigned ns=0;if(!span(spans,&ns,s,sizeof(*s),8)||!span(spans,&ns,state,sizeof(*state),8)||!span(spans,&ns,r,sizeof(*r),8)||!span(spans,&ns,out,sizeof(*out),8))return 1;enum ocnext_fixup_index_code c=spans_state(spans,&ns,state);if(c)return c;if(!request_valid(state,r,1)||!iszero(out,sizeof(*out)))return OCNEXT_FIXUP_INDEX_STALE;if((c=verify(s,state)))return c;struct ocnext_fixup_index_lease l={0};l.state=state;l.source=state->source;l.entries=state->entries;l.segments=state->segments;l.owner_id=state->owner_id;l.source_id=state->source_id;l.source_epoch=state->source_epoch;l.index_epoch=state->index_epoch;l.image_bytes=state->image_bytes;l.count=state->count;l.capacity=state->capacity;l.abi_version=1;l.lifecycle=1;cp(out,&l,sizeof(l));return 0;}
static int lease_binding(const struct ocnext_fixup_index_lease*l){const struct ocnext_fixup_index_state*s=l->state;return l->abi_version==1&&l->lifecycle==1&&!l->reserved[0]&&!l->reserved[1]&&l->source==s->source&&l->entries==s->entries&&l->segments==s->segments&&l->owner_id==s->owner_id&&l->source_id==s->source_id&&l->source_epoch==s->source_epoch&&l->index_epoch==s->index_epoch&&l->image_bytes==s->image_bytes&&l->count==s->count&&l->capacity==s->capacity;}
enum ocnext_fixup_index_code ocnext_fixup_index_read_lease(const struct ocnext_fixup_index_lease*l,const struct ocnext_fixup_index_read_request*r,struct ocnext_fixup_index_entry*out){struct span spans[7];unsigned ns=0;if(!span(spans,&ns,l,sizeof(*l),8)||!span(spans,&ns,r,sizeof(*r),8)||!span(spans,&ns,l->state,sizeof(*l->state),8))return 1;enum ocnext_fixup_index_code c=spans_state(spans,&ns,l->state);if(c)return c;if(!lease_binding(l)||!request_valid(l->state,r,0))return OCNEXT_FIXUP_INDEX_STALE;if(!span(spans,&ns,out,(size_t)r->count*64u,8))return 1;if(!selected(l->state,r))return OCNEXT_FIXUP_INDEX_STRUCTURE;cp(out,l->entries+r->first_ordinal,(size_t)r->count*64u);return 0;}
enum ocnext_fixup_index_code ocnext_fixup_index_close(struct ocnext_fixup_index_lease*l){struct span spans[5];unsigned ns=0;if(!span(spans,&ns,l,sizeof(*l),8)||!span(spans,&ns,l->state,sizeof(*l->state),8))return 1;enum ocnext_fixup_index_code c=spans_state(spans,&ns,l->state);if(c)return c;if(!lease_binding(l))return OCNEXT_FIXUP_INDEX_STALE;l->lifecycle=2;return 0;}
enum ocnext_fixup_index_code ocnext_fixup_index_adapt(const struct ocnext_chained_snapshot*s,const struct ocnext_fixup_index_state*state,const struct ocnext_fixup_index_read_request*r,const struct ocnext_fixup_index_resolution*res,const struct ocnext_fixup_capability*cap,union ocnext_fixup_index_workspace*workspace,struct ocnext_fixup_candidate*out,struct ocnext_fixup_segment*segments,struct ocnext_fixup_index_adapter_result*result){
 struct span spans[12];unsigned ns=0;if(!span(spans,&ns,s,sizeof(*s),8)||!span(spans,&ns,state,sizeof(*state),8)||!span(spans,&ns,r,sizeof(*r),8)||!span(spans,&ns,cap,sizeof(*cap),8)||!span(spans,&ns,workspace,sizeof(*workspace),_Alignof(union ocnext_fixup_index_workspace))||!span(spans,&ns,result,sizeof(*result),8))return 1;
 enum ocnext_fixup_index_code c=spans_state(spans,&ns,state);if(c)return c;if(!request_valid(state,r,0))return OCNEXT_FIXUP_INDEX_STALE;if(!span(spans,&ns,res,(size_t)r->count*96u,8)||!span(spans,&ns,out,(size_t)r->count*64u,8)||!span(spans,&ns,segments,32u*40u,8))return 1;
 if((c=verify(s,state)))return c;if(state->profile!=2)return OCNEXT_FIXUP_INDEX_UNSUPPORTED;if(!selected(state,r))return OCNEXT_FIXUP_INDEX_STRUCTURE;
 if(cap->abi_version!=1||cap->profile!=1||cap->flags!=3||cap->reserved||cap->owner_id!=state->owner_id||!cap->key_generation||!ocnext_pac_keys_valid(&cap->bank)||!ocnext_pac_pointer_config_valid(&cap->geometry)||cap->bank.profile!=1||cap->bank.owner_id!=cap->owner_id||cap->bank.generation!=cap->key_generation)return OCNEXT_FIXUP_INDEX_RESOLUTION;
 struct adapter_work*w=&((union work*)(void*)workspace)->adapt;z(w,sizeof(*w));uint64_t base=UINT64_MAX;for(unsigned i=0;i<32;i++)if(state->segments[i].segment.vmsize&&state->segments[i].segment.vmaddr<base)base=state->segments[i].segment.vmaddr;
 for(unsigned i=0;i<32;i++){const struct ocnext_fixup_index_segment*g=state->segments+i;if(!g->segment.vmsize)continue;w->segments[i].file_offset=g->segment.fileoff;w->segments[i].file_bytes=g->segment.filesize;w->segments[i].image_vm_offset=g->segment.vmaddr-base;w->segments[i].vm_bytes=g->segment.vmsize;w->segments[i].page_bytes=g->page_bytes?g->page_bytes:4096;w->segments[i].pointer_format=8;}
 for(unsigned i=0;i<r->count;i++){
  const struct ocnext_fixup_index_resolution*x=res+i;const struct ocnext_fixup_index_entry*e=state->entries+r->first_ordinal+i;const struct ocnext_chained_slot*t=&e->slot;
  if((e->classification&(OCNEXT_FIXUP_INDEX_METADATA|OCNEXT_FIXUP_INDEX_EXECUTE|OCNEXT_FIXUP_INDEX_UNKNOWN))||(e->classification&(OCNEXT_FIXUP_INDEX_DATA|OCNEXT_FIXUP_INDEX_READABLE|OCNEXT_FIXUP_INDEX_WRITABLE))!=(OCNEXT_FIXUP_INDEX_DATA|OCNEXT_FIXUP_INDEX_READABLE|OCNEXT_FIXUP_INDEX_WRITABLE))return OCNEXT_FIXUP_INDEX_UNSUPPORTED;
  if(x->abi_version!=1||x->reserved||x->owner_id!=state->owner_id||x->source_id!=state->source_id||x->source_epoch!=state->source_epoch||x->index_epoch!=state->index_epoch||x->key_generation!=cap->key_generation||x->ordinal!=r->first_ordinal+i||!eq(&x->geometry,&cap->geometry,16)||x->flags!=(t->authenticated?7u:2u)||x->key_index!=(t->authenticated?t->key_selector:0u)||(!t->authenticated&&x->modifier))return OCNEXT_FIXUP_INDEX_RESOLUTION;
  if(t->authenticated&&!(cap->bank.known_mask&(1u<<t->key_selector)))return OCNEXT_FIXUP_INDEX_RESOLUTION;
  struct ocnext_fixup_candidate*v=w->candidates+i;v->file_offset=t->file_offset;v->original_word=t->encoded_word;v->resolved_pointer=x->resolved_pointer;v->modifier=x->modifier;v->image_vm_offset=t->image_vm_offset;v->segment_index=t->segment_index;v->flags=x->flags;v->key_index=x->key_index;
 }
 w->result.owner_id=state->owner_id;w->result.index_epoch=state->index_epoch;w->result.key_generation=cap->key_generation;w->result.count=r->count;w->result.abi_version=1;
 cp(out,w->candidates,(size_t)r->count*64u);cp(segments,w->segments,sizeof(w->segments));cp(result,&w->result,sizeof(*result));return 0;
}
