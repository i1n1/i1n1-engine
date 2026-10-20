#include "ocnext/backend_heap.h"
#include "../../../third_party/tlsf/tlsf.h"
#include "tlsf_include/assert.h"
#include <stddef.h>
#include <stdint.h>

/* This bookkeeping seal is a non-authenticated corruption diagnostic. Native
 * callers still own stable serialized storage and trusted allocator metadata;
 * neither this registry nor TLSF validates hostile native links or payload
 * overruns. Every source TLSF assertion/diagnostic terminates in a real trap.
 */
struct ocnext_backend_heap {
    uint64_t magic,self;
    uint32_t abi_version,phase;
    uint64_t owner,generation,pool_address,pool_bytes;
    uint64_t registry_address,registry_bytes,registry_capacity;
    uint64_t control_address,managed_address,managed_bytes;
    uint64_t live_count,live_requested,peak_requested,next_serial;
    uint64_t registry_seal,seal;
    uint64_t reserved[13];
};
struct native_span {uintptr_t begin,end;};
struct registry_scan {size_t free_slot;};

#define HEAP_MAGIC UINT64_C(0x4f4e485450323001)
#define NO_SLOT ((size_t)-1)
#define CONTROL_PREFIX ((size_t)6544)

_Static_assert(sizeof(void *)==8 && sizeof(uintptr_t)==8 && sizeof(size_t)==8,"native64 heap");
_Static_assert(sizeof(struct ocnext_backend_heap)==256,"opaque storage ABI1");
_Static_assert(offsetof(struct ocnext_backend_heap,seal)==144,"private seal position");
_Static_assert(sizeof(struct ocnext_backend_heap_config)==40,"config ABI1");
_Static_assert(sizeof(struct ocnext_backend_heap_allocation)==32,"entry/descriptor ABI1");
_Static_assert(sizeof(struct ocnext_backend_heap_stats)==80,"stats ABI1");
_Static_assert(_Alignof(struct ocnext_backend_heap_config)==8 &&
               _Alignof(struct ocnext_backend_heap_allocation)==8 &&
               _Alignof(struct ocnext_backend_heap_stats)==8,"native object alignment");

/* The public contract retains stable, serialized ordinary native RAM.
 * No helper accepts MMIO, volatile device registers or concurrent mutation.
 * Byte access width/order is not a public effect. Exact whole-span bounds and
 * every caller preflight remain unchanged. Constant-size copying avoids
 * aligned-u64 pointer casts, effective-type assumptions and widened tails. */
#if defined(__has_builtin)
# if __has_builtin(__builtin_memcpy_inline)
#  define HEAP_HAVE_COPY8 1
# endif
#endif
#ifndef HEAP_HAVE_COPY8
# define HEAP_HAVE_COPY8 0
#endif
_Static_assert(sizeof(uint64_t)==8,"8-byte RAM helper word");

static uint64_t bytes_load8(const void *source)
{
    uint64_t word;
#if HEAP_HAVE_COPY8
    __builtin_memcpy_inline(&word,source,8);
#else
    unsigned char *d=(unsigned char *)&word;
    const volatile unsigned char *s=(const volatile unsigned char *)source;
    for(size_t i=0;i<8;++i)d[i]=s[i];
#endif
    return word;
}
static void bytes_store8(void *destination,uint64_t word)
{
#if HEAP_HAVE_COPY8
    __builtin_memcpy_inline(destination,&word,8);
#else
    volatile unsigned char *d=(volatile unsigned char *)destination;
    const unsigned char *s=(const unsigned char *)&word;
    for(size_t i=0;i<8;++i)d[i]=s[i];
#endif
}
static void bytes_copy(void *out,const void *in,size_t bytes)
{
    unsigned char *d=(unsigned char *)out;
    const unsigned char *s=(const unsigned char *)in;
    /* All callers require disjoint input/output complete spans. */
    while(bytes>=32) {
        uint64_t a=bytes_load8(s),b=bytes_load8(s+8);
        uint64_t c=bytes_load8(s+16),e=bytes_load8(s+24);
        bytes_store8(d,a);bytes_store8(d+8,b);
        bytes_store8(d+16,c);bytes_store8(d+24,e);
        s+=32;d+=32;bytes-=32;
    }
    while(bytes>=8) {uint64_t word=bytes_load8(s);bytes_store8(d,word);s+=8;d+=8;bytes-=8;}
    for(size_t i=0;i<bytes;++i)((volatile unsigned char *)d)[i]=((const volatile unsigned char *)s)[i];
}
static void bytes_zero(void *out,size_t bytes)
{
    unsigned char *d=(unsigned char *)out;
    while(bytes>=32) {
        bytes_store8(d,0);bytes_store8(d+8,0);bytes_store8(d+16,0);bytes_store8(d+24,0);
        d+=32;bytes-=32;
    }
    while(bytes>=8) {bytes_store8(d,0);d+=8;bytes-=8;}
    for(size_t i=0;i<bytes;++i)((volatile unsigned char *)d)[i]=0;
}
static int all_zero(const void *in,size_t bytes)
{
    const unsigned char *p=(const unsigned char *)in;
    uint64_t bits=0;
    while(bytes>=32) {
        uint64_t a=bytes_load8(p),b=bytes_load8(p+8);
        uint64_t c=bytes_load8(p+16),d=bytes_load8(p+24);
        bits|=a|b|c|d;p+=32;bytes-=32;
    }
    while(bytes>=8) {bits|=bytes_load8(p);p+=8;bytes-=8;}
    for(size_t i=0;i<bytes;++i)bits|=((const volatile unsigned char *)p)[i];
    return bits==0;
}
static int span(const void *pointer,size_t bytes,size_t alignment,struct native_span *out)
{
    uintptr_t p=(uintptr_t)pointer;
    if(!p || !bytes || p%alignment || bytes>UINTPTR_MAX-p)return 0;
    out->begin=p;out->end=p+bytes;return 1;
}
static int intersects(struct native_span a,struct native_span b)
{return a.begin<b.end && b.begin<a.end;}
static int alignment_valid(uint64_t a)
{
    return a>=OCNEXT_BACKEND_HEAP_MIN_ALIGNMENT && a<=OCNEXT_BACKEND_HEAP_MAX_ALIGNMENT && !(a&(a-1));
}
static uint64_t hash_bytes(const void *data,size_t bytes)
{
    const unsigned char *p=(const unsigned char *)data;
    uint64_t h=UINT64_C(14695981039346656037);
    /* All arithmetic is uint64_t: the three products derive P^8 modulo2^64.
     * The branch is based on the actual eight bytes just read, not cached
     * metadata or an assumption that unused entries remain zero. */
    const uint64_t prime=UINT64_C(1099511628211);
    const uint64_t prime2=prime*prime,prime4=prime2*prime2,prime8=prime4*prime4;
    while(bytes>=8) {
        uint64_t word=bytes_load8(p);
        /* Character inspection of the local object representation preserves
         * address-byte order on every endian; no native shift-order guess. */
        const unsigned char *b=(const unsigned char *)&word;
        if(word==0) {h*=prime8;} else {
        h=(h^b[0])*UINT64_C(1099511628211);
        h=(h^b[1])*UINT64_C(1099511628211);
        h=(h^b[2])*UINT64_C(1099511628211);
        h=(h^b[3])*UINT64_C(1099511628211);
        h=(h^b[4])*UINT64_C(1099511628211);
        h=(h^b[5])*UINT64_C(1099511628211);
        h=(h^b[6])*UINT64_C(1099511628211);
        h=(h^b[7])*UINT64_C(1099511628211);
        }
        p+=8;bytes-=8;
    }
    for(size_t i=0;i<bytes;++i)h=(h^((const volatile unsigned char *)p)[i])*UINT64_C(1099511628211);
    return h;
}
static uint64_t header_seal(const struct ocnext_backend_heap *s)
{
    const volatile unsigned char *p=(const volatile unsigned char *)s;
    uint64_t h=UINT64_C(14695981039346656037);
    for(size_t i=0;i<sizeof(*s);++i)if(i<144 || i>=152)h=(h^p[i])*UINT64_C(1099511628211);
    return h;
}
static void entry_read(const struct ocnext_backend_heap *s,size_t i,struct ocnext_backend_heap_allocation *entry)
{
    bytes_copy(entry,(const unsigned char *)(uintptr_t)s->registry_address+i*sizeof(*entry),sizeof(*entry));
}
static void entry_write(const struct ocnext_backend_heap *s,size_t i,const struct ocnext_backend_heap_allocation *entry)
{
    bytes_copy((unsigned char *)(uintptr_t)s->registry_address+i*sizeof(*entry),entry,sizeof(*entry));
}
static void publish_state(struct ocnext_backend_heap *heap,struct ocnext_backend_heap *s)
{
    s->registry_seal=hash_bytes((const void *)(uintptr_t)s->registry_address,(size_t)s->registry_bytes);
    s->seal=header_seal(s);bytes_copy(heap,s,sizeof(*s));
}

static int initial_api_spans(const struct ocnext_backend_heap *heap,const void *one,size_t one_bytes,
                             const void *two,size_t two_bytes)
{
    struct native_span h,a={0,0},b={0,0};
    if(!span(heap,256,16,&h))return 0;
    if(one_bytes && (!span(one,one_bytes,8,&a) || intersects(h,a)))return 0;
    if(two_bytes && (!span(two,two_bytes,8,&b) || intersects(h,b) || (one_bytes && intersects(a,b))))return 0;
    return 1;
}
static int external_allowed(const struct ocnext_backend_heap *s,const void *pointer,size_t bytes)
{
    struct native_span p,pool,registry;
    return span(pointer,bytes,8,&p) && span((const void *)(uintptr_t)s->pool_address,(size_t)s->pool_bytes,16,&pool) &&
           span((const void *)(uintptr_t)s->registry_address,(size_t)s->registry_bytes,8,&registry) &&
           !intersects(p,pool) && !intersects(p,registry);
}
static enum ocnext_backend_heap_code load_state(const struct ocnext_backend_heap *heap,struct ocnext_backend_heap *s)
{
    struct native_span h,p,r;
    bytes_copy(s,heap,sizeof(*s));
    if(all_zero(s,sizeof(*s)))return OCNEXT_BACKEND_HEAP_BAD_STATE;
    if(s->magic!=HEAP_MAGIC || s->self!=(uint64_t)(uintptr_t)heap || s->abi_version!=1 ||
       (s->phase!=OCNEXT_BACKEND_HEAP_ACTIVE && s->phase!=OCNEXT_BACKEND_HEAP_CLOSED) ||
       !s->owner || !s->generation || !all_zero(s->reserved,sizeof(s->reserved)) || s->seal!=header_seal(s))
        return OCNEXT_BACKEND_HEAP_CORRUPT;
    if(s->pool_bytes<OCNEXT_BACKEND_HEAP_MIN_POOL || s->pool_bytes>OCNEXT_BACKEND_HEAP_MAX_POOL ||
       !s->registry_capacity || s->registry_capacity>OCNEXT_BACKEND_HEAP_MAX_ENTRIES ||
       s->registry_bytes!=s->registry_capacity*32 ||
       !span(heap,256,16,&h) || !span((const void *)(uintptr_t)s->pool_address,(size_t)s->pool_bytes,16,&p) ||
       !span((const void *)(uintptr_t)s->registry_address,(size_t)s->registry_bytes,8,&r) ||
       intersects(h,p) || intersects(h,r) || intersects(p,r) ||
       s->control_address!=s->pool_address || s->managed_address!=s->pool_address+CONTROL_PREFIX ||
       s->managed_bytes!=s->pool_bytes-CONTROL_PREFIX || !s->next_serial ||
       s->live_count>s->registry_capacity || s->live_requested>s->pool_bytes ||
       s->peak_requested<s->live_requested || s->peak_requested>s->pool_bytes ||
       (s->phase==OCNEXT_BACKEND_HEAP_CLOSED && (s->live_count || s->live_requested)))
        return OCNEXT_BACKEND_HEAP_CORRUPT;
    return OCNEXT_BACKEND_HEAP_OK;
}
static enum ocnext_backend_heap_code registry_valid(const struct ocnext_backend_heap *s,struct registry_scan *scan)
{
    uint64_t count=0,requested=0;scan->free_slot=NO_SLOT;
    if(hash_bytes((const void *)(uintptr_t)s->registry_address,(size_t)s->registry_bytes)!=s->registry_seal)
        return OCNEXT_BACKEND_HEAP_CORRUPT;
    for(size_t i=0;i<(size_t)s->registry_capacity;++i) {
        struct ocnext_backend_heap_allocation e;struct native_span p;
        entry_read(s,i,&e);
        if(all_zero(&e,sizeof(e))) {if(scan->free_slot==NO_SLOT)scan->free_slot=i;continue;}
        if(!e.native || !e.requested_bytes || e.requested_bytes>s->pool_bytes || !alignment_valid(e.alignment) ||
           !e.serial || e.serial>=s->next_serial || !span(e.native,(size_t)e.requested_bytes,(size_t)e.alignment,&p) ||
           p.begin<s->managed_address || p.end>s->pool_address+s->pool_bytes ||
           e.requested_bytes>UINT64_MAX-requested)
            return OCNEXT_BACKEND_HEAP_CORRUPT;
        ++count;requested+=e.requested_bytes;
    }
    return count==s->live_count && requested==s->live_requested?OCNEXT_BACKEND_HEAP_OK:OCNEXT_BACKEND_HEAP_CORRUPT;
}
static size_t find_exact(const struct ocnext_backend_heap *s,const struct ocnext_backend_heap_allocation *old)
{
    if(!old->native)return NO_SLOT;
    for(size_t i=0;i<(size_t)s->registry_capacity;++i) {
        struct ocnext_backend_heap_allocation e;entry_read(s,i,&e);
        if(e.native==old->native && e.requested_bytes==old->requested_bytes &&
           e.alignment==old->alignment && e.serial==old->serial)return i;
    }
    return NO_SLOT;
}
static int tlsf_request_safe(const struct ocnext_backend_heap *s,uint64_t bytes,uint64_t alignment)
{
    uint64_t adjusted,gapped,rounded;
    if(bytes>s->pool_bytes || bytes>UINT64_MAX-7)return 0;
    adjusted=(bytes+7)&~UINT64_C(7);if(adjusted<24)adjusted=24;
    if(adjusted>=UINT64_C(4294967296) || alignment>UINT64_MAX-adjusted ||
       adjusted+alignment>UINT64_MAX-32)return 0;
    gapped=adjusted+alignment+32;
    if(gapped>UINT64_MAX-(alignment-1))return 0;
    rounded=(gapped+alignment-1)&~(alignment-1);
    return rounded<UINT64_C(4294967296);
}
static void allocated_pointer(const struct ocnext_backend_heap *s,void *pointer,uint64_t bytes,uint64_t alignment)
{
    struct native_span p;
    if(!span(pointer,(size_t)bytes,(size_t)alignment,&p) || p.begin<s->managed_address || p.end>s->pool_address+s->pool_bytes)
        ocnext_backend_tlsf_assert_fail("TLSF returned out-of-contract allocation",__FILE__,__LINE__);
}

enum ocnext_backend_heap_code ocnext_backend_heap_initialize(void *storage,size_t storage_bytes,void *pool,size_t pool_bytes,
    void *registry,size_t registry_bytes,const struct ocnext_backend_heap_config *config)
{
    struct native_span spans[4];struct ocnext_backend_heap_config c;struct ocnext_backend_heap s;
    if(storage_bytes!=256 || pool_bytes<OCNEXT_BACKEND_HEAP_MIN_POOL || pool_bytes>OCNEXT_BACKEND_HEAP_MAX_POOL ||
       !registry_bytes || registry_bytes%32 || registry_bytes/32>OCNEXT_BACKEND_HEAP_MAX_ENTRIES ||
       !span(storage,storage_bytes,16,&spans[0]) || !span(pool,pool_bytes,16,&spans[1]) ||
       !span(registry,registry_bytes,8,&spans[2]) || !span(config,40,8,&spans[3]))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    for(unsigned i=0;i<4;++i)for(unsigned j=i+1;j<4;++j)if(intersects(spans[i],spans[j]))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    bytes_copy(&c,config,sizeof(c));
    if(c.abi_version!=1 || c.bytes!=40 || !c.owner || !c.generation || c.reserved ||
       c.registry_capacity!=registry_bytes/32)return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(!all_zero(storage,256))return OCNEXT_BACKEND_HEAP_BAD_STATE;
    if(!all_zero(registry,registry_bytes))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(tlsf_size()!=6536 || tlsf_align_size()!=8 || tlsf_block_size_min()!=24 ||
       tlsf_block_size_max()!=UINT64_C(4294967296) || tlsf_pool_overhead()!=16 || tlsf_alloc_overhead()!=8 ||
       pool_bytes-CONTROL_PREFIX<40)return OCNEXT_BACKEND_HEAP_CORRUPT;
    bytes_zero(&s,sizeof(s));s.magic=HEAP_MAGIC;s.self=(uint64_t)(uintptr_t)storage;s.abi_version=1;s.phase=OCNEXT_BACKEND_HEAP_ACTIVE;
    s.owner=c.owner;s.generation=c.generation;s.pool_address=(uint64_t)(uintptr_t)pool;s.pool_bytes=pool_bytes;
    s.registry_address=(uint64_t)(uintptr_t)registry;s.registry_bytes=registry_bytes;s.registry_capacity=c.registry_capacity;
    s.control_address=s.pool_address;s.managed_address=s.pool_address+CONTROL_PREFIX;s.managed_bytes=pool_bytes-CONTROL_PREFIX;s.next_serial=1;
    if(tlsf_create(pool)!=pool || tlsf_add_pool(pool,(void *)(uintptr_t)s.managed_address,(size_t)s.managed_bytes)!=(void *)(uintptr_t)s.managed_address)
        ocnext_backend_tlsf_assert_fail("preflighted TLSF initialization",__FILE__,__LINE__);
    publish_state((struct ocnext_backend_heap *)storage,&s);
    return OCNEXT_BACKEND_HEAP_OK;
}

enum ocnext_backend_heap_code ocnext_backend_heap_allocate(struct ocnext_backend_heap *heap,uint64_t bytes,uint64_t alignment,
    struct ocnext_backend_heap_allocation *out)
{
    struct ocnext_backend_heap s;struct registry_scan scan;enum ocnext_backend_heap_code code;
    struct ocnext_backend_heap_allocation e;
    if(!initial_api_spans(heap,out,sizeof(*out),NULL,0) || !bytes || !alignment_valid(alignment))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(!external_allowed(&s,out,sizeof(*out)))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(s.phase!=OCNEXT_BACKEND_HEAP_ACTIVE)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    code=registry_valid(&s,&scan);if(code)return code;
    if(!tlsf_request_safe(&s,bytes,alignment))return OCNEXT_BACKEND_HEAP_EXHAUSTED;
    if(scan.free_slot==NO_SLOT || s.next_serial==UINT64_MAX || s.live_count==UINT64_MAX || bytes>UINT64_MAX-s.live_requested)
        return OCNEXT_BACKEND_HEAP_QUOTA;
    e.native=tlsf_memalign((tlsf_t)(uintptr_t)s.control_address,(size_t)alignment,(size_t)bytes);
    if(!e.native)return OCNEXT_BACKEND_HEAP_EXHAUSTED;
    allocated_pointer(&s,e.native,bytes,alignment);e.requested_bytes=bytes;e.alignment=alignment;e.serial=s.next_serial++;
    ++s.live_count;s.live_requested+=bytes;if(s.live_requested>s.peak_requested)s.peak_requested=s.live_requested;
    entry_write(&s,scan.free_slot,&e);publish_state(heap,&s);bytes_copy(out,&e,sizeof(e));
    return OCNEXT_BACKEND_HEAP_OK;
}

enum ocnext_backend_heap_code ocnext_backend_heap_reallocate(struct ocnext_backend_heap *heap,const struct ocnext_backend_heap_allocation *old,
    uint64_t bytes,uint64_t alignment,struct ocnext_backend_heap_allocation *out)
{
    struct ocnext_backend_heap s;struct registry_scan scan;struct ocnext_backend_heap_allocation before,after;
    enum ocnext_backend_heap_code code;size_t slot;uint64_t remaining;
    if(!initial_api_spans(heap,old,sizeof(*old),out,sizeof(*out)) || !bytes || !alignment_valid(alignment))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(!external_allowed(&s,old,sizeof(*old)) || !external_allowed(&s,out,sizeof(*out)))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(s.phase!=OCNEXT_BACKEND_HEAP_ACTIVE)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    code=registry_valid(&s,&scan);if(code)return code;
    bytes_copy(&before,old,sizeof(before));slot=find_exact(&s,&before);
    if(slot==NO_SLOT)return OCNEXT_BACKEND_HEAP_BAD_HANDLE;
    if(bytes==before.requested_bytes && alignment==before.alignment) {bytes_copy(out,&before,sizeof(before));return OCNEXT_BACKEND_HEAP_OK;}
    if(!tlsf_request_safe(&s,bytes,alignment))return OCNEXT_BACKEND_HEAP_EXHAUSTED;
    remaining=s.live_requested-before.requested_bytes;
    if(s.next_serial==UINT64_MAX || bytes>UINT64_MAX-remaining)return OCNEXT_BACKEND_HEAP_QUOTA;
    after.native=tlsf_memalign((tlsf_t)(uintptr_t)s.control_address,(size_t)alignment,(size_t)bytes);
    if(!after.native)return OCNEXT_BACKEND_HEAP_EXHAUSTED;
    allocated_pointer(&s,after.native,bytes,alignment);
    /* Both complete live spans are owned and disjoint before copying. */
    {struct native_span a,b;
     if(!span(before.native,(size_t)before.requested_bytes,(size_t)before.alignment,&a) ||
        !span(after.native,(size_t)bytes,(size_t)alignment,&b) || intersects(a,b))
         ocnext_backend_tlsf_assert_fail("realloc allocation intersects old payload",__FILE__,__LINE__);}
    bytes_copy(after.native,before.native,(size_t)(before.requested_bytes<bytes?before.requested_bytes:bytes));
    tlsf_free((tlsf_t)(uintptr_t)s.control_address,before.native);
    after.requested_bytes=bytes;after.alignment=alignment;after.serial=s.next_serial++;
    s.live_requested=remaining+bytes;if(s.live_requested>s.peak_requested)s.peak_requested=s.live_requested;
    entry_write(&s,slot,&after);publish_state(heap,&s);bytes_copy(out,&after,sizeof(after));
    return OCNEXT_BACKEND_HEAP_OK;
}

enum ocnext_backend_heap_code ocnext_backend_heap_release(struct ocnext_backend_heap *heap,const struct ocnext_backend_heap_allocation *allocation)
{
    struct ocnext_backend_heap s;struct registry_scan scan;struct ocnext_backend_heap_allocation e,empty;
    enum ocnext_backend_heap_code code;size_t slot;
    if(!initial_api_spans(heap,allocation,sizeof(*allocation),NULL,0))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(!external_allowed(&s,allocation,sizeof(*allocation)))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(s.phase!=OCNEXT_BACKEND_HEAP_ACTIVE)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    code=registry_valid(&s,&scan);if(code)return code;
    bytes_copy(&e,allocation,sizeof(e));slot=find_exact(&s,&e);if(slot==NO_SLOT)return OCNEXT_BACKEND_HEAP_BAD_HANDLE;
    bytes_zero(&empty,sizeof(empty));tlsf_free((tlsf_t)(uintptr_t)s.control_address,e.native);
    --s.live_count;s.live_requested-=e.requested_bytes;entry_write(&s,slot,&empty);publish_state(heap,&s);
    return OCNEXT_BACKEND_HEAP_OK;
}

enum ocnext_backend_heap_code ocnext_backend_heap_lookup(const struct ocnext_backend_heap *heap,const void *native,
    struct ocnext_backend_heap_allocation *out)
{
    struct ocnext_backend_heap s;struct registry_scan scan;enum ocnext_backend_heap_code code;
    if(!initial_api_spans(heap,out,sizeof(*out),NULL,0))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(!external_allowed(&s,out,sizeof(*out)))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    if(s.phase!=OCNEXT_BACKEND_HEAP_ACTIVE)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    code=registry_valid(&s,&scan);if(code)return code;
    if(native)for(size_t i=0;i<(size_t)s.registry_capacity;++i) {
        struct ocnext_backend_heap_allocation e;entry_read(&s,i,&e);
        if(e.native==native) {bytes_copy(out,&e,sizeof(e));return OCNEXT_BACKEND_HEAP_OK;}
    }
    return OCNEXT_BACKEND_HEAP_BAD_HANDLE;
}

enum ocnext_backend_heap_code ocnext_backend_heap_query(const struct ocnext_backend_heap *heap,struct ocnext_backend_heap_stats *out)
{
    struct ocnext_backend_heap s;struct registry_scan scan;struct ocnext_backend_heap_stats stats;
    enum ocnext_backend_heap_code code;
    if(!initial_api_spans(heap,out,sizeof(*out),NULL,0))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(!external_allowed(&s,out,sizeof(*out)))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=registry_valid(&s,&scan);if(code)return code;
    bytes_zero(&stats,sizeof(stats));stats.abi_version=1;stats.bytes=80;stats.phase=s.phase;
    stats.owner=s.owner;stats.generation=s.generation;stats.pool_bytes=s.pool_bytes;stats.registry_capacity=s.registry_capacity;
    stats.live_count=s.live_count;stats.live_requested=s.live_requested;stats.peak_requested=s.peak_requested;stats.next_serial=s.next_serial;
    bytes_copy(out,&stats,sizeof(stats));return OCNEXT_BACKEND_HEAP_OK;
}

enum ocnext_backend_heap_code ocnext_backend_heap_close(struct ocnext_backend_heap *heap)
{
    struct ocnext_backend_heap s;struct registry_scan scan;enum ocnext_backend_heap_code code;
    if(!initial_api_spans(heap,NULL,0,NULL,0))return OCNEXT_BACKEND_HEAP_ARGUMENT;
    code=load_state(heap,&s);if(code)return code;
    if(s.phase!=OCNEXT_BACKEND_HEAP_ACTIVE)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    code=registry_valid(&s,&scan);if(code)return code;
    if(s.live_count)return OCNEXT_BACKEND_HEAP_BAD_STATE;
    s.phase=OCNEXT_BACKEND_HEAP_CLOSED;publish_state(heap,&s);return OCNEXT_BACKEND_HEAP_OK;
}
