#include "ocnext/a64.h"
#include "ocnext/boot_args.h"
#include "ocnext/ordering.h"
#include "ocnext/mmu_cpu.h"
#include "ocnext/sha256.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IMAGE_BYTES ((size_t)96 * 1024 * 1024)
#define MAX_SEGMENTS 256
#define MAX_BUDGET UINT64_C(1000000)
#define MAX_WORKING_STUDY_BUDGET UINT64_C(16000000)
#define MAX_SNAPSHOT_BYTES ((size_t)65536)

struct segment {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t protection;
};

struct image {
    uint8_t *bytes;
    size_t size;
    struct segment segments[MAX_SEGMENTS];
    size_t count;
    uint64_t entry_pc;
    const char *mode;
    uint8_t boot_args[OCNEXT_BOOTARGS_V3_BYTES];
    uint64_t boot_args_pa, study_phys_base, study_virt_base, study_kernel_span;
    unsigned boot_args_study;
    unsigned writable_kernel_data;
    unsigned physical_entry;
    unsigned mmu_study;
    uint64_t root_entry_pc;
    uint64_t write_transactions,written_bytes;
    struct ocnext_ordering ordering;
};

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t u64(const uint8_t *p)
{
    return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32;
}

static int bounded(size_t offset, size_t size, size_t limit)
{
    return offset <= limit && size <= limit - offset;
}

static int parse_integer(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long parsed;
    if (!text || *text < '0' || *text > '9') return 0;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno || *end) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

static int load_image(struct image *image, const char *path, size_t cap)
{
    FILE *file = fopen(path, "rb");
    long size;
    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) || (size = ftell(file)) <= 0 || (uint64_t)size > cap ||
        fseek(file, 0, SEEK_SET)) { fclose(file); return 0; }
    image->size = (size_t)size;
    image->bytes = malloc(image->size);
    if (!image->bytes) { fclose(file); return 0; }
    if (fread(image->bytes, 1, image->size, file) != image->size) {
        free(image->bytes); image->bytes = NULL; fclose(file); return 0;
    }
    if (fclose(file)) { free(image->bytes); image->bytes = NULL; return 0; }
    return 1;
}

static int macho_map(struct image *image)
{
    uint32_t commands, command_bytes, index;
    size_t cursor = 32, finish;
    unsigned threads = 0, matches = 0;
    if (image->size < 32 || u32(image->bytes) != UINT32_C(0xfeedfacf) ||
        u32(image->bytes + 4) != UINT32_C(0x0100000c) ||
        u32(image->bytes + 12) != 12 || u32(image->bytes + 28) != 0) return 0;
    commands = u32(image->bytes + 16);
    command_bytes = u32(image->bytes + 20);
    if (!commands || commands > 4096 || command_bytes > 2 * 1024 * 1024 ||
        command_bytes < commands * 8 || !bounded(32, command_bytes, image->size)) return 0;
    finish = 32 + command_bytes;
    for (index = 0; index < commands; ++index) {
        uint32_t command, size;
        const uint8_t *p;
        if (!bounded(cursor, 8, finish)) return 0;
        p = image->bytes + cursor;
        command = u32(p); size = u32(p + 4);
        if (size < 8 || size % 8 || !bounded(cursor, size, finish)) return 0;
        if (command == 0x19) {
            struct segment *segment;
            size_t previous;
            uint32_t sections;
            if (size < 72 || image->count == MAX_SEGMENTS) return 0;
            sections = u32(p + 64);
            if (sections > (size - 72) / 80 || size != 72 + sections * 80) return 0;
            segment = &image->segments[image->count];
            segment->vmaddr = u64(p + 24); segment->vmsize = u64(p + 32);
            segment->fileoff = u64(p + 40); segment->filesize = u64(p + 48);
            segment->protection = u32(p + 60);
            if (segment->vmsize < segment->filesize ||
                segment->vmsize > UINT64_MAX - segment->vmaddr ||
                segment->fileoff > image->size || segment->filesize > image->size - segment->fileoff) return 0;
            for (previous = 0; previous < image->count; ++previous) {
                const struct segment *other = &image->segments[previous];
                if (segment->vmsize && other->vmsize &&
                    segment->vmaddr < other->vmaddr + other->vmsize &&
                    other->vmaddr < segment->vmaddr + segment->vmsize) return 0;
                if (segment->filesize && other->filesize &&
                    segment->fileoff < other->fileoff + other->filesize &&
                    other->fileoff < segment->fileoff + segment->filesize) return 0;
            }
            ++image->count;
        } else if (command == 5) {
            size_t state = 8;
            while (state < size) {
                uint32_t flavor, words;
                if (!bounded(state, 8, size)) return 0;
                flavor = u32(p + state); words = u32(p + state + 4); state += 8;
                if (words > 1024 || !bounded(state, (size_t)words * 4, size)) return 0;
                if (flavor == 6) {
                    if (words != 68 || ++threads != 1) return 0;
                    image->entry_pc = u64(p + state + 256);
                }
                state += (size_t)words * 4;
            }
        }
        cursor += size;
    }
    if (cursor != finish || threads != 1 || image->entry_pc % 4) return 0;
    for (index = 0; index < image->count; ++index) {
        const struct segment *segment = &image->segments[index];
        if ((segment->protection & 4) && image->entry_pc >= segment->vmaddr &&
            image->entry_pc - segment->vmaddr < segment->filesize) ++matches;
    }
    return matches == 1;
}

static const struct segment *find_segment(const struct image *image, uint64_t address)
{
    size_t index;
    for (index = 0; index < image->count; ++index) {
        const struct segment *segment = &image->segments[index];
        if (address >= segment->vmaddr && address - segment->vmaddr < segment->vmsize) return segment;
    }
    return NULL;
}

static uint64_t study_address(const struct image *image,uint64_t address)
{
    if(image->boot_args_study && address>=image->study_phys_base &&
       address-image->study_phys_base<image->study_kernel_span)
        return image->study_virt_base+(address-image->study_phys_base);
    return address;
}

static int load_boot_args(struct image *image,const char *path,uint64_t pa)
{
    struct ocnext_bootargs_study p={0};uint8_t canonical[1152];
    uint64_t minimum=UINT64_MAX,maximum=0,dt_va;
    size_t i;FILE *file=fopen(path,"rb");
    if(!file)return 0;
    if(fread(image->boot_args,1,sizeof(image->boot_args),file)!=sizeof(image->boot_args) ||
       fgetc(file)!=EOF || ferror(file)) {fclose(file);return 0;}
    if(fclose(file))return 0;
    for(i=0;i<image->count;++i)if(image->segments[i].vmsize) {
        if(minimum>image->segments[i].vmaddr)minimum=image->segments[i].vmaddr;
        if(maximum<image->segments[i].vmaddr+image->segments[i].vmsize)
            maximum=image->segments[i].vmaddr+image->segments[i].vmsize;
    }
    p.revision=(uint16_t)(image->boot_args[0]|image->boot_args[1]<<8);
    p.version=(uint16_t)(image->boot_args[2]|image->boot_args[3]<<8);
    p.virt_base=u64(image->boot_args+8);p.phys_base=u64(image->boot_args+16);
    p.mem_size=u64(image->boot_args+24);p.top_of_kernel_data=u64(image->boot_args+32);
    p.mem_size_actual=u64(image->boot_args+1144);p.boot_args_pa=pa;
    if(minimum!=p.virt_base || maximum<=minimum || p.phys_base>UINT64_MAX-(maximum-minimum))return 0;
    p.kernel_pa=p.phys_base;p.kernel_bytes=maximum-minimum;
    /* Two observation aliases must not make one address ambiguous. */
    if(minimum!=p.phys_base && minimum<p.phys_base+p.kernel_bytes &&
       p.phys_base<maximum)return 0;
    if(pa>=minimum && pa<maximum)return 0;
    dt_va=u64(image->boot_args+96);
    if(dt_va<p.virt_base || dt_va-p.virt_base>=p.mem_size ||
       p.phys_base>UINT64_MAX-(dt_va-p.virt_base))return 0;
    p.device_tree_pa=p.phys_base+(dt_va-p.virt_base);p.device_tree_bytes=u32(image->boot_args+104);
    p.machine_type=u32(image->boot_args+88);p.boot_flags=u64(image->boot_args+1136);
    p.video_pa=u64(image->boot_args+40);p.video_stride=u64(image->boot_args+56);
    p.video_width=u64(image->boot_args+64);p.video_height=u64(image->boot_args+72);p.video_depth=u64(image->boot_args+80);
    p.command_line=(const char *)image->boot_args+108;
    while(p.command_line_bytes<1024 && p.command_line[p.command_line_bytes])++p.command_line_bytes;
    if(ocnext_bootargs_v3_encode(&p,canonical,sizeof(canonical))!=OCNEXT_BOOTARGS_OK ||
       memcmp(canonical,image->boot_args,sizeof(canonical)))return 0;
    image->boot_args_pa=pa;image->study_phys_base=p.phys_base;
    image->study_virt_base=p.virt_base;image->study_kernel_span=p.kernel_bytes;
    image->boot_args_study=1;return 1;
}

static int read_code(void *context, uint64_t address, uint8_t *out, size_t size,
                     enum ocnext_a64_access access)
{
    const struct image *image = context;
    uint64_t cursor = address;
    size_t remaining = size, copied = 0;
    uint32_t required = access == OCNEXT_A64_ACCESS_FETCH ? 4u : 1u;
    if (!size || address > UINT64_MAX - (size - 1)) return -1;
    if(image->boot_args_study && address>=image->boot_args_pa &&
       address-image->boot_args_pa<sizeof(image->boot_args)) {
        uint64_t relative=address-image->boot_args_pa;
        if(access!=OCNEXT_A64_ACCESS_READ || size>sizeof(image->boot_args)-relative)return -1;
        memcpy(out,image->boot_args+(size_t)relative,size);return 0;
    }
    cursor=study_address(image,address);
    /* Preflight every mapped chunk before exposing any requested bytes. */
    while (remaining) {
        const struct segment *segment = find_segment(image, cursor);
        uint64_t available;
        size_t count;
        if (!segment || !(segment->protection & required)) return -1;
        available = segment->vmsize - (cursor - segment->vmaddr);
        count = available < remaining ? (size_t)available : remaining;
        cursor += count; remaining -= count;
    }
    cursor = study_address(image,address); remaining = size;
    while (remaining) {
        const struct segment *segment = find_segment(image, cursor);
        uint64_t relative = cursor - segment->vmaddr;
        uint64_t available = segment->vmsize - relative;
        size_t count = available < remaining ? (size_t)available : remaining;
        size_t backed = relative >= segment->filesize ? 0 :
                        (segment->filesize - relative < count ? (size_t)(segment->filesize - relative) : count);
        if (backed) memcpy(out + copied, image->bytes + (size_t)(segment->fileoff + relative), backed);
        if (backed < count) memset(out + copied + backed, 0, count - backed);
        cursor += count; remaining -= count; copied += count;
    }
    return 0;
}

static int reject_write(void *context, uint64_t address, const uint8_t *source, size_t size)
{
    struct image *image=context;uint64_t cursor;size_t remaining=size,copied=0;
    if(!image->writable_kernel_data || !source || !size || size>16 || address>UINT64_MAX-(size-1) ||
       image->write_transactions==UINT64_MAX || size>UINT64_MAX-image->written_bytes)return -1;
    cursor=study_address(image,address);
    /* Explicit flat bootstrap RAM policy: file-backed readable non-executable
     * ranges are writable. DATA_CONST contains early bootstrap table storage;
     * Mach-O const flags are not a pre-MMU physical RAM protection contract.
     * Code/args/DT/hole denied. No invented BSS backing or qualified MMU claim. */
    while(remaining) {
        const struct segment *s=find_segment(image,cursor);uint64_t relative;size_t n;
        if(!s || !(s->protection&1) || (s->protection&4))return -1;
        relative=cursor-s->vmaddr;
        if(relative>=s->filesize)return -1;
        n=s->filesize-relative<remaining?(size_t)(s->filesize-relative):remaining;
        cursor+=n;remaining-=n;
    }
    cursor=study_address(image,address);remaining=size;
    while(remaining) {
        const struct segment *s=find_segment(image,cursor);uint64_t relative=cursor-s->vmaddr;
        size_t n=s->filesize-relative<remaining?(size_t)(s->filesize-relative):remaining;
        memcpy(image->bytes+(size_t)(s->fileoff+relative),source+copied,n);
        cursor+=n;remaining-=n;copied+=n;
    }
    ++image->write_transactions;image->written_bytes+=size;return 0;
}

/* Physical bus for the separately selected MMU study. A high virtual alias
 * is never accepted as a physical bus address, including while M is clear. */
static int physical_probe(void *context,uint64_t address,size_t size,enum ocnext_a64_access access)
{
    const struct image *image=context;uint64_t cursor;size_t remaining=size;
    uint32_t required=access==OCNEXT_A64_ACCESS_FETCH?4u:1u;
    if(!size || address>UINT64_MAX-(size-1) || (unsigned)access>(unsigned)OCNEXT_A64_ACCESS_WRITE)return -1;
    if(address>=image->boot_args_pa && address-image->boot_args_pa<sizeof(image->boot_args))
        return access==OCNEXT_A64_ACCESS_READ && size<=sizeof(image->boot_args)-(address-image->boot_args_pa)?0:-1;
    if(address<image->study_phys_base || address-image->study_phys_base>=image->study_kernel_span ||
       size>image->study_kernel_span-(address-image->study_phys_base))return -1;
    cursor=study_address(image,address);
    while(remaining) {
        const struct segment *s=find_segment(image,cursor);uint64_t relative;size_t count;
        if(!s || !(s->protection&required))return -1;
        relative=cursor-s->vmaddr;
        count=s->vmsize-relative<remaining?(size_t)(s->vmsize-relative):remaining;
        if(access==OCNEXT_A64_ACCESS_WRITE && (!image->writable_kernel_data || (s->protection&4u) ||
           relative>=s->filesize || count>s->filesize-relative))return -1;
        cursor+=count;remaining-=count;
    }
    return 0;
}

static int physical_read(void *context,uint64_t address,uint8_t *out,size_t size)
{
    return physical_probe(context,address,size,OCNEXT_A64_ACCESS_READ)?-1:
           read_code(context,address,out,size,OCNEXT_A64_ACCESS_READ);
}

static int physical_writev(void *context,const struct ocnext_mmu_span *spans,size_t count,
                           const uint8_t *source,size_t bytes)
{
    struct image *image=context;uint8_t snapshot[16];size_t index,expected=0;
    if(!spans || !source || !count || count>OCNEXT_MMU_MAX_SPANS || !bytes || bytes>sizeof(snapshot) ||
       image->write_transactions==UINT64_MAX || bytes>UINT64_MAX-image->written_bytes)return -1;
    for(index=0;index<count;++index) {
        if(spans[index].offset!=expected || !spans[index].bytes || spans[index].bytes>bytes-expected ||
           physical_probe(image,spans[index].pa,spans[index].bytes,OCNEXT_A64_ACCESS_WRITE))return -1;
        expected+=spans[index].bytes;
    }
    if(expected!=bytes)return -1;
    memcpy(snapshot,source,bytes);
    for(index=0;index<count;++index) {
        uint64_t cursor=study_address(image,spans[index].pa);size_t remaining=spans[index].bytes;
        size_t copied=spans[index].offset;
        while(remaining) {
            const struct segment *s=find_segment(image,cursor);uint64_t relative=cursor-s->vmaddr;
            size_t n=s->filesize-relative<remaining?(size_t)(s->filesize-relative):remaining;
            memcpy(image->bytes+(size_t)(s->fileoff+relative),snapshot+copied,n);
            cursor+=n;remaining-=n;copied+=n;
        }
    }
    ++image->write_transactions;image->written_bytes+=bytes;return 0;
}

static enum ocnext_a64_sync_result sync_ram(void *context,
                                  const struct ocnext_a64_sync_request *request)
{
    struct image *image=context;
    return ocnext_ordering_sync(&image->ordering,request);
}

static void json_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    while (*p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32 || *p > 126) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
        ++p;
    }
    putchar('"');
}

/* Diagnostics are restricted to the explicit physical alias of file-backed,
 * readable non-executable study RAM. Never make holes/BSS/boot inputs readable
 * for a snapshot or change the CPU's memory provider to collect one. */
static int snapshot_range(const struct image *image,uint64_t address,size_t bytes)
{
    uint64_t cursor;size_t remaining=bytes;
    if(!image->boot_args_study || !bytes || bytes>MAX_SNAPSHOT_BYTES ||
       (address&7u) || (bytes&7u) || address<image->study_phys_base ||
       address-image->study_phys_base>=image->study_kernel_span ||
       bytes>image->study_kernel_span-(address-image->study_phys_base))return 0;
    cursor=study_address(image,address);
    while(remaining) {
        const struct segment *s=find_segment(image,cursor);uint64_t relative;size_t chunk;
        if(!s || !(s->protection&1u) || (s->protection&4u))return 0;
        relative=cursor-s->vmaddr;
        if(relative>=s->filesize)return 0;
        chunk=s->filesize-relative<remaining?(size_t)(s->filesize-relative):remaining;
        cursor+=chunk;remaining-=chunk;
    }
    return 1;
}

static void print_digest(const uint8_t digest[32])
{size_t index;putchar('"');for(index=0;index<32;++index)printf("%02x",(unsigned)digest[index]);putchar('"');}

static void print_mmu_value(const char *name,uint64_t stored,uint32_t mask,uint32_t bit,unsigned comma)
{
    printf("%s\"%s\":{\"known\":%s,\"stored_value\":\"0x%016" PRIx64 "\"}",
           comma?",":"",name,(mask&bit)?"true":"false",stored);
}

static void print_snapshot(uint64_t address,size_t bytes,const uint8_t *before,const uint8_t *after,
                           const uint8_t before_sha[32],const uint8_t after_sha[32],unsigned connected)
{
    size_t offset,nonzero=0,changed=0;unsigned comma=0;
    for(offset=0;offset<bytes;offset+=8) {
        if(u64(after+offset))++nonzero;
        if(u64(before+offset)!=u64(after+offset))++changed;
    }
    printf(",\"owned_ram_snapshot\":{\"guest_pa\":\"0x%016" PRIx64 "\",\"bytes\":%zu,"
           "\"file_backed_nonexec\":true,\"initial_sha256\":",address,bytes);
    print_digest(before_sha);printf(",\"final_sha256\":");print_digest(after_sha);
    printf(",\"u64_words\":%zu,\"zero_u64_words\":%zu,\"nonzero_u64_words\":%zu,"
           "\"changed_u64_words\":%zu,\"nonzero_u64\":[",bytes/8,bytes/8-nonzero,nonzero,changed);
    for(offset=0;offset<bytes;offset+=8)if(u64(after+offset)) {
        printf("%s{\"offset\":%zu,\"guest_pa\":\"0x%016" PRIx64 "\",\"value\":\"0x%016" PRIx64 "\"}",
               comma?",":"",offset,address+offset,u64(after+offset));comma=1;
    }
    printf("],\"descriptor_semantics_qualified\":false,\"guest_mmu_connected\":%s}",connected?"true":"false");
}

/* Diagnostic bytes are architectural low byte first, independently of native
 * integer or host SIMD layout. Stored zero does not set any knowledge bit. */
static void print_vector_registers(const struct ocnext_a64_vector_registers *bank)
{
    unsigned reg, byte;
    printf(",\"vector_register_abi_version\":%u,\"vector_register_bank_bytes\":%zu,"
           "\"vector_register_bank_offset\":%zu,\"vector_registers\":[",
           bank->abi_version, sizeof(*bank), offsetof(struct ocnext_a64_cpu, vector));
    for (reg=0; reg<32; ++reg) {
        printf("%s{\"register\":\"V%u\",\"known_bytes\":%u,\"stored_bytes_le\":\"",
               reg?",":"", reg, (unsigned)bank->known_bytes[reg]);
        for (byte=0; byte<16; ++byte) printf("%02x", (unsigned)bank->bytes[reg][byte]);
        printf("\"}");
    }
    printf("]");
}

int main(int argc, char **argv)
{
    struct image image = {0};
    struct ocnext_a64_cpu cpu;
    struct ocnext_a64_memory memory = {0};
    struct ocnext_mmu mmu={0};struct ocnext_mmu_cpu adapter={0};
    const struct ocnext_ordering *ordering=&image.ordering;
    enum ocnext_a64_result result;
    uint64_t budget,dispatches=0;
    unsigned el1_debug = 0, el1_sync = 0, initial_os_lock;
    uint32_t initial_daif;
    uint64_t snapshot_pa=0,snapshot_length=0;
    uint8_t *snapshot_before=NULL,*snapshot_after=NULL;
    uint8_t snapshot_initial_sha[32]={0},snapshot_final_sha[32]={0};
    const char *path;
    if((argc==6 || argc==9) && (!strcmp(argv[1],"--macho-boot-args-study") || !strcmp(argv[1],"--macho-boot-args-study-rw") ||
                 !strcmp(argv[1],"--macho-boot-args-study-rw-physical") ||
                 !strcmp(argv[1],"--macho-boot-args-study-rw-physical-mmu"))) {
        uint64_t boot_pa;
        path=argv[2];image.mode="root-fileset-public-rv3-study";el1_sync=el1_debug=1;
        image.mmu_study=!strcmp(argv[1],"--macho-boot-args-study-rw-physical-mmu");
        image.physical_entry=image.mmu_study || !strcmp(argv[1],"--macho-boot-args-study-rw-physical");
        image.writable_kernel_data=image.physical_entry || !strcmp(argv[1],"--macho-boot-args-study-rw");
        if(image.writable_kernel_data)image.mode="root-fileset-public-rv3-owned-working-copy";
        if(!parse_integer(argv[4],&boot_pa) || !parse_integer(argv[5],&budget) ||
           budget>(image.writable_kernel_data?MAX_WORKING_STUDY_BUDGET:MAX_BUDGET) ||
           !load_image(&image,path,MAX_IMAGE_BYTES) || !macho_map(&image) ||
           !load_boot_args(&image,argv[3],boot_pa)) {
            free(image.bytes);fprintf(stderr,"Invalid explicit unqualified boot-args study input.\n");return 2;
        }
        image.root_entry_pc=image.entry_pc;
        if(image.physical_entry) {
            image.entry_pc=image.study_phys_base+(image.root_entry_pc-image.study_virt_base);
            image.mode="root-fileset-public-rv3-physical-owned-working-copy";
            if(image.mmu_study)image.mode="root-fileset-public-rv3-physical-mmu-research-m0";
        }
        if(argc==9) {
            if(strcmp(argv[6],"--ram-snapshot") || !parse_integer(argv[7],&snapshot_pa) ||
               !parse_integer(argv[8],&snapshot_length) || snapshot_length>MAX_SNAPSHOT_BYTES ||
               !snapshot_range(&image,snapshot_pa,(size_t)snapshot_length)) {
                free(image.bytes);fprintf(stderr,"Invalid bounded owned-RAM snapshot span.\n");return 2;
            }
        }
    } else if (argc == 4 && (strcmp(argv[1], "--macho") == 0 ||
                      strcmp(argv[1], "--macho-el1-debug") == 0 ||
                      strcmp(argv[1], "--macho-el1-sync") == 0)) {
        path = argv[2]; image.mode = "root-fileset-read-only";
        el1_sync = strcmp(argv[1], "--macho-el1-sync") == 0;
        el1_debug = el1_sync || strcmp(argv[1], "--macho-el1-debug") == 0;
        if (!parse_integer(argv[3], &budget) || budget > MAX_BUDGET ||
            !load_image(&image, path, MAX_IMAGE_BYTES) || !macho_map(&image)) {
            free(image.bytes); fprintf(stderr, "Invalid bounded root MH_FILESET input/budget.\n"); return 2;
        }
    } else if (argc == 4) {
        path = argv[1]; image.mode = "entry-prefix-read-only";
        if (!parse_integer(argv[2], &image.entry_pc) || !parse_integer(argv[3], &budget) ||
            budget > MAX_BUDGET || !load_image(&image, path, 1024) ||
            image.size % 4 || image.entry_pc > UINT64_MAX - image.size) {
            free(image.bytes); fprintf(stderr, "Invalid bounded prefix input/PC/budget.\n"); return 2;
        }
        image.count = 1;
        image.segments[0].vmaddr = image.entry_pc;
        image.segments[0].vmsize = image.size;
        image.segments[0].fileoff = 0;
        image.segments[0].filesize = image.size;
        image.segments[0].protection = 5;
    } else {
        fprintf(stderr, "Usage: %s ENTRY_BIN ENTRY_PC BUDGET\n       %s --macho KERNEL_FILESET BUDGET\n"
                        "       %s --macho-el1-debug KERNEL_FILESET BUDGET\n"
                        "       %s --macho-el1-sync KERNEL_FILESET BUDGET\n"
                        "       %s --macho-boot-args-study KERNEL_FILESET BOOT_ARGS BOOT_ARGS_PA BUDGET\n"
                        "       %s --macho-boot-args-study-rw KERNEL_FILESET BOOT_ARGS BOOT_ARGS_PA BUDGET\n"
                        "       %s --macho-boot-args-study-rw-physical KERNEL_FILESET BOOT_ARGS BOOT_ARGS_PA BUDGET\n"
                        "       %s --macho-boot-args-study-rw-physical-mmu KERNEL_FILESET BOOT_ARGS BOOT_ARGS_PA BUDGET\n"
                        "       Study modes optionally accept --ram-snapshot GUEST_PA BYTES (8-byte aligned, max65536).\n",
                        argv[0], argv[0], argv[0], argv[0],argv[0],argv[0],argv[0],argv[0]);
        return 2;
    }
    if(snapshot_length) {
        snapshot_before=malloc((size_t)snapshot_length);snapshot_after=malloc((size_t)snapshot_length);
        if(!snapshot_before || !snapshot_after ||
           read_code(&image,snapshot_pa,snapshot_before,(size_t)snapshot_length,OCNEXT_A64_ACCESS_READ) ||
           ocnext_sha256_digest(snapshot_before,(size_t)snapshot_length,snapshot_initial_sha)) {
            free(snapshot_before);free(snapshot_after);free(image.bytes);return 2;
        }
    }
    ocnext_a64_reset(&cpu, image.entry_pc, 0);
    if (el1_debug && ocnext_a64_configure_system(&cpu, el1_sync ? OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC : OCNEXT_A64_SYSTEM_ARMV8_EL1_DEBUG, 1)) {
        free(snapshot_before);free(snapshot_after);free(image.bytes); fprintf(stderr, "Invalid initial EL1 debug profile.\n"); return 2;
    }
    initial_os_lock = cpu.system.os_lock;
    initial_daif = cpu.system.daif;
    if(image.boot_args_study)cpu.x[0]=image.boot_args_pa;
    memory.context = &image; memory.read = read_code; memory.write = reject_write;
    if(el1_sync) {
        if(ocnext_ordering_init(&image.ordering,OCNEXT_ORDERING_SERIAL_RAM)) {
            free(snapshot_before);free(snapshot_after);free(image.bytes);return 2;
        }
        memory.sync=sync_ram;
    }
    if(image.mmu_study) {
        struct ocnext_a64_mmu_registers bank={0};
        bank.sctlr_el1=OCNEXT_A64_SCTLR_RES1;bank.known_mask=OCNEXT_A64_MMU_KNOWN_SCTLR;
        mmu.config.sctlr_el1=bank.sctlr_el1;mmu.config.current_el=1;
        mmu.bus.context=&image;mmu.bus.read=physical_read;mmu.bus.probe=physical_probe;
        mmu.bus.writev=physical_writev;
        if(ocnext_a64_configure_mmu_registers(&cpu,&bank) || ocnext_mmu_cpu_init(&adapter,&cpu,&mmu) ||
           ocnext_mmu_cpu_configure_ordering(&adapter,OCNEXT_ORDERING_SERIAL_RAM) ||
           ocnext_mmu_cpu_configure_maintenance(&adapter,OCNEXT_MMU_MAINTENANCE_SERIAL_NORMAL_RAM) ||
           ocnext_mmu_cpu_configure_features(&adapter,OCNEXT_MMU_FEATURE_SERIAL_S1_PA48_ASID16)) {
            free(snapshot_before);free(snapshot_after);free(image.bytes);return 2;
        }
        ordering=&adapter.ordering;result=OCNEXT_A64_BUDGET;
        while(dispatches<budget) {
            result=ocnext_mmu_cpu_step(&adapter);++dispatches;
            if(result!=OCNEXT_A64_RETIRED && result!=OCNEXT_A64_EXCEPTION)break;
        }
        if(dispatches==budget && (result==OCNEXT_A64_RETIRED || result==OCNEXT_A64_EXCEPTION))result=OCNEXT_A64_BUDGET;
    } else {
        result = ocnext_a64_run(&cpu, &memory, budget);
        dispatches=cpu.retired+cpu.system.exception_count+(result==OCNEXT_A64_FAULTED?1u:0u);
    }
    if(snapshot_length && (read_code(&image,snapshot_pa,snapshot_after,(size_t)snapshot_length,OCNEXT_A64_ACCESS_READ) ||
       ocnext_sha256_digest(snapshot_after,(size_t)snapshot_length,snapshot_final_sha))) {
        free(snapshot_before);free(snapshot_after);free(image.bytes);return 2;
    }
    printf("{\"schema_version\":1,\"probe_completed\":true,\"input_mode\":"); json_string(image.mode);
    printf(",\"input_path\":"); json_string(path);
    printf(",\"cpu_profile\":"); json_string(el1_sync ? "armv8-el1-sync-no-el2-el3" : el1_debug ? "armv8-el1-debug-no-el2-el3" : "scalar-default");
    printf(",\"cpu_abi_version\":%u,\"cpu_state_bytes\":%zu,\"initial_el_modeled\":%s,"
           "\"current_el\":%u,\"os_lock_initial\":%u,\"os_lock_final\":%u,"
           "\"daif_initial\":\"0x%03" PRIx32 "\",\"daif_final\":\"0x%03" PRIx32 "\",\"uma\":%u,"
           "\"fault_ec_valid\":%s,\"fault_ec\":%u,\"fault_target_el\":%u",
           OCNEXT_A64_ABI_VERSION, sizeof(cpu), el1_debug ? "true" : "false",
           (unsigned)cpu.system.current_el, initial_os_lock, (unsigned)cpu.system.os_lock,
           initial_daif, cpu.system.daif, (unsigned)cpu.system.uma,
           cpu.fault.has_syndrome ? "true" : "false", (unsigned)cpu.fault.syndrome_ec,
           (unsigned)cpu.fault.target_el);
    printf(",\"guest_exception_count\":%" PRIu64 ",\"spsel\":%u,"
           "\"vbar_el1\":\"0x%016" PRIx64 "\",\"esr_el1\":\"0x%08" PRIx64 "\","
           "\"far_el1\":\"0x%016" PRIx64 "\",\"elr_el1\":\"0x%016" PRIx64 "\","
           "\"spsr_el1\":\"0x%08" PRIx64 "\",\"system_known_mask\":%u,"
           "\"guest_sync_delivery_enabled\":%s",
           cpu.system.exception_count, (unsigned)cpu.system.spsel, cpu.system.vbar_el1,
           cpu.system.esr_el1, cpu.system.far_el1, cpu.system.elr_el1, cpu.system.spsr_el1,
           cpu.system.known_state, el1_sync ? "true" : "false");
    printf(",\"mmu_register_known_mask\":%u,\"mmu_register_state_initially_supplied\":%s,"
           "\"explicit_initial_m0_research_policy\":%s,\"feature_known_mask\":%u,"
           "\"id_aa64mmfr0_el1\":\"0x%016" PRIx64 "\",\"feature_profile\":",
           cpu.system.mmu.known_mask,image.mmu_study?"true":"false",image.mmu_study?"true":"false",
           cpu.system.features.known_mask,cpu.system.features.id_aa64mmfr0_el1);
    json_string(image.mmu_study?"validated software S1 PA48 ASID16 4/16/64KiB, no stage2":"UNKNOWN");
    printf(",\"mmu_registers\":{");
    print_mmu_value("tcr_el1",cpu.system.mmu.tcr_el1,cpu.system.mmu.known_mask,OCNEXT_A64_MMU_KNOWN_TCR,0);
    print_mmu_value("ttbr0_el1",cpu.system.mmu.ttbr0_el1,cpu.system.mmu.known_mask,OCNEXT_A64_MMU_KNOWN_TTBR0,1);
    print_mmu_value("ttbr1_el1",cpu.system.mmu.ttbr1_el1,cpu.system.mmu.known_mask,OCNEXT_A64_MMU_KNOWN_TTBR1,1);
    print_mmu_value("sctlr_el1",cpu.system.mmu.sctlr_el1,cpu.system.mmu.known_mask,OCNEXT_A64_MMU_KNOWN_SCTLR,1);
    print_mmu_value("mair_el1",cpu.system.mmu.mair_el1,cpu.system.mmu.known_mask,OCNEXT_A64_MMU_KNOWN_MAIR,1);
    printf("}");
    printf(",\"fp_control_abi_version\":%u,\"fp_control_known_mask\":%u,\"fp_control_registers\":{",
           cpu.fp.abi_version,cpu.fp.known_mask);
    print_mmu_value("cpacr_el1",cpu.fp.cpacr_el1,cpu.fp.known_mask,OCNEXT_A64_FP_KNOWN_CPACR,0);
    print_mmu_value("fpcr",cpu.fp.fpcr,cpu.fp.known_mask,OCNEXT_A64_FP_KNOWN_FPCR,1);
    print_mmu_value("fpsr",cpu.fp.fpsr,cpu.fp.known_mask,OCNEXT_A64_FP_KNOWN_FPSR,1);
    printf("},\"fp_simd_arithmetic_qualified\":false,\"fp_feature_ids_advertised\":false");
    print_vector_registers(&cpu.vector);
    printf(",\"full_arm_isa_qualified\":false,\"apple_hvc_service_qualified\":false,\"gpu_verified\":false");
    printf(",\"memory_abi_version\":%u,\"tls_known_mask\":%u,"
           "\"tpidr_el0\":\"0x%016" PRIx64 "\",\"tpidrro_el0\":\"0x%016" PRIx64 "\","
           "\"tpidr_el1\":\"0x%016" PRIx64 "\",\"ordering_profile\":%u,"
           "\"ordering_events\":%" PRIu64 ",\"host_fences\":%" PRIu64 ","
           "\"dmb_completed\":%" PRIu64 ",\"dsb_completed\":%" PRIu64 ","
           "\"isb_completed\":%" PRIu64 ",\"instruction_view_epoch\":%" PRIu64 ","
           "\"smp_ordering_verified\":false,\"device_ordering_verified\":false",
           OCNEXT_A64_MEMORY_ABI_VERSION,cpu.system.tls.known_mask,
           cpu.system.tls.tpidr_el0,cpu.system.tls.tpidrro_el0,cpu.system.tls.tpidr_el1,
           ordering->profile,ordering->events,ordering->host_fences,
           ordering->dmb,ordering->dsb,ordering->isb,ordering->instruction_epoch);
    printf(",\"maintenance_profile\":%u,\"maintenance_events\":%" PRIu64 ","
           "\"maintenance_host_fences\":%" PRIu64 ",\"translation_epoch\":%" PRIu64 ","
           "\"mmu_configuration_rejected\":%s,\"rejected_sctlr_el1\":\"0x%016" PRIx64 "\"",
           adapter.maintenance.profile,adapter.maintenance.events,adapter.maintenance.host_fences,
           adapter.maintenance.translation_epoch,adapter.configuration_rejected?"true":"false",adapter.rejected_mmu.sctlr_el1);
    printf(",\"mmu_abort_pending\":%s,\"mmu_last_fault\":{\"kind\":%d,\"raw_va\":\"0x%016" PRIx64 "\","
           "\"access\":%d,\"level\":%u,\"esr_el1\":\"0x%08" PRIx32 "\","
           "\"syndrome_valid\":%s,\"far_valid\":%s}",adapter.abort_pending?"true":"false",
           (int)mmu.fault.kind,mmu.fault.va,(int)mmu.fault.access,(unsigned)mmu.fault.level,mmu.fault.esr_el1,
           mmu.fault.syndrome_valid?"true":"false",mmu.fault.far_valid?"true":"false");
    printf(",\"boot_args_study_supplied\":%s,\"boot_args_pa\":\"0x%016" PRIx64 "\","
           "\"physical_alias_supplied\":%s,\"device_tree_input_connected\":false,"
           "\"initial_register_policy\":",image.boot_args_study?"true":"false",image.boot_args_pa,
           image.boot_args_study?"true":"false");
    json_string(image.boot_args_study?"explicit public-rv3 study x0; other GPR/SP/NZCV zero; not an iBoot handoff":"all GPR/SP/NZCV zero; no qualified boot arguments");
    printf(",\"initial_registers\":");
    json_string(image.boot_args_study?"explicit public-rv3 study x0; other GPR/SP/NZCV zero; not an iBoot handoff":"all GPR/SP/NZCV zero; no qualified boot arguments");
    printf(",\"working_copy_write_transactions\":%" PRIu64 ",\"working_copy_written_bytes\":%" PRIu64 ","
           "\"guest_write_policy\":",image.write_transactions,image.written_bytes);
    json_string(image.mmu_study?"explicit physical MMU bus, file-backed non-executable owned RAM; high VA/code/args/DT/hole writes denied":
                image.writable_kernel_data?"explicit flat bootstrap file-backed non-executable RAM; code/args/DT/hole denied":"read-only observation");
    printf(",\"final_sp\":\"0x%016" PRIx64 "\",\"final_gpr\":[",cpu.sp);
    {unsigned index;for(index=0;index<31;++index)printf("%s\"0x%016" PRIx64 "\"",index?",":"",cpu.x[index]);}
    printf("]");
    printf(",\"final_nzcv\":\"0x%08" PRIx32 "\",\"stored_sp_el0\":\"0x%016" PRIx64 "\","
           "\"stored_sp_el1\":\"0x%016" PRIx64 "\"",cpu.nzcv,cpu.system.sp_el0,cpu.system.sp_el1);
    if(snapshot_length)print_snapshot(snapshot_pa,(size_t)snapshot_length,snapshot_before,snapshot_after,
                                      snapshot_initial_sha,snapshot_final_sha,image.mmu_study);
    printf(",\"physical_entry_enabled\":%s,\"root_entry_pc\":\"0x%016" PRIx64 "\","
           "\"effective_initial_entry_pc\":\"0x%016" PRIx64 "\"",
           image.physical_entry?"true":"false",image.root_entry_pc?image.root_entry_pc:image.entry_pc,image.entry_pc);
    printf(",\"image_bytes\":%zu,\"mapped_segments\":%zu,\"entry_pc\":\"0x%016" PRIx64 "\","
           "\"budget\":%" PRIu64 ",\"dispatches\":%" PRIu64 ",\"result\":%d,\"retired\":%" PRIu64 ",\"pc\":\"0x%016" PRIx64 "\",\"x0\":\"0x%016" PRIx64 "\","
           "\"fault_code\":%d,\"fault_pc\":\"0x%016" PRIx64 "\",\"fault_address\":\"0x%016" PRIx64 "\","
           "\"fault_opcode\":\"0x%08" PRIx32 "\",\"fault_access\":%d,\"fault_size\":%" PRIu32 ","
           "\"halt_fixture_policy\":false,\"guest_writes_allowed\":%s,\"boot_contract_qualified\":false,"
           "\"stage1_mmu_connected\":%s,\"stage1_translation_enabled\":%s,"
           "\"boot_complete\":false,\"macos_boot_proven\":false}\n",
           image.size, image.count, image.entry_pc, budget,dispatches, (int)result, cpu.retired, cpu.pc, cpu.x[0],
           (int)cpu.fault.code, cpu.fault.pc, cpu.fault.address, cpu.fault.opcode,
           (int)cpu.fault.access, cpu.fault.access_size,image.writable_kernel_data?"true":"false",
           image.mmu_study?"true":"false",image.mmu_study && (cpu.system.mmu.sctlr_el1&1u)?"true":"false");
    free(snapshot_before);free(snapshot_after);free(image.bytes);
    return 0; /* Valid observation, including unsupported/fault/budget: not OS boot success. */
}
