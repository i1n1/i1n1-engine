#include "ocnext/boot_args.h"

#define PA48 UINT64_C(0x0000ffffffffffff)

static int canonical(uint64_t address)
{
    return address >> 48 == ((address & (UINT64_C(1) << 47)) ? 65535u : 0u);
}
static int range(uint64_t start, uint64_t bytes, uint64_t base, uint64_t size)
{
    return bytes && start >= base && start - base <= size &&
           bytes <= size - (start - base);
}
static int overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
    return an && bn && a < b + bn && b < a + an;
}
static void put(uint8_t *out, size_t offset, uint64_t value, unsigned bytes)
{
    unsigned i;
    for (i=0; i<bytes; ++i) out[offset+i]=(uint8_t)(value >> (i*8));
}

enum ocnext_bootargs_result ocnext_bootargs_v3_encode(
    const struct ocnext_bootargs_study *p, uint8_t *out, size_t bytes)
{
    uint8_t temporary[OCNEXT_BOOTARGS_V3_BYTES];
    uint64_t dt_va, video_bytes=0, top;
    size_t i;
    if (!p || !out || bytes != OCNEXT_BOOTARGS_V3_BYTES || p->reserved ||
        (!p->command_line && p->command_line_bytes)) return OCNEXT_BOOTARGS_ARGUMENT;
    if (p->revision != 3 || p->version != 2 || (p->boot_flags & ~UINT64_C(1)) ||
        p->command_line_bytes >= OCNEXT_BOOTARGS_V3_COMMAND_BYTES) return OCNEXT_BOOTARGS_LAYOUT;
    for (i=0; i<p->command_line_bytes; ++i)
        if ((unsigned char)p->command_line[i] < 32 || (unsigned char)p->command_line[i] > 126)
            return OCNEXT_BOOTARGS_LAYOUT;
    if (!p->mem_size || p->mem_size > PA48 || p->phys_base > PA48 - p->mem_size ||
        (p->phys_base & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        (p->virt_base & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        (p->mem_size & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        !canonical(p->virt_base) || p->virt_base > UINT64_MAX - (p->mem_size-1) ||
        !canonical(p->virt_base+p->mem_size-1) ||
        p->mem_size_actual != p->mem_size)
        return OCNEXT_BOOTARGS_RANGE;
    if ((p->kernel_pa & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        (p->boot_args_pa & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        (p->device_tree_pa & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        !range(p->kernel_pa,p->kernel_bytes,p->phys_base,p->mem_size) ||
        !range(p->boot_args_pa,OCNEXT_BOOTARGS_V3_BYTES,p->phys_base,p->mem_size) ||
        !range(p->device_tree_pa,p->device_tree_bytes,p->phys_base,p->mem_size))
        return OCNEXT_BOOTARGS_RANGE;
    if (overlap(p->kernel_pa,p->kernel_bytes,p->boot_args_pa,OCNEXT_BOOTARGS_V3_BYTES) ||
        overlap(p->kernel_pa,p->kernel_bytes,p->device_tree_pa,p->device_tree_bytes) ||
        overlap(p->boot_args_pa,OCNEXT_BOOTARGS_V3_BYTES,p->device_tree_pa,p->device_tree_bytes))
        return OCNEXT_BOOTARGS_OVERLAP;
    if (p->video_pa || p->video_stride || p->video_width || p->video_height || p->video_depth) {
        if (!p->video_width || !p->video_height || p->video_depth != 32 ||
            p->video_width > UINT64_MAX/4 || p->video_stride < p->video_width*4 ||
            p->video_height > UINT64_MAX/p->video_stride)
            return OCNEXT_BOOTARGS_RANGE;
        video_bytes=p->video_stride*p->video_height;
        if (!range(p->video_pa,video_bytes,p->phys_base,p->mem_size)) return OCNEXT_BOOTARGS_RANGE;
        if (overlap(p->video_pa,video_bytes,p->kernel_pa,p->kernel_bytes) ||
            overlap(p->video_pa,video_bytes,p->boot_args_pa,OCNEXT_BOOTARGS_V3_BYTES) ||
            overlap(p->video_pa,video_bytes,p->device_tree_pa,p->device_tree_bytes))
            return OCNEXT_BOOTARGS_OVERLAP;
    }
    top=p->kernel_pa+p->kernel_bytes;
    if (top < p->boot_args_pa+OCNEXT_BOOTARGS_V3_BYTES) top=p->boot_args_pa+OCNEXT_BOOTARGS_V3_BYTES;
    if (top < p->device_tree_pa+p->device_tree_bytes) top=p->device_tree_pa+p->device_tree_bytes;
    if ((p->top_of_kernel_data & (OCNEXT_BOOTARGS_GRANULE-1)) ||
        p->top_of_kernel_data < top || p->top_of_kernel_data > p->phys_base+p->mem_size)
        return OCNEXT_BOOTARGS_RANGE;
    dt_va=p->virt_base+(p->device_tree_pa-p->phys_base);
    for (i=0; i<sizeof(temporary); ++i) temporary[i]=0;
    put(temporary,0,p->revision,2); put(temporary,2,p->version,2);
    put(temporary,8,p->virt_base,8); put(temporary,16,p->phys_base,8);
    put(temporary,24,p->mem_size,8); put(temporary,32,p->top_of_kernel_data,8);
    put(temporary,40,p->video_pa,8); /* Explicit PA convention for this study. */
    put(temporary,56,p->video_stride,8); put(temporary,64,p->video_width,8);
    put(temporary,72,p->video_height,8); put(temporary,80,p->video_depth,8);
    put(temporary,88,p->machine_type,4); put(temporary,96,dt_va,8);
    put(temporary,104,p->device_tree_bytes,4);
    for (i=0; i<p->command_line_bytes; ++i) temporary[OCNEXT_BOOTARGS_V3_COMMAND_OFFSET+i]=(uint8_t)p->command_line[i];
    put(temporary,OCNEXT_BOOTARGS_V3_FLAGS_OFFSET,p->boot_flags,8);
    put(temporary,1144,p->mem_size_actual,8);
    for (i=0; i<sizeof(temporary); ++i) out[i]=temporary[i];
    return OCNEXT_BOOTARGS_OK;
}
