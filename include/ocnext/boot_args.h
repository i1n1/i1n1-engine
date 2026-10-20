#ifndef OCNEXT_BOOT_ARGS_H
#define OCNEXT_BOOT_ARGS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_BOOTARGS_CODEC_ABI_VERSION 1u
#define OCNEXT_BOOTARGS_V3_BYTES 1152u
#define OCNEXT_BOOTARGS_V3_COMMAND_OFFSET 108u
#define OCNEXT_BOOTARGS_V3_COMMAND_BYTES 1024u
#define OCNEXT_BOOTARGS_V3_FLAGS_OFFSET 1136u
#define OCNEXT_BOOTARGS_GRANULE 16384u

/* Explicit legacy proxy Python rv3 wire/public XNU common-field research layout.
 * This is NOT qualification of Golden Gate's complete private boot ABI.
 * Addresses below are guest PA/VA; never host pointers. All regions describe
 * one caller-owned contiguous RAM backing, distinct from native EFI handoff.
 */
struct ocnext_bootargs_study {
    uint16_t revision, version;
    uint32_t machine_type;
    uint64_t virt_base, phys_base, mem_size, mem_size_actual;
    uint64_t kernel_pa, kernel_bytes, boot_args_pa, top_of_kernel_data;
    uint64_t device_tree_pa;
    uint32_t device_tree_bytes;
    uint32_t reserved;
    uint64_t video_pa, video_stride, video_width, video_height, video_depth;
    uint64_t boot_flags;
    const char *command_line;
    size_t command_line_bytes;
};

enum ocnext_bootargs_result { OCNEXT_BOOTARGS_OK=0,
    OCNEXT_BOOTARGS_ARGUMENT=1, OCNEXT_BOOTARGS_LAYOUT=2,
    OCNEXT_BOOTARGS_RANGE=3, OCNEXT_BOOTARGS_OVERLAP=4 };

/* Requires revision3/version2 explicitly, only DarkBoot bit0, no video rotation,
 * 32-bit framebuffer if present. Checks all guest ranges, PA48/canonical VA48,
 * 16KiB placement, nonoverlap, DT physical-to-virtual conversion, top bound,
 * ASCII command length/termination. Error leaves output unchanged. Exact
 * 1152-byte output; C padding/native pointers are never serialized.
 */
enum ocnext_bootargs_result ocnext_bootargs_v3_encode(
    const struct ocnext_bootargs_study *, uint8_t *, size_t);

#ifdef __cplusplus
}
#endif
#endif
