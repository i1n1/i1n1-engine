#ifndef OCNEXT_ELF_MODULE_H
#define OCNEXT_ELF_MODULE_H
#include <stddef.h>
#include <stdint.h>

/* Native host module staging ABI1. Distinct from ARM CPU, ONXT, legacy proxy and
 * Apple BootContract. Neither a plan nor staged bytes grant execution. */
#define OCNEXT_ELF_MODULE_ABI_VERSION 1u
#define OCNEXT_ELF_MODULE_MAX_BYTES UINT64_C(8388608)
#define OCNEXT_ELF_MODULE_MAX_PHDRS 32u
#define OCNEXT_ELF_MODULE_MAX_SEGMENTS 8u
#define OCNEXT_ELF_MODULE_MAX_RELOCATIONS 65536u
#define OCNEXT_ELF_MODULE_PLAN_VALID 1u
#define OCNEXT_ELF_MODULE_FILE_SHA_KNOWN 2u
#define OCNEXT_ELF_MODULE_STAGED 4u
#define OCNEXT_ELF_MODULE_IMAGE_SHA_KNOWN 8u

enum ocnext_elf_module_status {
    OCNEXT_ELF_MODULE_OK=0,
    OCNEXT_ELF_MODULE_ARGUMENT=1,
    OCNEXT_ELF_MODULE_FORMAT=2,
    OCNEXT_ELF_MODULE_UNSUPPORTED=3,
    OCNEXT_ELF_MODULE_BOUNDS=4,
    OCNEXT_ELF_MODULE_ALIAS=5,
    OCNEXT_ELF_MODULE_DIGEST=6,
    OCNEXT_ELF_MODULE_RELOCATION=7,
    OCNEXT_ELF_MODULE_QUOTA=8
};

/* All five complete native spans (request, file, backing, workspace, output) must be accessible/stable/serialized and pairwise disjoint.
 * backing is caller-owned RW-NX, page aligned, page-multiple4KiB..8MiB. The
 * caller separately excludes core/runtime/active-code/native allocator storage.
 * This is not an arbitrary-pointer or concurrent-mutation sandbox. */
struct ocnext_elf_module_request {
    uint32_t abi_version, bytes;
    uint64_t owner_id, generation;
    const uint8_t *file;
    uint64_t file_bytes;
    uint8_t *backing;
    uint64_t backing_bytes;
    uint8_t expected_file_sha256[32];
    uint64_t reserved[3];
};
/* Original PT_LOAD fields plus page extent. Offset/RVA are integers, not
 * executable pointers. flags uses ELF PF_R4/PF_W2/PF_X1. Final publisher must
 * overlay the separately reported RELRO pages and leave holes inaccessible. */
struct ocnext_elf_module_segment {
    uint64_t file_offset, file_bytes, rva, memory_bytes, page_rva, page_bytes;
    uint32_t flags, reserved;
};
struct ocnext_elf_module_image {
    uint32_t abi_version, bytes, flags, segment_count;
    uint64_t owner_id, generation;
    uint64_t native_base, image_bytes, entry_rva, relocation_count;
    uint64_t relro_rva, relro_bytes, dynamic_file_offset, dynamic_bytes;
    uint64_t rela_file_offset, rela_bytes, file_bytes;
    uint8_t file_sha256[32], image_sha256[32];
    uint64_t reserved[9];
    struct ocnext_elf_module_segment segments[OCNEXT_ELF_MODULE_MAX_SEGMENTS];
};
struct ocnext_elf_module_workspace { uint64_t opaque[512]; };

/* Profile: ELF64/LSB/EM_X86_64/ET_DYN/SystemV0, minimum LOAD RVA0,
 * 4KiB nonoverlapping LOAD pages, no W+X, self-contained RELA/RELATIVE only.
 * No interpreter/TLS/NEEDED/constructors/symbol resolver or implicit tags.
 * Every relocation target/addend/overflow is validated before backing writes.
 * Plan and every rejection preserve backing/output. Workspace is unspecified.
 * Stage zeros exactly image_bytes (including owned storage holes), copies
 * file-backed LOAD bytes and applies preflighted relocations. Tail beyond
 * image_bytes is preserved. No fallible provider call follows the first write.
 * File input is immutable; byte hashing establishes equality, not authority.
 * Stage success is flags15; plan success flags3 and unknown image hash zero.
 */
enum ocnext_elf_module_status ocnext_elf_module_plan(
    const struct ocnext_elf_module_request *,struct ocnext_elf_module_workspace *,
    struct ocnext_elf_module_image *);
enum ocnext_elf_module_status ocnext_elf_module_stage(
    const struct ocnext_elf_module_request *,struct ocnext_elf_module_workspace *,
    struct ocnext_elf_module_image *);

_Static_assert(sizeof(void *)==8,"native64 only");
_Static_assert(sizeof(struct ocnext_elf_module_request)==112,"ELF request112");
_Static_assert(sizeof(struct ocnext_elf_module_segment)==56,"ELF segment56");
_Static_assert(sizeof(struct ocnext_elf_module_image)==704,"ELF image704");
_Static_assert(sizeof(struct ocnext_elf_module_workspace)==4096,"ELF workspace4096");
_Static_assert(_Alignof(struct ocnext_elf_module_request)==8,"ELF request align8");
_Static_assert(_Alignof(struct ocnext_elf_module_image)==8,"ELF image align8");
_Static_assert(offsetof(struct ocnext_elf_module_image,segments)==256,"ELF segments256");
#endif
