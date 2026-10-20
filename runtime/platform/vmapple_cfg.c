/* VMApple cfg-v2 explicit research image encoder, native request ABI1.
 *
 * Independently authored from the issued Phase40 header, contract table and
 * result clarification; no upstream cfg.c text is used. This is a stateless
 * byte encoder only: no host identity/RNG, retained template or reset device,
 * physical mapping, MMIO, CPU ID/BootContract/Apple initialization or guest
 * execution authority. The caller owns stable, serialized, accessible native
 * objects; address checks are contract preflight, not a pointer sandbox. */
#include "ocnext/vmapple_cfg.h"
#include "ocnext/sha256.h"

#define CFG_NATIVE_ALIGN 8u
#define CFG_REQUEST_BYTES 288u
#define CFG_RESULT_BYTES 64u
#define CFG_VERSION 2u
#define CFG_STRING_BYTES 32u
#define CFG_MAC_COUNT 4u
#define CFG_MAC_BYTES 6u
#define CFG_MAC_STRIDE 8u
#define CFG_CPU_CAPACITY 128u
#define CFG_CPU_ID_BYTES 4u
#define CFG_SCRATCH_BYTES 512u
#define CFG_SEED_BYTES 64u

/* Explicit little-endian image offsets from the issued contract table. The
 * stale source comments after the CPU ID array are deliberately not used:
 * CPU IDs end at 0x2ff, so scratch starts at 0x300 and serial at 0x500. */
#define CFG_OFF_VERSION 0x000u
#define CFG_OFF_NR_CPUS 0x004u
#define CFG_OFF_PRODUCTION 0x008u
#define CFG_OFF_ONE_00C 0x00cu
#define CFG_OFF_X20_010 0x010u
#define CFG_OFF_ECID 0x018u
#define CFG_OFF_RAM_SIZE 0x020u
#define CFG_OFF_INSTALLER1 0x028u
#define CFG_OFF_ONE_02C 0x02cu
#define CFG_OFF_ONE_030 0x030u
#define CFG_OFF_INSTALLER2 0x034u
#define CFG_OFF_RND 0x038u
#define CFG_OFF_MAC 0x040u
#define CFG_OFF_CPU_IDS 0x100u
#define CFG_OFF_SCRATCH 0x300u
#define CFG_OFF_SERIAL 0x500u
#define CFG_OFF_DA 0x520u
#define CFG_OFF_MODEL 0x540u
#define CFG_OFF_ZERO_560 0x560u
#define CFG_OFF_ONE_580 0x580u
#define CFG_OFF_SOC_NAME 0x584u
#define CFG_OFF_SEED 0x5c8u

#define REQ_MEMBER_BYTES(m) sizeof(((struct ocnext_vmap_cfg_request_v1 *)0)->m)
#define RES_MEMBER_BYTES(m) sizeof(((struct ocnext_vmap_cfg_result_v1 *)0)->m)

/* Issued native ABI1 shape: request288/native8, result64/native8. */
_Static_assert(sizeof(struct ocnext_vmap_cfg_request_v1) == CFG_REQUEST_BYTES,
               "request ABI1 is 288 bytes");
_Static_assert(_Alignof(struct ocnext_vmap_cfg_request_v1) == CFG_NATIVE_ALIGN,
               "request ABI1 is native8");
_Static_assert(sizeof(struct ocnext_vmap_cfg_result_v1) == CFG_RESULT_BYTES,
               "result ABI1 is 64 bytes");
_Static_assert(_Alignof(struct ocnext_vmap_cfg_result_v1) == CFG_NATIVE_ALIGN,
               "result ABI1 is native8");
_Static_assert(offsetof(struct ocnext_vmap_cfg_request_v1, owner) == 16u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, generation) == 24u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, nr_cpus) == 32u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, reserved0) == 52u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, ecid) == 56u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, ram_size) == 64u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, mac) == 72u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, serial) == 96u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, model) == 128u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, soc_name) == 160u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, seed) == 192u &&
               offsetof(struct ocnext_vmap_cfg_request_v1, reserved) == 256u,
               "request ABI1 offsets");
_Static_assert(REQ_MEMBER_BYTES(mac) == CFG_MAC_COUNT * CFG_MAC_BYTES &&
               REQ_MEMBER_BYTES(serial) == CFG_STRING_BYTES &&
               REQ_MEMBER_BYTES(model) == CFG_STRING_BYTES &&
               REQ_MEMBER_BYTES(soc_name) == CFG_STRING_BYTES &&
               REQ_MEMBER_BYTES(seed) == CFG_SEED_BYTES &&
               REQ_MEMBER_BYTES(reserved) == 4u * sizeof(uint64_t),
               "request ABI1 fixed arrays");
_Static_assert(offsetof(struct ocnext_vmap_cfg_result_v1, owner) == 16u &&
               offsetof(struct ocnext_vmap_cfg_result_v1, generation) == 24u &&
               offsetof(struct ocnext_vmap_cfg_result_v1, image_sha256) == 32u &&
               RES_MEMBER_BYTES(image_sha256) == OCNEXT_SHA256_BYTES &&
               OCNEXT_SHA256_BYTES == 32u,
               "result ABI1 offsets and digest width");
_Static_assert(OCNEXT_VMAP_CFG_IMAGE_BYTES == 65536u &&
               OCNEXT_VMAP_CFG_WORKSPACE_BYTES == OCNEXT_VMAP_CFG_IMAGE_BYTES,
               "image and workspace are exactly 65536 bytes");

/* Contract table geometry, including the explicit zero regions. */
_Static_assert(CFG_OFF_MAC + CFG_MAC_COUNT * CFG_MAC_STRIDE <= CFG_OFF_CPU_IDS,
               "four 8-byte MAC slots precede CPU IDs");
_Static_assert(CFG_OFF_CPU_IDS + CFG_CPU_CAPACITY * CFG_CPU_ID_BYTES ==
               CFG_OFF_SCRATCH, "CPU IDs occupy 0x100..0x2ff");
_Static_assert(CFG_OFF_SCRATCH + CFG_SCRATCH_BYTES == CFG_OFF_SERIAL,
               "zero scratch occupies 0x300..0x4ff");
_Static_assert(CFG_OFF_SERIAL + CFG_STRING_BYTES == CFG_OFF_DA &&
               CFG_OFF_DA + CFG_STRING_BYTES == CFG_OFF_MODEL &&
               CFG_OFF_MODEL + CFG_STRING_BYTES == CFG_OFF_ZERO_560 &&
               CFG_OFF_ZERO_560 + CFG_STRING_BYTES == CFG_OFF_ONE_580 &&
               CFG_OFF_ONE_580 + 4u == CFG_OFF_SOC_NAME,
               "string and constant slots 0x500..0x5a3");
_Static_assert(CFG_OFF_SOC_NAME + CFG_STRING_BYTES <= CFG_OFF_SEED &&
               CFG_OFF_SEED + CFG_SEED_BYTES <= OCNEXT_VMAP_CFG_IMAGE_BYTES,
               "seed occupies 0x5c8..0x607 inside the image");

static void copy_bytes(void *dst, const void *src, size_t bytes)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;

    for (i = 0; i < bytes; ++i)
        d[i] = s[i];
}

static void put_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

static void put_le64(uint8_t *dst, uint64_t value)
{
    put_le32(dst, (uint32_t)value);
    put_le32(dst + 4, (uint32_t)(value >> 32));
}

/* Complete half-open span [base, base + bytes). An end that is not
 * representable is overflow, including a span touching the top address. */
static int span_end(uintptr_t base, uintptr_t bytes, uintptr_t *end)
{
    if (bytes > UINTPTR_MAX - base)
        return 0;
    *end = base + bytes;
    return 1;
}

/* Stage 6: a NUL inside the 32 bytes and only zero bytes after the first NUL.
 * Bytes before the NUL are unrestricted explicit research data. */
static int string32_canonical(const char *field)
{
    size_t i = 0;

    while (i < CFG_STRING_BYTES && (unsigned char)field[i] != 0u)
        ++i;
    if (i == CFG_STRING_BYTES)
        return 0;
    for (++i; i < CFG_STRING_BYTES; ++i)
        if ((unsigned char)field[i] != 0u)
            return 0;
    return 1;
}

/* Bytes before the first NUL; the rest of the slot stays staged zero. */
static void put_string32(uint8_t *dst, const char *field)
{
    size_t i;

    for (i = 0; i < CFG_STRING_BYTES && (unsigned char)field[i] != 0u; ++i)
        dst[i] = (uint8_t)(unsigned char)field[i];
}

enum ocnext_vmap_cfg_code ocnext_vmap_cfg_encode_v1(
    const struct ocnext_vmap_cfg_request_v1 *request, uint8_t *image,
    size_t image_bytes, uint8_t *workspace, size_t workspace_bytes,
    struct ocnext_vmap_cfg_result_v1 *result)
{
    static const uint8_t da[3] = { 0x44u, 0x2fu, 0x41u }; /* "D/A" */
    struct ocnext_vmap_cfg_request_v1 req;
    struct ocnext_vmap_cfg_result_v1 staged;
    uint8_t digest[OCNEXT_SHA256_BYTES];
    uintptr_t base[4], end[4];
    uint32_t cpu;
    size_t i, j;

    /* Stage 1: null objects, or a request/result off its native8 alignment.
     * Image and workspace are byte buffers and may be unaligned. */
    if (request == NULL || image == NULL || workspace == NULL || result == NULL)
        return OCNEXT_VMAP_CFG_ARGUMENT;
    if ((uintptr_t)(const void *)request % CFG_NATIVE_ALIGN != 0u ||
        (uintptr_t)(void *)result % CFG_NATIVE_ALIGN != 0u)
        return OCNEXT_VMAP_CFG_ARGUMENT;

    /* Stage 2: exact supplied sizes, then all four complete native spans. */
    if (image_bytes != OCNEXT_VMAP_CFG_IMAGE_BYTES ||
        workspace_bytes != OCNEXT_VMAP_CFG_WORKSPACE_BYTES)
        return OCNEXT_VMAP_CFG_BOUNDS;
    base[0] = (uintptr_t)(const void *)request;
    base[1] = (uintptr_t)(void *)image;
    base[2] = (uintptr_t)(void *)workspace;
    base[3] = (uintptr_t)(void *)result;
    if (!span_end(base[0], CFG_REQUEST_BYTES, &end[0]) ||
        !span_end(base[1], OCNEXT_VMAP_CFG_IMAGE_BYTES, &end[1]) ||
        !span_end(base[2], OCNEXT_VMAP_CFG_WORKSPACE_BYTES, &end[2]) ||
        !span_end(base[3], CFG_RESULT_BYTES, &end[3]))
        return OCNEXT_VMAP_CFG_BOUNDS;

    /* Stage 3: all six pairs of complete spans, before any request read. */
    for (i = 0; i < 4u; ++i)
        for (j = i + 1u; j < 4u; ++j)
            if (base[i] < end[j] && base[j] < end[i])
                return OCNEXT_VMAP_CFG_ALIAS;

    /* One private snapshot; every later check and staged byte uses it. */
    copy_bytes(&req, request, CFG_REQUEST_BYTES);

    /* Stage 4: ABI shape and reserved fields. */
    if (req.abi_version != OCNEXT_VMAP_CFG_ABI ||
        req.bytes != CFG_REQUEST_BYTES || req.reserved0 != 0u)
        return OCNEXT_VMAP_CFG_ARGUMENT;
    for (i = 0; i < 4u; ++i)
        if (req.reserved[i] != 0u)
            return OCNEXT_VMAP_CFG_ARGUMENT;

    /* Stage 5: coverage of the single named explicit research profile. */
    if (req.profile != OCNEXT_VMAP_CFG_ORCHARD_C73A_V2 ||
        req.flags != OCNEXT_VMAP_CFG_EXPLICIT_RESEARCH ||
        req.owner == 0u || req.generation == 0u ||
        req.nr_cpus < 1u || req.nr_cpus > CFG_CPU_CAPACITY ||
        req.production_mode > 1u)
        return OCNEXT_VMAP_CFG_UNSUPPORTED;

    /* Stage 6: canonical fixed 32-byte strings. */
    if (!string32_canonical(req.serial) || !string32_canonical(req.model) ||
        !string32_canonical(req.soc_name))
        return OCNEXT_VMAP_CFG_ARGUMENT;

    /* Validation complete; workspace may be clobbered from here on. Every
     * byte not named below is the profile's zero: 0x014, 0x03c, MAC padding,
     * unused CPU IDs, scratch 0x300..0x4ff, 0x560..0x57f and the tail. */
    for (i = 0; i < OCNEXT_VMAP_CFG_WORKSPACE_BYTES; ++i)
        workspace[i] = 0u;
    put_le32(workspace + CFG_OFF_VERSION, CFG_VERSION);
    put_le32(workspace + CFG_OFF_NR_CPUS, req.nr_cpus);
    put_le32(workspace + CFG_OFF_PRODUCTION, req.production_mode);
    put_le32(workspace + CFG_OFF_ONE_00C, 1u);
    put_le32(workspace + CFG_OFF_X20_010, 0x20u);
    put_le64(workspace + CFG_OFF_ECID, req.ecid);
    put_le64(workspace + CFG_OFF_RAM_SIZE, req.ram_size);
    put_le32(workspace + CFG_OFF_INSTALLER1, req.run_installer1);
    put_le32(workspace + CFG_OFF_ONE_02C, 1u);
    put_le32(workspace + CFG_OFF_ONE_030, 1u);
    put_le32(workspace + CFG_OFF_INSTALLER2, req.run_installer2);
    put_le32(workspace + CFG_OFF_RND, req.rnd);
    for (i = 0; i < CFG_MAC_COUNT; ++i)
        copy_bytes(workspace + CFG_OFF_MAC + CFG_MAC_STRIDE * i, req.mac[i],
                   CFG_MAC_BYTES);
    /* Logical source-profile CPU IDs 0..nr-1 only; no CPU/SMP authority. */
    for (cpu = 0; cpu < req.nr_cpus; ++cpu)
        put_le32(workspace + CFG_OFF_CPU_IDS + CFG_CPU_ID_BYTES * cpu, cpu);
    put_string32(workspace + CFG_OFF_SERIAL, req.serial);
    copy_bytes(workspace + CFG_OFF_DA, da, sizeof da);
    put_string32(workspace + CFG_OFF_MODEL, req.model);
    put_le32(workspace + CFG_OFF_ONE_580, 1u);
    put_string32(workspace + CFG_OFF_SOC_NAME, req.soc_name);
    copy_bytes(workspace + CFG_OFF_SEED, req.seed, CFG_SEED_BYTES);

    /* Last fallible operation; on failure image and result stay untouched. */
    if (ocnext_sha256_digest(workspace, OCNEXT_VMAP_CFG_IMAGE_BYTES, digest) != 0)
        return OCNEXT_VMAP_CFG_INTERNAL;

    staged.abi_version = OCNEXT_VMAP_CFG_ABI;
    staged.bytes = CFG_RESULT_BYTES;
    staged.profile = req.profile;
    staged.flags = req.flags;
    staged.owner = req.owner;
    staged.generation = req.generation;
    copy_bytes(staged.image_sha256, digest, OCNEXT_SHA256_BYTES);

    /* Publication: image first, result last, no fallible call in between. */
    copy_bytes(image, workspace, OCNEXT_VMAP_CFG_IMAGE_BYTES);
    result->abi_version = staged.abi_version;
    result->bytes = staged.bytes;
    result->profile = staged.profile;
    result->flags = staged.flags;
    result->owner = staged.owner;
    result->generation = staged.generation;
    copy_bytes(result->image_sha256, staged.image_sha256, OCNEXT_SHA256_BYTES);
    return OCNEXT_VMAP_CFG_OK;
}
