#ifndef OCNEXT_VMAP_CFG_H
#define OCNEXT_VMAP_CFG_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Independently authored native request ABI1 and explicit LE research image.
 * Not a CPU ID/BootContract/Apple initialization/device or execution issuer.
 * Requires stable, serialized, accessible caller-owned native objects. */
#define OCNEXT_VMAP_CFG_ABI 1u
#define OCNEXT_VMAP_CFG_ORCHARD_C73A_V2 1u
#define OCNEXT_VMAP_CFG_EXPLICIT_RESEARCH 1u
#define OCNEXT_VMAP_CFG_IMAGE_BYTES 65536u
#define OCNEXT_VMAP_CFG_WORKSPACE_BYTES 65536u
enum ocnext_vmap_cfg_code {
 OCNEXT_VMAP_CFG_OK=0, OCNEXT_VMAP_CFG_ARGUMENT=1,
 OCNEXT_VMAP_CFG_BOUNDS=2, OCNEXT_VMAP_CFG_ALIAS=3,
 OCNEXT_VMAP_CFG_UNSUPPORTED=4, OCNEXT_VMAP_CFG_INTERNAL=5
};
struct ocnext_vmap_cfg_request_v1 {
 uint32_t abi_version,bytes,profile,flags;
 uint64_t owner,generation;
 uint32_t nr_cpus,production_mode,run_installer1,run_installer2,rnd,reserved0;
 uint64_t ecid,ram_size;
 uint8_t mac[4][6];
 char serial[32],model[32],soc_name[32];
 uint8_t seed[64];
 uint64_t reserved[4];
}; /*288B/native8; no pointers/implicit identity/RNG*/
struct ocnext_vmap_cfg_result_v1 {
 uint32_t abi_version,bytes,profile,flags;
 uint64_t owner,generation;
 uint8_t image_sha256[32];
}; /*64B/native8; success: abi1/bytes64, request profile/flags/owner/generation
    * echoed exactly; digest binds all65536 image bytes only, not authority. */
/* Refusal precedence:
 * 1 null request/image/workspace/result or misaligned request/result: ARGUMENT.
 * 2 either supplied buffer size !=65536 or any complete native span overflow:
 *   BOUNDS. Four spans are request288/image65536/workspace65536/result64.
 * 3 any pair of those complete spans overlaps: ALIAS, before request reads.
 * 4 bad ABI/bytes/nonzero reserved0 or reserved[]: ARGUMENT.
 * 5 profile!=1, flags!=EXPLICIT_RESEARCH, owner/generation0, nr_cpus outside
 *   1..128, production_mode outside0..1: UNSUPPORTED (coverage, not CPU fault).
 * 6 each 32B string must contain NUL and all remaining bytes must0: ARGUMENT.
 * Other integer/MAC/seed bytes are explicit research data, including zero.
 * No host identity or randomness is read. The whole LE image is staged in
 * workspace, SHA-256 computed, then image/result published with no fallible
 * call after the first write. Refusals preserve request/image/result; workspace
 * may be clobbered only after complete validation. No concurrent publication,
 * retained state/reset device, physical mapping, MMIO or guest execution. */
enum ocnext_vmap_cfg_code ocnext_vmap_cfg_encode_v1(
 const struct ocnext_vmap_cfg_request_v1 *,uint8_t *image,size_t image_bytes,
 uint8_t *workspace,size_t workspace_bytes,struct ocnext_vmap_cfg_result_v1 *);
#ifdef __cplusplus
}
#endif
#endif
