#ifndef OCNEXT_RAM_H
#define OCNEXT_RAM_H
#include "ocnext/mmu.h"
#include "ocnext/proxy.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_RAM_ABI_VERSION 1u
#define OCNEXT_RAM_MAX_REGIONS 32u
#define OCNEXT_RAM_MAX_WRITES 32u
#define OCNEXT_RAM_MAX_TRANSFER 65536u
#define OCNEXT_RAM_READ 1u
#define OCNEXT_RAM_WRITE 2u
#define OCNEXT_RAM_EXECUTE 4u
enum ocnext_ram_result { OCNEXT_RAM_OK=0, OCNEXT_RAM_ARGUMENT=1,
    OCNEXT_RAM_UNMAPPED=2, OCNEXT_RAM_PERMISSION=3, OCNEXT_RAM_EXHAUSTED=4 };
/* Caller supplies actual, initialized, stable native RAM. No implicit zero
 * backing, MMIO, DMA, allocation, guest→host pointer cast or ownership discovery.
 * guest_base is a guest physical address; backing is a separate native pointer.
 * Regions must be guest-sorted, with disjoint guest and native backing ranges.
 * Native bytes must remain accessible, and calls must be serialized with no
 * concurrent CPU/device/callback mutation of backing or registry. */
struct ocnext_ram_region {
    uint64_t guest_base;
    uint8_t *backing;
    size_t bytes;
    uint32_t permissions,reserved;
};
struct ocnext_ram_write { uint64_t guest_address;const uint8_t *source;size_t bytes; };
struct ocnext_ram {
    struct ocnext_ram_region regions[OCNEXT_RAM_MAX_REGIONS];
    uint8_t *scratch;
    size_t scratch_bytes,region_count;
    uint64_t successful_reads,write_transactions,written_bytes;
    uint32_t abi_version,reserved;
};
/* Registry and scratch must be disjoint from all backing. Input descriptors
 * may alias out; they are snapshotted before initialization commits. Failed init
 * changes neither out nor backing/scratch. Scratch must be1..65536 bytes. */
enum ocnext_ram_result ocnext_ram_init(struct ocnext_ram *,
    const struct ocnext_ram_region *,size_t count,uint8_t *scratch,size_t scratch_bytes);
enum ocnext_ram_result ocnext_ram_probe(const struct ocnext_ram *,uint64_t,size_t,unsigned permission);
/* Whole-request preflight before output/counters commit. Output must be disjoint
 * from registry, scratch and every native backing range (a read cannot write RAM).
 * Failure leaves output/RAM/counters unchanged; size is1..65536. */
enum ocnext_ram_result ocnext_ram_read(struct ocnext_ram *,uint64_t,uint8_t *,size_t,unsigned permission);
/* Input descriptors must be disjoint from registry/scratch/backing. Source
 * bytes may alias RAM: ALL sources are snapshotted into caller scratch before
 * any RAM write. Scratch/registry sources are rejected. Transfers may cross
 * adjacent regions; all ranges/permissions/counters are checked before snapshot.
 * Supplied write order defines overlap outcome. Failure changes no RAM/counter
 * or scratch. No reallocating/failing callback exists after the preflight. */
enum ocnext_ram_result ocnext_ram_writev(struct ocnext_ram *,const struct ocnext_ram_write *,size_t count);
/* Explicit convention adapters: MMU returns0success/-1failure, proxy returns
 * exactly1success/0failure. Do not interchange these callback families. */
int ocnext_ram_mmu_probe(void *,uint64_t,size_t,enum ocnext_a64_access);
int ocnext_ram_mmu_read(void *,uint64_t,uint8_t *,size_t);
int ocnext_ram_mmu_writev(void *,const struct ocnext_mmu_span *,size_t,const uint8_t *,size_t);
int ocnext_ram_proxy_probe(void *,uint64_t,size_t,unsigned write);
int ocnext_ram_proxy_read(void *,uint64_t,uint8_t *,size_t);
int ocnext_ram_proxy_writev(void *,const struct ocnext_proxy_write *,size_t);
#ifdef __cplusplus
}
#endif
#endif
