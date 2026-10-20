#ifndef OCNEXT_GICV3_MODEL_H
#define OCNEXT_GICV3_MODEL_H
/* Pure partial GICv3-derived two-PPI single-security-state Group1 model, ABI1.
 * Explicit software provisioning; no clock/native MMIO/CPU/GIC authority.
 * Bitmap reads know only the two modeled bits. Unknown registers reject. */
#include <stdint.h>
#include <stddef.h>
#define OCNEXT_GICV3_MODEL_ABI 1u
#define OCNEXT_GICV3_MODEL_PROFILE 1u
#define OCNEXT_GICV3_MODEL_BITS UINT32_C(0x48000000)
#define OCNEXT_GICV3_MODEL_VIRTUAL 27u
#define OCNEXT_GICV3_MODEL_PHYSICAL 30u
#define OCNEXT_GICV3_MODEL_SPURIOUS 1023u
enum ocnext_gicv3_model_code {
 OCNEXT_GIC_OK=0,OCNEXT_GIC_ARGUMENT=1,OCNEXT_GIC_UNSUPPORTED=2,
 OCNEXT_GIC_STATE=3,OCNEXT_GIC_STALE=4,OCNEXT_GIC_OVERFLOW=5
};
enum ocnext_gicv3_model_operation {
 OCNEXT_GIC_LINE=1,OCNEXT_GIC_MMIO_READ=2,OCNEXT_GIC_MMIO_WRITE=3,
 OCNEXT_GIC_ICC_READ=4,OCNEXT_GIC_ICC_WRITE=5,
 OCNEXT_GIC_OBSERVE=6,OCNEXT_GIC_CLOSE=7
};
enum ocnext_gicv3_model_icc {
 OCNEXT_GIC_ICC_PMR=1,OCNEXT_GIC_ICC_BPR1=2,OCNEXT_GIC_ICC_IGRPEN1=3,
 OCNEXT_GIC_ICC_IAR1=4,OCNEXT_GIC_ICC_EOIR1=5,
 OCNEXT_GIC_ICC_HPPIR1=6,OCNEXT_GIC_ICC_RPR=7,OCNEXT_GIC_ICC_CTLR=8
};
struct ocnext_gicv3_model_config_v1 {
 uint32_t abi_version,bytes,profile,flags;
 uint64_t owner,generation,dist_base,sgi_base,reserved[2];
};
struct ocnext_gicv3_model_state_v1 {
 uint32_t abi_version,bytes,profile,phase;
 uint64_t owner,generation,next_sequence,epoch,dist_base,sgi_base;
 uint32_t input_lines,sw_pending,enabled,active;
 uint32_t dist_enable,cpu_enable,pmr,depth;
 uint32_t priority[2],active_id[2],active_priority[2];
 uint32_t irq_level,hppir;
 uint64_t completed,iar_reads,eoir_writes,level_updates,reserved[4];
};
struct ocnext_gicv3_model_request_v1 {
 uint32_t abi_version,bytes,operation,flags;
 uint64_t owner,generation,sequence,address,value;
 uint32_t width,el;
 uint64_t reserved[2];
};
struct ocnext_gicv3_model_effect_v1 {
 uint32_t abi_version,bytes,operation,flags;
 uint64_t sequence,next_sequence,epoch,value,value_known_mask;
 uint32_t irq_before,irq_after,hppir,depth;
 uint64_t reserved;
};
/* Stable accessible serialized native spans, aligned8, pairwise disjoint.
 * Every refusal preserves all state/output/input bytes. All validation,
 * routing, quotas and output staging precede logical publication. Native
 * callbacks, interrupts, bus transport and CPU exception entry are separate.
 * No implicit RAZ/WI for an unsupported register or unknown bitmap bit. */
enum ocnext_gicv3_model_code ocnext_gicv3_model_init_v1(
 struct ocnext_gicv3_model_state_v1 *,const struct ocnext_gicv3_model_config_v1 *);
enum ocnext_gicv3_model_code ocnext_gicv3_model_step_v1(
 struct ocnext_gicv3_model_state_v1 *,const struct ocnext_gicv3_model_request_v1 *,
 struct ocnext_gicv3_model_effect_v1 *);
_Static_assert(sizeof(struct ocnext_gicv3_model_config_v1)==64,"gic config64");
_Static_assert(sizeof(struct ocnext_gicv3_model_state_v1)==192,"gic state192");
_Static_assert(sizeof(struct ocnext_gicv3_model_request_v1)==80,"gic request80");
_Static_assert(sizeof(struct ocnext_gicv3_model_effect_v1)==80,"gic effect80");
_Static_assert(offsetof(struct ocnext_gicv3_model_state_v1,irq_level)==120,"irq120");
_Static_assert(offsetof(struct ocnext_gicv3_model_effect_v1,value_known_mask)==48,"known48");
#endif
