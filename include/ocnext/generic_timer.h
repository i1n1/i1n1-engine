#ifndef OCNEXT_GENERIC_TIMER_H
#define OCNEXT_GENERIC_TIMER_H
/* Serialized software Generic Timer bank ABI1. This pure transition library
 * consumes explicitly supplied nanoseconds; it issues no clock/IRQ authority.
 * Native provider, CPU access checks and output delivery are separate owners. */
#include <stddef.h>
#include <stdint.h>
#define OCNEXT_GENERIC_TIMER_ABI 1u
enum ocnext_generic_timer_code {
 OCNEXT_TIMER_OK=0, OCNEXT_TIMER_ARGUMENT=1, OCNEXT_TIMER_UNSUPPORTED=2,
 OCNEXT_TIMER_STATE=3, OCNEXT_TIMER_CLOCK=4, OCNEXT_TIMER_OVERFLOW=5
};
enum ocnext_generic_timer_operation {
 OCNEXT_TIMER_READ_PHYSICAL_COUNT=1, OCNEXT_TIMER_READ_VIRTUAL_COUNT=2,
 OCNEXT_TIMER_READ_FREQUENCY=3, OCNEXT_TIMER_READ_PHYSICAL_CTL=4,
 OCNEXT_TIMER_READ_VIRTUAL_CTL=5, OCNEXT_TIMER_READ_PHYSICAL_CVAL=6,
 OCNEXT_TIMER_READ_VIRTUAL_CVAL=7, OCNEXT_TIMER_READ_PHYSICAL_TVAL=8,
 OCNEXT_TIMER_READ_VIRTUAL_TVAL=9, OCNEXT_TIMER_WRITE_PHYSICAL_CVAL=10,
 OCNEXT_TIMER_WRITE_VIRTUAL_CVAL=11, OCNEXT_TIMER_WRITE_PHYSICAL_TVAL=12,
 OCNEXT_TIMER_WRITE_VIRTUAL_TVAL=13, OCNEXT_TIMER_WRITE_PHYSICAL_CTL=14,
 OCNEXT_TIMER_WRITE_VIRTUAL_CTL=15, OCNEXT_TIMER_POLL=16
};
struct ocnext_generic_timer_config_v1 {
 uint32_t abi_version,bytes,flags,reserved;
 uint64_t frequency_hz,virtual_offset;
};
struct ocnext_generic_timer_state_v1 {
 uint32_t abi_version,bytes;
 uint64_t frequency_hz,virtual_offset,last_ns,physical_count,next_sequence;
 uint64_t physical_cval,virtual_cval;
 uint32_t physical_ctl,virtual_ctl,sample_known,reserved0;
 uint32_t output_levels,reserved1;
 uint64_t sample_count,reserved[4];
};
struct ocnext_generic_timer_request_v1 {
 uint32_t abi_version,bytes,operation,flags;
 uint64_t sequence,now_ns,value,reserved;
};
struct ocnext_generic_timer_effect_v1 {
 uint32_t abi_version,bytes,status,operation;
 uint64_t sequence,value,physical_count,now_ns;
 uint32_t output_levels,levels_changed;
 uint64_t value_known_mask,next_sequence,reserved;
};
/* All native spans are stable, accessible, serialized, aligned8 and disjoint.
 * Errors preserve every input/state/output byte. Successful publication has
 * no fallible operation after its first write. Config is explicit provisioning,
 * not an architectural reset or default-time claim. */
enum ocnext_generic_timer_code ocnext_generic_timer_init_v1(
 struct ocnext_generic_timer_state_v1 *,const struct ocnext_generic_timer_config_v1 *);
enum ocnext_generic_timer_code ocnext_generic_timer_step_v1(
 struct ocnext_generic_timer_state_v1 *,const struct ocnext_generic_timer_request_v1 *,
 struct ocnext_generic_timer_effect_v1 *);
_Static_assert(sizeof(struct ocnext_generic_timer_config_v1)==32,"timer config32");
_Static_assert(sizeof(struct ocnext_generic_timer_state_v1)==128,"timer state128");
_Static_assert(sizeof(struct ocnext_generic_timer_request_v1)==48,"timer request48");
_Static_assert(sizeof(struct ocnext_generic_timer_effect_v1)==80,"timer effect80");
_Static_assert(offsetof(struct ocnext_generic_timer_state_v1,output_levels)==80,"levels80");
_Static_assert(offsetof(struct ocnext_generic_timer_effect_v1,value_known_mask)==56,"known56");
#endif
