/* Pure partial GICv3-derived two-PPI single-security-state Group1 model, ABI1.
 * Independently authored from the Root Phase37 contract. No libc, callbacks,
 * clock, native MMIO, CPU interrupt or GIC identity authority. */
#include "ocnext/gicv3_model.h"

#define APERTURE UINT64_C(0x10000)
#define PHASE_READY 1u
#define PHASE_CLOSED 2u

typedef struct ocnext_gicv3_model_state_v1 state_t;
typedef struct ocnext_gicv3_model_request_v1 request_t;
typedef struct ocnext_gicv3_model_effect_v1 effect_t;
typedef struct ocnext_gicv3_model_config_v1 config_t;

static void copy_bytes(void *dst, const void *src, size_t n) {
 volatile unsigned char *d = (volatile unsigned char *)dst;
 const volatile unsigned char *s = (const volatile unsigned char *)src;
 size_t i;
 for (i = 0; i < n; i++) d[i] = s[i];
}

static void zero_bytes(void *dst, size_t n) {
 volatile unsigned char *d = (volatile unsigned char *)dst;
 size_t i;
 for (i = 0; i < n; i++) d[i] = 0;
}

/* aligned8, nonnull, nonwrapping */
static int span_ok(const void *p, size_t n) {
 uintptr_t a = (uintptr_t)p;
 if (!p || (a & 7u)) return 0;
 if (a + n < a) return 0;
 return 1;
}

static int disjoint(const void *p, size_t pn, const void *q, size_t qn) {
 uintptr_t a = (uintptr_t)p, b = (uintptr_t)q;
 return a + pn <= b || b + qn <= a;
}

static int apertures_ok(uint64_t dist, uint64_t sgi) {
 if (dist & (APERTURE - 1) || sgi & (APERTURE - 1)) return 0;
 if (dist > UINT64_MAX - APERTURE || sgi > UINT64_MAX - APERTURE) return 0;
 if (dist == sgi) return 0;
 return 1;
}

static int prio_ok(uint32_t p) { return p <= 0xf8u && (p & 7u) == 0; }

static uint32_t id_to_idx(uint32_t id) { return id == OCNEXT_GICV3_MODEL_VIRTUAL ? 0u : 1u; }
static uint32_t idx_to_id(uint32_t i) { return i ? OCNEXT_GICV3_MODEL_PHYSICAL : OCNEXT_GICV3_MODEL_VIRTUAL; }
static uint32_t to_ext(uint32_t m) {
 return ((m & 1u) ? (UINT32_C(1) << 27) : 0u) | ((m & 2u) ? (UINT32_C(1) << 30) : 0u);
}

static void compute(const state_t *s, uint32_t *hppir, uint32_t *irq) {
 uint32_t cand = 0, idx = 0, prio;
 *hppir = OCNEXT_GICV3_MODEL_SPURIOUS;
 *irq = 0;
 if (!(s->dist_enable && s->cpu_enable)) return;
 cand = (s->sw_pending | s->input_lines) & s->enabled & ~s->active & 3u;
 if (!cand) return;
 if (cand == 3u) idx = (s->priority[0] <= s->priority[1]) ? 0u : 1u;
 else idx = (cand & 1u) ? 0u : 1u;
 prio = s->priority[idx];
 *hppir = idx_to_id(idx);
 if (prio < s->pmr && (s->depth == 0 || prio < s->active_priority[s->depth - 1]))
  *irq = 1;
}

static int state_valid(const state_t *s) {
 uint32_t i, hp, irq, mask = 0;
 uint64_t sum;
 if (s->abi_version != OCNEXT_GICV3_MODEL_ABI || s->bytes != sizeof(state_t) ||
     s->profile != OCNEXT_GICV3_MODEL_PROFILE || s->phase != PHASE_READY) return 0;
 if (!s->owner || !s->generation) return 0;
 if (!apertures_ok(s->dist_base, s->sgi_base)) return 0;
 for (i = 0; i < 4; i++) if (s->reserved[i]) return 0;
 if (s->input_lines > 3 || s->sw_pending > 3 || s->enabled > 3 || s->active > 3) return 0;
 if (s->dist_enable > 1 || s->cpu_enable > 1 || s->irq_level > 1) return 0;
 if (!prio_ok(s->pmr) || !prio_ok(s->priority[0]) || !prio_ok(s->priority[1])) return 0;
 if (s->depth > 2) return 0;
 for (i = 0; i < 2; i++) {
  if (i < s->depth) {
   uint32_t id = s->active_id[i], b;
   if (id != OCNEXT_GICV3_MODEL_VIRTUAL && id != OCNEXT_GICV3_MODEL_PHYSICAL) return 0;
   b = UINT32_C(1) << id_to_idx(id);
   if (mask & b) return 0;
   mask |= b;
   if (s->active_priority[i] != s->priority[id_to_idx(id)]) return 0;
   if (i > 0 && s->active_priority[i] >= s->active_priority[i - 1]) return 0;
  } else if (s->active_id[i] != 0 || s->active_priority[i] != 0) return 0;
 }
 if (mask != s->active) return 0;
 if (s->next_sequence < 1) return 0;
 if (s->completed != s->next_sequence - 1 || s->epoch != s->completed) return 0;
 sum = s->iar_reads;
 if (sum > UINT64_MAX - s->eoir_writes) return 0;
 sum += s->eoir_writes;
 if (sum > UINT64_MAX - s->level_updates) return 0;
 sum += s->level_updates;
 if (sum > s->completed) return 0;
 if (s->eoir_writes > s->iar_reads) return 0;
 if (s->depth > s->iar_reads - s->eoir_writes) return 0;
 compute(s, &hp, &irq);
 if (s->hppir != hp || s->irq_level != irq) return 0;
 return 1;
}

enum ocnext_gicv3_model_code ocnext_gicv3_model_init_v1(
 struct ocnext_gicv3_model_state_v1 *state, const struct ocnext_gicv3_model_config_v1 *cfg) {
 state_t st;
 config_t c;
 if (!span_ok(state, sizeof(state_t)) || !span_ok(cfg, sizeof(config_t))) return OCNEXT_GIC_ARGUMENT;
 if (!disjoint(state, sizeof(state_t), cfg, sizeof(config_t))) return OCNEXT_GIC_ARGUMENT;
 copy_bytes(&c, cfg, sizeof c);
 if (c.abi_version != OCNEXT_GICV3_MODEL_ABI || c.bytes != sizeof(config_t) ||
     c.profile != OCNEXT_GICV3_MODEL_PROFILE || c.flags != 0 ||
     c.reserved[0] || c.reserved[1] || !c.owner || !c.generation ||
     !apertures_ok(c.dist_base, c.sgi_base))
  return OCNEXT_GIC_ARGUMENT;
 zero_bytes(&st, sizeof st);
 st.abi_version = OCNEXT_GICV3_MODEL_ABI;
 st.bytes = sizeof(state_t);
 st.profile = OCNEXT_GICV3_MODEL_PROFILE;
 st.phase = PHASE_READY;
 st.owner = c.owner;
 st.generation = c.generation;
 st.next_sequence = 1;
 st.dist_base = c.dist_base;
 st.sgi_base = c.sgi_base;
 st.priority[0] = st.priority[1] = 0xa0u;
 st.hppir = OCNEXT_GICV3_MODEL_SPURIOUS;
 copy_bytes(state, &st, sizeof st);
 return OCNEXT_GIC_OK;
}

/* Successful operations set the private read value and known-bit mask. */
static enum ocnext_gicv3_model_code do_mmio(state_t *s, const request_t *r, int write,
 uint64_t *value, uint64_t *mask) {
 uint64_t off, a = r->address, ext;
 uint32_t w = r->width;
 if (a >= s->dist_base && a - s->dist_base < APERTURE) {
  off = a - s->dist_base;
  if (APERTURE - off < w) return OCNEXT_GIC_UNSUPPORTED;
  if (off != 0 || w != 4) return OCNEXT_GIC_UNSUPPORTED;
  if (!write) { *value = (uint64_t)s->dist_enable << 1; *mask = 2; return OCNEXT_GIC_OK; }
  if (r->value != 0 && r->value != 2) return OCNEXT_GIC_UNSUPPORTED;
  s->dist_enable = (uint32_t)(r->value >> 1);
  return OCNEXT_GIC_OK;
 }
 if (!(a >= s->sgi_base && a - s->sgi_base < APERTURE)) return OCNEXT_GIC_UNSUPPORTED;
 off = a - s->sgi_base;
 if (APERTURE - off < w) return OCNEXT_GIC_UNSUPPORTED;
 if (off == 0x400 + OCNEXT_GICV3_MODEL_VIRTUAL || off == 0x400 + OCNEXT_GICV3_MODEL_PHYSICAL) {
  uint32_t idx = off == 0x400 + OCNEXT_GICV3_MODEL_VIRTUAL ? 0u : 1u;
  if (w != 1) return OCNEXT_GIC_UNSUPPORTED;
  if (!write) { *value = s->priority[idx]; *mask = 0xff; return OCNEXT_GIC_OK; }
  if (r->value > 0xf8 || (r->value & 7u)) return OCNEXT_GIC_UNSUPPORTED;
  if (s->active & (1u << idx)) return OCNEXT_GIC_UNSUPPORTED;
  s->priority[idx] = (uint32_t)r->value;
  return OCNEXT_GIC_OK;
 }
 if (w != 4) return OCNEXT_GIC_UNSUPPORTED;
 switch (off) {
 case 0x80:
  if (!write) { *value = OCNEXT_GICV3_MODEL_BITS; *mask = OCNEXT_GICV3_MODEL_BITS; return OCNEXT_GIC_OK; }
  return r->value == OCNEXT_GICV3_MODEL_BITS ? OCNEXT_GIC_OK : OCNEXT_GIC_UNSUPPORTED;
 case 0x100: case 0x180: case 0x200: case 0x280: case 0x300:
  if (!write) {
   uint32_t m = off == 0x100 || off == 0x180 ? s->enabled :
                off == 0x300 ? s->active : (s->sw_pending | s->input_lines);
   *value = to_ext(m & 3u); *mask = OCNEXT_GICV3_MODEL_BITS;
   return OCNEXT_GIC_OK;
  }
  if (off == 0x300) return OCNEXT_GIC_UNSUPPORTED;
  if (r->value & ~(uint64_t)OCNEXT_GICV3_MODEL_BITS) return OCNEXT_GIC_UNSUPPORTED;
  ext = r->value;
  {
   uint32_t m = ((ext >> 27) & 1u) | (((ext >> 30) & 1u) << 1);
   if (off == 0x100) s->enabled |= m;
   else if (off == 0x180) s->enabled &= ~m;
   else if (off == 0x200) s->sw_pending |= m;
   else s->sw_pending &= ~m;
  }
  return OCNEXT_GIC_OK;
 default:
  return OCNEXT_GIC_UNSUPPORTED;
 }
}

static enum ocnext_gicv3_model_code do_icc(state_t *s, const request_t *r, int write,
 uint64_t *value, uint64_t *mask) {
 uint32_t reg = (r->address <= 0xffffffffu) ? (uint32_t)r->address : 0u;
 if (r->width != 8 || reg == 0) return OCNEXT_GIC_UNSUPPORTED;
 switch (reg) {
 case OCNEXT_GIC_ICC_PMR:
  if (!write) { *value = s->pmr; *mask = UINT64_MAX; return OCNEXT_GIC_OK; }
  if (r->value > 0xf8 || (r->value & 7u)) return OCNEXT_GIC_UNSUPPORTED;
  s->pmr = (uint32_t)r->value; return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_BPR1:
  if (!write) { *value = 3; *mask = 7; return OCNEXT_GIC_OK; }
  return r->value == 3 ? OCNEXT_GIC_OK : OCNEXT_GIC_UNSUPPORTED;
 case OCNEXT_GIC_ICC_IGRPEN1:
  if (!write) { *value = s->cpu_enable; *mask = 1; return OCNEXT_GIC_OK; }
  if (r->value > 1) return OCNEXT_GIC_UNSUPPORTED;
  s->cpu_enable = (uint32_t)r->value; return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_IAR1:
  if (write) return OCNEXT_GIC_UNSUPPORTED;
  s->iar_reads++;
  *mask = UINT64_MAX;
  if (!s->irq_level) { *value = OCNEXT_GICV3_MODEL_SPURIOUS; return OCNEXT_GIC_OK; }
  if (s->depth >= 2 || s->hppir == OCNEXT_GICV3_MODEL_SPURIOUS) return OCNEXT_GIC_UNSUPPORTED;
  {
   uint32_t idx = id_to_idx(s->hppir);
   s->sw_pending &= ~(1u << idx);
   s->active |= 1u << idx;
   s->active_id[s->depth] = s->hppir;
   s->active_priority[s->depth] = s->priority[idx];
   s->depth++;
   *value = s->hppir;
  }
  return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_EOIR1:
  if (!write) return OCNEXT_GIC_UNSUPPORTED;
  if (r->value != OCNEXT_GICV3_MODEL_VIRTUAL && r->value != OCNEXT_GICV3_MODEL_PHYSICAL)
   return OCNEXT_GIC_UNSUPPORTED;
  if (s->depth == 0) return OCNEXT_GIC_STATE;
  if (r->value != s->active_id[s->depth - 1]) return OCNEXT_GIC_STATE;
  s->active &= ~(1u << id_to_idx((uint32_t)r->value));
  s->depth--;
  s->active_id[s->depth] = 0;
  s->active_priority[s->depth] = 0;
  s->eoir_writes++;
  return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_HPPIR1:
  if (write) return OCNEXT_GIC_UNSUPPORTED;
  *value = s->hppir; *mask = UINT64_MAX; return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_RPR:
  if (write) return OCNEXT_GIC_UNSUPPORTED;
  *value = s->depth ? s->active_priority[s->depth - 1] : 0xffu;
  *mask = UINT64_MAX; return OCNEXT_GIC_OK;
 case OCNEXT_GIC_ICC_CTLR:
  if (!write) { *value = 0; *mask = 2; return OCNEXT_GIC_OK; }
  return r->value == 0 ? OCNEXT_GIC_OK : OCNEXT_GIC_UNSUPPORTED;
 default:
  return OCNEXT_GIC_UNSUPPORTED;
 }
}

enum ocnext_gicv3_model_code ocnext_gicv3_model_step_v1(
 struct ocnext_gicv3_model_state_v1 *state, const struct ocnext_gicv3_model_request_v1 *req,
 struct ocnext_gicv3_model_effect_v1 *effect) {
 state_t s;
 effect_t e;
 request_t r;
 enum ocnext_gicv3_model_code rc;
 uint64_t value = 0, mask = 0;
 int write = 0;
 uint32_t irq_before = 0;

 if (!span_ok(state, sizeof(state_t)) || !span_ok(req, sizeof(request_t)) ||
     !span_ok(effect, sizeof(effect_t))) return OCNEXT_GIC_ARGUMENT;
 if (!disjoint(state, sizeof(state_t), req, sizeof(request_t)) ||
     !disjoint(state, sizeof(state_t), effect, sizeof(effect_t)) ||
     !disjoint(req, sizeof(request_t), effect, sizeof(effect_t))) return OCNEXT_GIC_ARGUMENT;

 copy_bytes(&r, req, sizeof r);
 copy_bytes(&s, state, sizeof s);

 if (r.abi_version != OCNEXT_GICV3_MODEL_ABI || r.bytes != sizeof(request_t) || r.flags != 0 ||
     r.reserved[0] || r.reserved[1])
  return OCNEXT_GIC_ARGUMENT;
 if (r.operation < OCNEXT_GIC_LINE || r.operation > OCNEXT_GIC_CLOSE) return OCNEXT_GIC_ARGUMENT;

 if (!state_valid(&s)) return OCNEXT_GIC_STATE;
 if (r.owner != s.owner || r.generation != s.generation || r.sequence != s.next_sequence)
  return OCNEXT_GIC_STALE;
 irq_before = s.irq_level;
 if (r.el != 1) return OCNEXT_GIC_UNSUPPORTED;
 /* State validation bounds every subcounter by completed=next_sequence-1.
  * This quota therefore preflights epoch, completed and any selected subcounter. */
 if (s.next_sequence == UINT64_MAX) return OCNEXT_GIC_OVERFLOW;

 switch (r.operation) {
 case OCNEXT_GIC_LINE:
  if (r.width != 0 || (r.address != 27 && r.address != 30) || r.value > 1) return OCNEXT_GIC_ARGUMENT;
  {
   uint32_t b = UINT32_C(1) << id_to_idx((uint32_t)r.address);
   if (r.value) s.input_lines |= b; else s.input_lines &= ~b;
   s.level_updates++;
  }
  rc = OCNEXT_GIC_OK;
  break;
 case OCNEXT_GIC_MMIO_READ: case OCNEXT_GIC_ICC_READ:
  if (r.value != 0) return OCNEXT_GIC_ARGUMENT;
  rc = r.operation == OCNEXT_GIC_MMIO_READ ? do_mmio(&s, &r, 0, &value, &mask)
                                           : do_icc(&s, &r, 0, &value, &mask);
  break;
 case OCNEXT_GIC_MMIO_WRITE: case OCNEXT_GIC_ICC_WRITE:
  write = 1;
  rc = r.operation == OCNEXT_GIC_MMIO_WRITE ? do_mmio(&s, &r, write, &value, &mask)
                                            : do_icc(&s, &r, write, &value, &mask);
  break;
 case OCNEXT_GIC_OBSERVE: case OCNEXT_GIC_CLOSE:
  if (r.width != 0 || r.address != 0 || r.value != 0) return OCNEXT_GIC_ARGUMENT;
  if (r.operation == OCNEXT_GIC_CLOSE) {
   if (s.input_lines || s.sw_pending || s.active || s.enabled || s.depth ||
       s.dist_enable || s.cpu_enable || s.irq_level) return OCNEXT_GIC_STATE;
   s.phase = PHASE_CLOSED;
  }
  rc = OCNEXT_GIC_OK;
  break;
 default:
  return OCNEXT_GIC_ARGUMENT;
 }
 if (rc != OCNEXT_GIC_OK) return rc;

 compute(&s, &s.hppir, &s.irq_level);
 if (r.operation == OCNEXT_GIC_OBSERVE) { value = s.hppir; mask = UINT64_MAX; }

 s.next_sequence++;
 s.epoch++;
 s.completed++;

 zero_bytes(&e, sizeof e);
 e.abi_version = OCNEXT_GICV3_MODEL_ABI;
 e.bytes = sizeof(effect_t);
 e.operation = r.operation;
 e.sequence = r.sequence;
 e.next_sequence = s.next_sequence;
 e.epoch = s.epoch;
 e.value = value;
 e.value_known_mask = mask;
 e.irq_before = irq_before;
 e.irq_after = s.irq_level;
 e.hppir = s.hppir;
 e.depth = s.depth;

 copy_bytes(state, &s, sizeof s);
 copy_bytes(effect, &e, sizeof e);
 return OCNEXT_GIC_OK;
}
