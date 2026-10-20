#ifndef OCNEXT_A64_SYSREG_H
#define OCNEXT_A64_SYSREG_H
/* AArch64 system-register model for the bounded A64 interpreter.
 *
 * Two parts:
 *  1. An Apple-profile SCTLR_EL1 write policy (per-bit table, below).
 *  2. A sysreg provider (struct ocnext_a64_sysreg_model) that plugs into
 *     struct ocnext_a64_memory.sysreg and serves MDSCR/MIDR/MPIDR/ACTLR/
 *     CNTKCTL, counters and timers, CONTEXTIDR, cache-ID, ID_AA64 feature
 *     registers, ISR and ICC_ accesses.
 *
 * Ground rules (project rule 1):
 *  - Every ID/identity register value comes from the explicit
 *    struct ocnext_a64_sysreg_profile; nothing is read from the host.
 *  - A register or bit whose semantics are not modeled stops
 *    deterministically (OCNEXT_A64_SYSREG_UNSUPPORTED) and records a reason
 *    retrievable with ocnext_a64_sysreg_stop_describe(). No RAZ/WI fallbacks
 *    except where the architecture itself defines RAZ/WI/RAO (documented at
 *    each site in a64_sysreg.c).
 *  - The profile is SYNTHETIC: it is not read from Apple silicon. See
 *    docs/findings/sysreg-apple-profile.md.
 */
#include <stddef.h>
#include <stdint.h>
#include "ocnext/a64.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- SCTLR_EL1, Apple profile -------------------------------------------
 * Bit classes (numbering per Arm ARM DDI0487 SCTLR_EL1; classification is
 * derived from the feature set in ocnext_a64_sysreg_profile_apple_v1 and from
 * the value XNU 26A434 writes at the first MMU enable, 0x12001000fc14793d):
 *
 *  EFFECTIVE   M0 SA3 SA0(4) UMA9 WXN19, EnIA31 EnIB30 EnDA27 EnDB13
 *              (PAC bits only when a PAC pointer profile is configured)
 *  STATE_ONLY  C2 nAA6 EOS11 I12 DZE14 UCT15 nTWI16 nTWE18 TSCXT20 EIS22
 *              SPAN23 UCI26 DSSBS44 EPAN57: stored and read back; the effect
 *              they control (caches, PAN, EL0 traps of unsupported
 *              instructions, ...) is either not modeled or reached only via
 *              instructions that already stop.
 *  UNMODELED   A1 (alignment-fault checking): writing 1 stops.
 *  RES1        28 nTLSMD, 29 LSMAOE (FEAT_LSMAOC absent): must be written 1.
 *  WRITE_IGNORED_OBSERVED  5 CP15BEN, 8 SED, 60: RES0 for this profile
 *              (AArch32 EL0 absent, no SME). XNU writes 1 to them. RES0 reads
 *              as 0 and a write is ignored, so they are accepted and cleared
 *              in the stored value. This set is exactly the bits observed in
 *              the boot write; any other RES0 bit written 1 stops.
 *  RES0        everything else: writing 1 stops.
 */
#define OCNEXT_A64_SCTLR_APPLE_EFFECTIVE UINT64_C(0x80219)
#define OCNEXT_A64_SCTLR_APPLE_PAC_BITS OCNEXT_A64_SCTLR_PAC_ENABLE_MASK
#define OCNEXT_A64_SCTLR_APPLE_STATE_ONLY UINT64_C(0x0200100004d5d844)
#define OCNEXT_A64_SCTLR_APPLE_UNMODELED UINT64_C(0x2)
#define OCNEXT_A64_SCTLR_APPLE_RES1 UINT64_C(0x30000000)
#define OCNEXT_A64_SCTLR_APPLE_WRITE_IGNORED UINT64_C(0x1000000000000120)

enum ocnext_a64_sctlr_result {
    OCNEXT_A64_SCTLR_OK = 0,
    OCNEXT_A64_SCTLR_RES1_CLEAR = 1,   /* a RES1 bit written 0 */
    OCNEXT_A64_SCTLR_RES0_SET = 2,     /* a RES0 bit (not write-ignored) written 1 */
    OCNEXT_A64_SCTLR_UNMODELED_SET = 3,/* A (alignment check) written 1 */
    OCNEXT_A64_SCTLR_PAC_NOT_CONFIGURED = 4 /* EnIx/EnDx written 1 without a PAC profile */
};
/* Validates `value` against the Apple policy. On OK stores the canonical
 * register value (RES1 set, write-ignored bits cleared) in *stored. On any
 * other result *stored is untouched; *bad_mask (if non-NULL) receives the
 * offending bits and *reason (if non-NULL) a static string. */
enum ocnext_a64_sctlr_result ocnext_a64_sctlr_apple_write(uint64_t value, unsigned pac_profile,
        uint64_t *stored, uint64_t *bad_mask, const char **reason);

/* ---- Identity profile ---------------------------------------------------- */
#define OCNEXT_SYSREG_CACHE_LEVELS 7u
struct ocnext_a64_sysreg_profile {
    const char *name;
    uint64_t midr, mpidr;
    uint64_t id_aa64pfr0, id_aa64pfr1, id_aa64dfr0, id_aa64dfr1, id_aa64afr0, id_aa64afr1;
    uint64_t id_aa64isar0, id_aa64isar1, id_aa64isar2;
    uint64_t id_aa64mmfr0, id_aa64mmfr1, id_aa64mmfr2;
    uint64_t clidr;
    uint32_t ccsidr[OCNEXT_SYSREG_CACHE_LEVELS][2]; /* [level-1][InD] */
    uint64_t cntfrq;
    /* ACTLR_EL1 bits whose behaviour is modeled. Apple's ACTLR_EL1 is
     * IMPLEMENTATION DEFINED and undocumented; default 0 => any nonzero
     * write stops. */
    uint64_t actlr_el1_modeled_mask;
};
extern const struct ocnext_a64_sysreg_profile ocnext_a64_sysreg_profile_apple_v1;

/* ---- Providers the host binds -------------------------------------------- */
struct ocnext_a64_sysreg_ops {
    /* Physical count (CNTPCT_EL0). Return 0 on success. NULL => counter and
     * timer registers stop ("no counter source"). */
    int (*counter)(void *ctx, uint64_t *physical_count);
    /* Level of timer output: which 0 = physical (PPI 30), 1 = virtual (PPI 27). */
    void (*timer_irq)(void *ctx, unsigned which, int level);
    /* ISR_EL1 pending bits: returns A(bit8)|I(bit7)|F(bit6). NULL => ISR stops. */
    int (*isr)(void *ctx, uint64_t *isr);
    /* GICv3 CPU interface. NULL members make the register stop. */
    int (*icc_ack)(void *ctx, uint32_t *intid);
    int (*icc_eoi)(void *ctx, uint32_t intid);          /* nonzero: not deliverable */
    int (*icc_get_pmr)(void *ctx, uint8_t *pmr);
    int (*icc_set_pmr)(void *ctx, uint8_t pmr);
    int (*icc_get_igrpen1)(void *ctx, int *enable);
    int (*icc_set_igrpen1)(void *ctx, int enable);
};

struct ocnext_a64_sysreg_timer { uint64_t cval; uint32_t ctl; int level; };

struct ocnext_a64_sysreg_model {
    struct ocnext_a64_sysreg_profile profile;
    const struct ocnext_a64_sysreg_ops *ops;
    void *ctx;
    uint64_t mdscr_el1, actlr_el1, cntkctl_el1, contextidr_el1, cntvoff;
    uint32_t csselr_el1;
    uint32_t icc_ctlr_cbpr;
    struct ocnext_a64_sysreg_timer timer[2]; /* [0] physical, [1] virtual */
    /* Last non-OK result. */
    uint16_t stop_key;
    uint8_t stop_valid;
    const char *stop_reason;
};

/* Validates the profile (RES1/RES0 identity bits, cache table consistent with
 * CLIDR) and resets architectural-UNKNOWN state to the documented model reset
 * (all zero). Returns 0 or -1. */
int ocnext_a64_sysreg_model_init(struct ocnext_a64_sysreg_model *m,
        const struct ocnext_a64_sysreg_profile *profile,
        const struct ocnext_a64_sysreg_ops *ops, void *ctx);
/* Provider for struct ocnext_a64_memory: pass `.sysreg_context = model`. */
enum ocnext_a64_sysreg_result ocnext_a64_sysreg_provide(void *model,
        const struct ocnext_a64_sysreg_request *request, uint64_t *read_value);
/* Re-evaluate timer outputs (call when the counter advanced). Returns 0 or
 * nonzero if the counter source failed. */
int ocnext_a64_sysreg_poll(struct ocnext_a64_sysreg_model *m);
/* Feature bank for ocnext_a64_configure_feature_registers derived from the
 * profile's ID_AA64MMFR0_EL1 (-1 if it is not the supported software profile). */
int ocnext_a64_sysreg_feature_bank(const struct ocnext_a64_sysreg_model *m,
        struct ocnext_a64_feature_registers *bank);
/* Human-readable "s3_4_c15_c5_0: reason" of the last stop; returns length. */
size_t ocnext_a64_sysreg_stop_describe(const struct ocnext_a64_sysreg_model *m, char *buffer, size_t size);
/* Diagnostic name for a request key, or NULL if unknown to the model. */
const char *ocnext_a64_sysreg_name(uint16_t key);

#ifdef __cplusplus
}
#endif
#endif
