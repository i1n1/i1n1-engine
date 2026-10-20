#ifndef OCNEXT_A64_PAC_INSTALL_H
#define OCNEXT_A64_PAC_INSTALL_H

#include "ocnext/a64.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Install all five 128-bit PAC keys (IA, IB, DA, DB, GA; Lo/Hi as the
 * APxxKeyLo/Hi_EL1 registers) into a running CPU, as a platform service such
 * as the INIT hypercall does. Unlike ocnext_a64_configure_pac_registers() this
 * is allowed after instructions have retired, but only at an instruction
 * boundary of a SYNC-profile CPU whose PAC profile is already PAUTH1/PAUTH2/
 * FPAC (so no feature is ever advertised by installing keys), with no latched
 * fault and not halted. All ten halves become known and write_epoch advances
 * by one, exactly as ten guest key-register writes would have left the bank.
 * Returns 0, or -1 with the CPU byte-identical: null/misaligned/overlapping
 * arguments, wrong profile, halted/faulted CPU, or write_epoch overflow.
 * The key values are caller data; nothing is derived or defaulted here. */
int ocnext_a64_install_pac_keys(struct ocnext_a64_cpu *cpu,
                                const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT]);

#ifdef __cplusplus
}
#endif
#endif
