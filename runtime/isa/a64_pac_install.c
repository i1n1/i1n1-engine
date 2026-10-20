/* Runtime installation of the five PAC keys into a running CPU (see header).
 * Kept apart from a64.c so the interpreter's dispatch stays untouched. */
#include "ocnext/a64_pac_install.h"
#include <stdint.h>

int ocnext_a64_install_pac_keys(struct ocnext_a64_cpu *cpu,
                                const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT])
{
    uintptr_t a = (uintptr_t)cpu, b = (uintptr_t)keys;
    unsigned i;
    if (!cpu || !keys || a % _Alignof(struct ocnext_a64_cpu) ||
        b % _Alignof(struct ocnext_pac_key) ||
        sizeof(*cpu) > UINTPTR_MAX - a ||
        OCNEXT_PAC_KEY_COUNT * sizeof(keys[0]) > UINTPTR_MAX - b ||
        (a < b + OCNEXT_PAC_KEY_COUNT * sizeof(keys[0]) && b < a + sizeof(*cpu)))
        return -1;
    if (cpu->system.profile != OCNEXT_A64_SYSTEM_ARMV8_EL1_SYNC || cpu->halted ||
        cpu->fault.code != OCNEXT_A64_FAULT_NONE ||
        cpu->pac.abi_version != OCNEXT_A64_PAC_REGISTERS_ABI_VERSION ||
        cpu->pac.pointer_profile < OCNEXT_A64_PAC_PAUTH2 ||
        cpu->pac.pointer_profile > OCNEXT_A64_PAC_PAUTH1 ||
        !cpu->pac.owner_id || cpu->pac.write_epoch == UINT64_MAX)
        return -1;
    for (i = 0; i < OCNEXT_PAC_KEY_COUNT; ++i) cpu->pac.keys[i] = keys[i];
    cpu->pac.half_known_mask = OCNEXT_A64_PAC_HALF_KNOWN_ALL;
    ++cpu->pac.write_epoch;
    return 0;
}
