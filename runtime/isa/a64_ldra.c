/* Authored address planner from Arm DDI0487H.a C6.2.169/C6-1560..1561.
 * Standalone numeric planner; CPU owns authentication/SP/read/retirement. */
#include "ocnext/a64_ldra.h"
#include <stddef.h>
#include <stdint.h>
_Static_assert(sizeof(struct ocnext_a64_ldra_request)==32,"request32");
_Static_assert(_Alignof(struct ocnext_a64_ldra_request)==8,"requestalign8");
_Static_assert(offsetof(struct ocnext_a64_ldra_request,opcode)==8,"opcode8");
_Static_assert(offsetof(struct ocnext_a64_ldra_request,reserved)==24,"requestreserved24");
_Static_assert(sizeof(struct ocnext_a64_ldra_effect)==32,"effect32");
_Static_assert(_Alignof(struct ocnext_a64_ldra_effect)==8,"effectalign8");
_Static_assert(offsetof(struct ocnext_a64_ldra_effect,key_index)==24,"keyindex24");

static int span(const void *p,uintptr_t *begin,uintptr_t *end)
{
    uintptr_t n=(uintptr_t)p;
    if(!p||(n&7u)||n>UINTPTR_MAX-31u)return 0;
    *begin=n;*end=n+31u;return 1;
}

int ocnext_a64_ldra_decode(uint32_t opcode)
{
    /* This allocation predicate advertises no PAuth feature. Outside fixed
     * bits stay unsupported, never blanket guest UNDEFINED or NOP. */
    return (opcode&UINT32_C(0xff200400))==UINT32_C(0xf8200400);
}

enum ocnext_a64_ldra_status ocnext_a64_ldra_prepare(
    const struct ocnext_a64_ldra_request *request,
    struct ocnext_a64_ldra_effect *effect)
{
    uintptr_t rb,re,eb,ee;
    unsigned rn,rt,wback,encoded,i;
    uint64_t offset,address;
    struct ocnext_a64_ldra_effect staged;
    if(!span(request,&rb,&re)||!span(effect,&eb,&ee)||(rb<=ee&&eb<=re))
        return OCNEXT_A64_LDRA_ARGUMENT;
    if(request->abi_version!=OCNEXT_A64_LDRA_ABI||request->reserved||
       (request->known_mask&~OCNEXT_A64_LDRA_BASE_KNOWN))
        return OCNEXT_A64_LDRA_ARGUMENT;
    if(!ocnext_a64_ldra_decode(request->opcode))return OCNEXT_A64_LDRA_UNSUPPORTED;
    rn=(request->opcode>>5)&31u;rt=request->opcode&31u;
    wback=(request->opcode>>11)&1u;
    /* Architecturally constrained-UNPREDICTABLE; no one permitted hardware
     * choice is guessed by this bounded model. This is not unallocated. */
    if(wback&&rn==rt&&rn!=31u)return OCNEXT_A64_LDRA_UNSUPPORTED;
    if(request->address_add_profile!=OCNEXT_A64_LDRA_ADDRESS_NORMAL_BASE64_NO_MTE||
       !(request->known_mask&OCNEXT_A64_LDRA_BASE_KNOWN))
        return OCNEXT_A64_LDRA_UNSUPPORTED;
    encoded=((request->opcode>>12)&511u)|((request->opcode>>13)&512u);
    /* signed10 multiplied by8, represented entirely as unsigned64. */
    offset=(uint64_t)encoded<<3;
    if(encoded&512u)offset|=UINT64_MAX<<13;
    address=request->selected_base+offset;
    staged.access_address=address;
    staged.writeback_value=wback?address:0;
    staged.abi_version=OCNEXT_A64_LDRA_ABI;
    staged.target_register=(uint8_t)rt;staged.base_register=(uint8_t)rn;
    staged.writeback=(uint8_t)wback;staged.access_bytes=8;
    staged.key_index=2u+((request->opcode>>23)&1u);staged.reserved=0;
    for(i=0;i<sizeof(staged);++i)((uint8_t*)effect)[i]=((const uint8_t*)&staged)[i];
    return OCNEXT_A64_LDRA_OK;
}
