#include "ocnext/mmu.h"

#define BIT(n) (UINT64_C(1) << (n))
#define PA48 UINT64_C(0x0000ffffffffffff)
#define DESC_PA UINT64_C(0x0000fffffffff000)
#define TCR_SUPPORTED OCNEXT_A64_TCR_SUPPORTED_MASK
/* Endianness, architectural alignment checking, EPAN and active MTE controls
 * require semantics outside this base RAM provider. Never silently enable. */
#define SCTLR_UNSUPPORTED (BIT(1)|BIT(24)|BIT(25)|BIT(57)|(UINT64_C(0x3f)<<38))

static void clear(void *out, size_t size)
{
    uint8_t *p = out;
    while (size--) *p++ = 0;
}

static uint64_t lowmask(unsigned bits)
{
    return (UINT64_C(1) << bits) - 1;
}

static unsigned pa_width(uint64_t tcr)
{
    const unsigned widths[6] = {32,36,40,42,44,48};
    unsigned ips = (unsigned)((tcr >> 32) & 7);
    return ips < 6 ? widths[ips] : 0;
}

static unsigned granule(uint64_t tcr, unsigned region)
{
    unsigned tg = (unsigned)((tcr >> (region ? 30 : 14)) & 3);
    if (!region) return tg == 0 ? 12 : tg == 1 ? 16 : tg == 2 ? 14 : 0;
    return tg == 1 ? 14 : tg == 2 ? 12 : tg == 3 ? 16 : 0;
}

enum ocnext_mmu_result ocnext_mmu_validate(const struct ocnext_mmu_config *c)
{
    unsigned i, region;
    if (!c || c->current_el > 1 || c->pan > 1) return OCNEXT_MMU_ARGUMENT;
    for (i=0; i<5; ++i) if (c->reserved[i]) return OCNEXT_MMU_ARGUMENT;
    if (c->allow_device > 1) return OCNEXT_MMU_ARGUMENT;
    if (c->sctlr_el1 & SCTLR_UNSUPPORTED) return OCNEXT_MMU_UNSUPPORTED;
    if (!(c->sctlr_el1 & 1)) return OCNEXT_MMU_OK;
    if ((c->tcr_el1 & ~TCR_SUPPORTED) || !pa_width(c->tcr_el1)) return OCNEXT_MMU_UNSUPPORTED;
    /* Baseline no-TTST minimum VA is 25 bits. Cacheability/shareability are
     * observed, not used to emulate caches. Reserved shareability 01 refused. */
    for (region=0; region<2; ++region) {
        unsigned sz = (unsigned)((c->tcr_el1 >> (region ? 16 : 0)) & 63);
        unsigned sh = (unsigned)((c->tcr_el1 >> (region ? 28 : 12)) & 3);
        if (sz < 16 || sz > 39 || !granule(c->tcr_el1,region) || sh == 1)
            return OCNEXT_MMU_UNSUPPORTED;
    }
    return OCNEXT_MMU_OK;
}

static enum ocnext_mmu_result fail(struct ocnext_mmu *m, enum ocnext_mmu_fault_kind kind,
             uint64_t va, enum ocnext_a64_access access, unsigned level, unsigned region,
             uint64_t descriptor_address)
{
    unsigned fsc=0, ec;
    m->fault.kind=kind; m->fault.access=access; m->fault.va=va;
    m->fault.level=(uint8_t)level; m->fault.ttbr_region=(uint8_t)region;
    m->fault.descriptor_address=descriptor_address;
    if (kind == OCNEXT_MMU_FAULT_UNSUPPORTED || kind == OCNEXT_MMU_FAULT_ARGUMENT) {
        m->fault.syndrome_valid=0; m->fault.far_valid=0; m->fault.esr_el1=0;
        return kind == OCNEXT_MMU_FAULT_UNSUPPORTED ? OCNEXT_MMU_UNSUPPORTED : OCNEXT_MMU_ARGUMENT;
    }
    switch (kind) {
    case OCNEXT_MMU_FAULT_ADDRESS_SIZE: fsc=level; break;
    case OCNEXT_MMU_FAULT_TRANSLATION: fsc=4+level; break;
    case OCNEXT_MMU_FAULT_ACCESS_FLAG: fsc=8+level; break;
    case OCNEXT_MMU_FAULT_PERMISSION: fsc=12+level; break;
    case OCNEXT_MMU_FAULT_TABLE_BUS: fsc=20+level; break;
    case OCNEXT_MMU_FAULT_DATA_BUS: fsc=16; break;
    default: return OCNEXT_MMU_ARGUMENT;
    }
    ec = access == OCNEXT_A64_ACCESS_FETCH ? (m->config.current_el ? 0x21u : 0x20u) :
                                           (m->config.current_el ? 0x25u : 0x24u);
    m->fault.esr_el1=(ec << 26) | UINT32_C(0x02000000) | fsc;
    if (access == OCNEXT_A64_ACCESS_WRITE) m->fault.esr_el1 |= UINT32_C(0x40);
    m->fault.syndrome_valid=1; m->fault.far_valid=1;
    return OCNEXT_MMU_ABORT;
}

static uint64_t u64(const uint8_t *p)
{
    uint64_t n=0;
    unsigned i;
    for (i=0; i<8; ++i) n |= (uint64_t)p[i] << (i*8);
    return n;
}

enum ocnext_mmu_result ocnext_mmu_translate(struct ocnext_mmu *m, uint64_t va,
                        enum ocnext_a64_access access, struct ocnext_mmu_translation *out)
{
    enum ocnext_mmu_result valid;
    uint64_t addr, table, ttbr, d=0, daddr=0, base, leafsize;
    unsigned region, gs, stride, bits, level, start, index_bits, pa_bits;
    int no_user=0, no_write=0, pxn=0, uxn=0;
    if (!m) return OCNEXT_MMU_ARGUMENT;
    clear(&m->fault,sizeof(m->fault));
    if (!out || (unsigned)access > (unsigned)OCNEXT_A64_ACCESS_WRITE)
        return fail(m,OCNEXT_MMU_FAULT_ARGUMENT,va,access,0,0,0);
    clear(out,sizeof(*out));
    valid=ocnext_mmu_validate(&m->config);
    if (valid != OCNEXT_MMU_OK) return fail(m,valid == OCNEXT_MMU_ARGUMENT ?
        OCNEXT_MMU_FAULT_ARGUMENT : OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,0,0,0);
    /* Address tagging controls also apply with M=0. Keep the incoming VA for
     * syndrome/FAR diagnostics. TBID affects only instruction fetch, not data
     * or AT/cache-maintenance address translations. */
    region=(unsigned)((va >> 55) & 1);
    addr=va;
    if ((m->config.tcr_el1 & BIT(region ? 38 : 37)) &&
        (access != OCNEXT_A64_ACCESS_FETCH ||
         !(m->config.tcr_el1 & BIT(region ? 52 : 51)))) {
        addr &= UINT64_C(0x00ffffffffffffff);
        if (region) addr |= UINT64_C(0xff00000000000000);
    }
    if (!(m->config.sctlr_el1 & 1)) {
        if (addr > PA48) return fail(m,OCNEXT_MMU_FAULT_ADDRESS_SIZE,va,access,0,region,0);
        out->pa=addr; out->mapping_bytes=4096; out->granule_shift=12;
        out->writable=1; out->user_accessible=1; out->mair_attribute=0x44;
        return OCNEXT_MMU_OK;
    }
    /* Bit55 chooses the TTBR range even when the top byte is a tag. */
    bits=64-(unsigned)((m->config.tcr_el1 >> (region ? 16 : 0)) & 63);
    if ((!region && (addr & ~lowmask(bits))) ||
        (region && (addr | lowmask(bits)) != UINT64_MAX))
        return fail(m,OCNEXT_MMU_FAULT_TRANSLATION,va,access,0,region,0);
    gs=granule(m->config.tcr_el1,region); stride=gs-3;
    start=gs == 16 ? 1 : 0;
    while (start < 3 && bits <= gs+stride*(3-start)) ++start;
    index_bits=bits-(gs+stride*(3-start));
    ttbr=region ? m->config.ttbr1_el1 : m->config.ttbr0_el1;
    table=ttbr & PA48 & ~UINT64_C(1); /* CnP recorded only; no shared TLB. */
    pa_bits=pa_width(m->config.tcr_el1);
    if (table & ~lowmask(pa_bits)) return fail(m,OCNEXT_MMU_FAULT_ADDRESS_SIZE,va,access,0,region,0);
    if (table & lowmask(index_bits+3)) return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,start,region,0);
    if (m->config.tcr_el1 & BIT(region ? 23 : 7))
        return fail(m,OCNEXT_MMU_FAULT_TRANSLATION,va,access,start,region,0);
    if (!m->bus.read) return fail(m,OCNEXT_MMU_FAULT_ARGUMENT,va,access,start,region,0);
    for (level=start; level<=3; ++level) {
        uint8_t bytes[8];
        unsigned shift=gs+stride*(3-level);
        uint64_t index=(addr >> shift) & lowmask(level == start ? index_bits : stride);
        daddr=table+index*8;
        if (daddr > lowmask(pa_bits)-7) return fail(m,OCNEXT_MMU_FAULT_ADDRESS_SIZE,va,access,level,region,daddr);
        if (m->bus.read(m->bus.context,daddr,bytes,8))
            return fail(m,OCNEXT_MMU_FAULT_TABLE_BUS,va,access,level,region,daddr);
        d=u64(bytes);
        if (!(d & 1)) return fail(m,OCNEXT_MMU_FAULT_TRANSLATION,va,access,level,region,daddr);
        if (d & (BIT(48)|BIT(49)|BIT(50))) return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,level,region,daddr);
        base=d & DESC_PA;
        if (base & ~lowmask(pa_bits)) return fail(m,OCNEXT_MMU_FAULT_ADDRESS_SIZE,va,access,level,region,daddr);
        if (level < 3 && (d & 3) == 3) {
            if (base & lowmask(gs)) return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,level,region,daddr);
            no_user |= !!(d & BIT(61)); no_write |= !!(d & BIT(62));
            pxn |= !!(d & BIT(59)); uxn |= !!(d & BIT(60));
            table=base; continue;
        }
        if ((level == 3 && (d & 3) != 3) || (level < 3 && (d & 3) != 1) ||
            level == 0 || (level == 1 && gs != 12))
            return fail(m,OCNEXT_MMU_FAULT_TRANSLATION,va,access,level,region,daddr);
        if (d & BIT(51)) return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,level,region,daddr);
        leafsize=BIT(shift);
        if (base & (leafsize-1)) return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,level,region,daddr);
        if (!(d & BIT(10))) return fail(m,OCNEXT_MMU_FAULT_ACCESS_FLAG,va,access,level,region,daddr);
        out->writable=(uint8_t)(!no_write && !(d & BIT(7)));
        out->user_accessible=(uint8_t)(!no_user && !!(d & BIT(6)));
        out->pxn=(uint8_t)(pxn || !!(d & BIT(53)));
        out->uxn=(uint8_t)(uxn || !!(d & BIT(54)));
        out->attr_index=(uint8_t)((d >> 2)&7);
        out->mair_attribute=(uint8_t)(m->config.mair_el1 >> (out->attr_index*8));
        out->device=(uint8_t)((out->mair_attribute & 0xf0) == 0);
        out->shareability=(uint8_t)((d >> 8)&3); out->nonglobal=(uint8_t)!!(d & BIT(11));
        if ((out->device && (out->mair_attribute & 3)) ||
            (!out->device && !(out->mair_attribute & 15)) || out->shareability == 1)
            return fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va,access,level,region,daddr);
        if ((!m->config.current_el && !out->user_accessible && access != OCNEXT_A64_ACCESS_FETCH) ||
            (access == OCNEXT_A64_ACCESS_WRITE && !out->writable) ||
            (m->config.current_el && m->config.pan && out->user_accessible && access != OCNEXT_A64_ACCESS_FETCH) ||
            (access == OCNEXT_A64_ACCESS_FETCH && (out->device ||
                (m->config.current_el && out->user_accessible && out->writable) ||
                (m->config.current_el ? out->pxn : out->uxn) ||
                ((m->config.sctlr_el1 & BIT(19)) && out->writable &&
                 (m->config.current_el || out->user_accessible)))))
            return fail(m,OCNEXT_MMU_FAULT_PERMISSION,va,access,level,region,daddr);
        out->pa=base+(addr & (leafsize-1)); out->mapping_bytes=leafsize;
        out->level=(uint8_t)level; out->granule_shift=(uint8_t)gs;
        ttbr=m->config.tcr_el1 & BIT(22) ? m->config.ttbr1_el1 : m->config.ttbr0_el1;
        out->asid=(uint16_t)((ttbr >> 48) & (m->config.tcr_el1 & BIT(36) ? 0xffffu : 0xffu));
        return OCNEXT_MMU_OK;
    }
    return fail(m,OCNEXT_MMU_FAULT_TRANSLATION,va,access,3,region,daddr);
}

static int preflight(struct ocnext_mmu *m, uint64_t va, size_t size,
                    enum ocnext_a64_access access, struct ocnext_mmu_span *spans, size_t *count)
{
    size_t offset=0;
    if (!m) return -1;
    clear(&m->fault,sizeof(m->fault)); *count=0;
    if (!size || size > OCNEXT_MMU_MAX_TRANSFER || va > UINT64_MAX-(size-1) || !m->bus.probe) {
        fail(m,OCNEXT_MMU_FAULT_ARGUMENT,va,access,0,0,0); return -1;
    }
    while (offset < size) {
        struct ocnext_mmu_translation t;
        uint64_t remaining;
        size_t take;
        if (*count >= OCNEXT_MMU_MAX_SPANS || ocnext_mmu_translate(m,va+offset,access,&t) != OCNEXT_MMU_OK) return -1;
        remaining=BIT(t.granule_shift)-(t.pa & lowmask(t.granule_shift));
        take=remaining < size-offset ? (size_t)remaining : size-offset;
        if (t.device && !m->config.allow_device) { fail(m,OCNEXT_MMU_FAULT_UNSUPPORTED,va+offset,access,t.level,0,0); return -1; }
        if (t.pa > UINT64_MAX-(take-1) || m->bus.probe(m->bus.context,t.pa,take,access)) {
            fail(m,OCNEXT_MMU_FAULT_DATA_BUS,va+offset,access,t.level,0,0); return -1;
        }
        spans[*count].pa=t.pa; spans[*count].offset=offset; spans[*count].bytes=take;
        ++*count; offset+=take;
    }
    return 0;
}

int ocnext_mmu_read(void *context, uint64_t va, uint8_t *destination, size_t size,
                    enum ocnext_a64_access access)
{
    struct ocnext_mmu *m=context;
    struct ocnext_mmu_span spans[OCNEXT_MMU_MAX_SPANS];
    uint8_t temporary[OCNEXT_MMU_MAX_TRANSFER];
    size_t count,i,j;
    if (!destination || access == OCNEXT_A64_ACCESS_WRITE ||
        preflight(m,va,size,access,spans,&count)) return -1;
    if (!m->bus.read) { fail(m,OCNEXT_MMU_FAULT_ARGUMENT,va,access,0,0,0); return -1; }
    for (i=0; i<count; ++i) if (m->bus.read(m->bus.context,spans[i].pa,temporary+spans[i].offset,spans[i].bytes)) {
        fail(m,OCNEXT_MMU_FAULT_DATA_BUS,va+spans[i].offset,access,0,0,0); return -1;
    }
    for (j=0; j<size; ++j) destination[j]=temporary[j];
    return 0;
}

int ocnext_mmu_write(void *context, uint64_t va, const uint8_t *source, size_t size)
{
    struct ocnext_mmu *m=context;
    struct ocnext_mmu_span spans[OCNEXT_MMU_MAX_SPANS];
    size_t count;
    if (!source || preflight(m,va,size,OCNEXT_A64_ACCESS_WRITE,spans,&count)) return -1;
    if (!m->bus.writev) { fail(m,OCNEXT_MMU_FAULT_ARGUMENT,va,OCNEXT_A64_ACCESS_WRITE,0,0,0); return -1; }
    if (m->bus.writev(m->bus.context,spans,count,source,size)) {
        fail(m,OCNEXT_MMU_FAULT_DATA_BUS,va,OCNEXT_A64_ACCESS_WRITE,0,0,0); return -1;
    }
    return 0;
}

const struct ocnext_mmu_fault *ocnext_mmu_last_fault(const struct ocnext_mmu *m)
{
    return m ? &m->fault : 0;
}
