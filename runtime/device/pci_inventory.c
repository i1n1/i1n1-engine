#include "ocnext/pci_inventory.h"
#include "ocnext/sha256.h"

/* Independent codec of public PCI field definitions, no upstream source
 * imported. Reference pins and deliberate conservative policies are recorded
 * in implementation-pci-inventory.md. All guest/device addresses stay integers. */
static void pci_zero(void *v, size_t n) {
    uint8_t *p = (uint8_t *)v;
    while (n--) *p++ = 0;
}
static void pci_copy(void *v, const void *s, size_t n) {
    uint8_t *p = (uint8_t *)v; const uint8_t *q = (const uint8_t *)s;
    while (n--) *p++ = *q++;
}
static uint16_t pci_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t pci_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int pci_span(const void *v, size_t n, size_t alignment) {
    uintptr_t a = (uintptr_t)v;
    return v && !(a % alignment) && n <= UINTPTR_MAX - a;
}
static int pci_overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x < y + bn && y < x + an;
}
static int pci_identity(const struct ocnext_pci_identity *i) {
    return i->abi == OCNEXT_PCI_INVENTORY_ABI && i->source_id && i->capture_id &&
        i->domain_id && i->owner_id && i->session_id && i->instance_id &&
        i->generation && i->device <= 31 && i->function <= 7 && !i->reserved &&
        i->source_kind >= OCNEXT_PCI_SOURCE_CAPTURED &&
        i->source_kind <= OCNEXT_PCI_SOURCE_QEMU;
}
static int pci_claim(struct ocnext_pci_workspace *w, unsigned off, unsigned n,
                     unsigned limit) {
    unsigned i;
    if (!n || off > limit || n > limit - off) return 0;
    for (i = off; i < off + n; i++)
        if (w->occupied[i >> 3] & (1u << (i & 7))) return 0;
    for (i = off; i < off + n; i++)
        w->occupied[i >> 3] |= (uint8_t)(1u << (i & 7));
    return 1;
}
static enum ocnext_pci_result pci_bars(struct ocnext_pci_inventory *o,
                                      const uint8_t *p) {
    unsigned i;
    for (i = 0; i < o->bar_slots; i++) {
        struct ocnext_pci_bar *b = &o->bars[i];
        uint32_t raw = pci_u32(p + 0x10 + i * 4);
        unsigned type = (raw >> 1) & 3;
        b->raw_low = raw; b->index = (uint8_t)i; b->slots = 1;
        b->known_mask = OCNEXT_PCI_BAR_K_RAW | OCNEXT_PCI_BAR_K_BASE |
                        OCNEXT_PCI_BAR_K_KIND;
        if (raw & 1) {
            if (raw & 2) return OCNEXT_PCI_INVALID_BAR;
            b->kind = OCNEXT_PCI_BAR_IO; b->base = raw & UINT32_C(0xfffffffc);
        } else {
            b->prefetch = (uint8_t)((raw >> 3) & 1);
            b->base = raw & UINT32_C(0xfffffff0);
            if (type == 3) return OCNEXT_PCI_INVALID_BAR;
            if (type == 0) b->kind = OCNEXT_PCI_BAR_MEMORY32;
            if (type == 1) {
                b->kind = OCNEXT_PCI_BAR_MEMORY_BELOW_1M;
                if (b->base >= UINT64_C(0x100000)) return OCNEXT_PCI_INVALID_BAR;
            }
            if (type == 2) {
                struct ocnext_pci_bar *high;
                if (i + 1 >= o->bar_slots) return OCNEXT_PCI_INVALID_BAR;
                b->kind = OCNEXT_PCI_BAR_MEMORY64; b->slots = 2;
                b->raw_high = pci_u32(p + 0x10 + (i + 1) * 4);
                b->base |= (uint64_t)b->raw_high << 32;
                high = &o->bars[++i];
                high->raw_low = b->raw_high; high->index = (uint8_t)i;
                high->kind = OCNEXT_PCI_BAR_CONTINUATION;
                high->known_mask = OCNEXT_PCI_BAR_K_RAW | OCNEXT_PCI_BAR_K_KIND;
            }
        }
    }
    return OCNEXT_PCI_OK;
}
static int pci_singleton(unsigned id, int extended) {
    return extended ? (id == 0x0d || id == 0x0f || id == 0x1b) :
        (id == 5 || id == 0x10 || id == 0x11);
}
static int pci_duplicate(const struct ocnext_pci_inventory *o,
                         unsigned count, unsigned id, unsigned list) {
    unsigned i;
    if (!pci_singleton(id, list == OCNEXT_PCI_CAP_EXTENDED)) return 0;
    for (i = 0; i < count; i++)
        if (o->capabilities[i].id == id && o->capabilities[i].list == list) return 1;
    return 0;
}
static enum ocnext_pci_result pci_standard_body(
    const uint8_t *p, struct ocnext_pci_inventory *o,
    struct ocnext_pci_capability *c) {
    unsigned n = 2, off = c->offset;
    uint16_t ctrl;
    if (c->id == 9) {
        if (off > 253) return OCNEXT_PCI_INVALID_CAPABILITY;
        n = p[off + 2];
        if (n < 3 || n > 256 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        c->values[0] = n;
        c->known_mask |= OCNEXT_PCI_CAP_K_FULL_LENGTH;
    } else if (c->id == 5) {
        unsigned bits64, mask, dataoff, maskoff, mmc, mme;
        if (off > 252) return OCNEXT_PCI_INVALID_CAPABILITY;
        ctrl = pci_u16(p + off + 2);
        bits64 = !!(ctrl & 0x80); mask = !!(ctrl & 0x100);
        mmc = (ctrl >> 1) & 7; mme = (ctrl >> 4) & 7;
        /* The bounded public-v6.12 profile covers MSI control bits0..8. */
        if ((ctrl & 0xfe00) || mmc > 5 || mme > mmc)
            return OCNEXT_PCI_INVALID_CAPABILITY;
        dataoff = bits64 ? 12 : 8; maskoff = bits64 ? 16 : 12;
        n = mask ? maskoff + 8 : dataoff + 2;
        if (n > 256 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        if (pci_u32(p + off + 4) & 3) return OCNEXT_PCI_INVALID_CAPABILITY;
        c->values[0] = ctrl; c->values[1] = pci_u32(p + off + 4);
        if (bits64) c->values[1] |= (uint64_t)pci_u32(p + off + 8) << 32;
        c->values[2] = pci_u16(p + off + dataoff);
        if (mask) c->values[3] = (uint64_t)pci_u32(p + off + maskoff) |
            ((uint64_t)pci_u32(p + off + maskoff + 4) << 32);
        c->known_mask |= OCNEXT_PCI_CAP_K_REGISTERS | OCNEXT_PCI_CAP_K_FULL_LENGTH;
    } else if (c->id == 0x11) {
        uint32_t table, pba; unsigned tb, pb, entries;
        n = 12;
        if (n > 256 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        ctrl = pci_u16(p + off + 2);
        if (ctrl & 0x3800) return OCNEXT_PCI_INVALID_CAPABILITY;
        table = pci_u32(p + off + 4); pba = pci_u32(p + off + 8);
        tb = table & 7; pb = pba & 7;
        if (tb >= o->bar_slots || pb >= o->bar_slots ||
            o->bars[tb].kind == OCNEXT_PCI_BAR_IO ||
            o->bars[pb].kind == OCNEXT_PCI_BAR_IO ||
            o->bars[tb].kind == OCNEXT_PCI_BAR_CONTINUATION ||
            o->bars[pb].kind == OCNEXT_PCI_BAR_CONTINUATION)
            return OCNEXT_PCI_INVALID_CAPABILITY;
        entries = (ctrl & 0x7ff) + 1;
        c->values[0] = ctrl; c->values[1] = table; c->values[2] = pba;
        c->values[3] = (uint64_t)(entries * 16) |
            ((uint64_t)(((entries + 63) / 64) * 8) << 32);
        c->known_mask |= OCNEXT_PCI_CAP_K_REGISTERS | OCNEXT_PCI_CAP_K_FULL_LENGTH |
                         OCNEXT_PCI_CAP_K_DERIVED;
    } else if (c->id == 0x10) {
        unsigned version, type;
        n = 4;
        if (n > 256 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        ctrl = pci_u16(p + off + 2); version = ctrl & 15; type = (ctrl >> 4) & 15;
        if (!version || (ctrl & 0xc000)) return OCNEXT_PCI_INVALID_CAPABILITY;
        c->version = (uint8_t)version; c->values[0] = ctrl;
        c->known_mask |= OCNEXT_PCI_CAP_K_REGISTERS;
        /* Decode only flags and the device block, never invent the full
         * optional link/slot/root block length from the next capability. */
        if ((version == 1 || version == 2) &&
            (type == 0 || type == 1 || (type >= 4 && type <= 9))) {
            n = 12;
            if (n > 256 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
            c->values[1] = pci_u32(p + off + 4);
            c->values[2] = pci_u16(p + off + 8);
            c->values[3] = pci_u16(p + off + 10);
        }
    }
    c->validated_bytes = (uint16_t)n;
    return OCNEXT_PCI_OK;
}
static enum ocnext_pci_result pci_extended_body(
    const uint8_t *p, struct ocnext_pci_capability *c) {
    unsigned off = c->offset, n = 4;
    if ((c->id == 0x0b || c->id == 0x23) && c->version == 1) {
        uint32_t h;
        unsigned minimum = c->id == 0x0b ? 8 : 12;
        if (minimum > 4096 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        h = pci_u32(p + off + 4); n = h >> 20;
        if (n < minimum || n > 4096 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        c->values[0] = h;
        if (minimum == 12) c->values[1] = pci_u32(p + off + 8);
        c->known_mask |= OCNEXT_PCI_CAP_K_REGISTERS | OCNEXT_PCI_CAP_K_FULL_LENGTH;
    } else if ((c->id == 0x0d || c->id == 0x0f || c->id == 0x1b) && c->version == 1) {
        uint16_t cap, ctrl;
        n = 8;
        if (n > 4096 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
        cap = pci_u16(p + off + 4); ctrl = pci_u16(p + off + 6);
        c->values[0] = cap; c->values[1] = ctrl;
        c->known_mask |= OCNEXT_PCI_CAP_K_REGISTERS | OCNEXT_PCI_CAP_K_FULL_LENGTH |
                         OCNEXT_PCI_CAP_K_DERIVED;
        if (c->id == 0x0d) {
            unsigned bits = p[off + 5] ? p[off + 5] : 256;
            if (cap & 0x20) n += (bits + 7) / 8;
            if (n > 4096 - off) return OCNEXT_PCI_INVALID_CAPABILITY;
            c->values[2] = (cap & 0x20) ? bits : 0;
        } else if (c->id == 0x0f) {
            c->values[2] = (cap & 31) ? (cap & 31) : 32;
            c->values[3] = (ctrl & 31) + 12;
        } else {
            c->values[2] = ((cap >> 8) & 31) + 1;
        }
        /* Raw extended registers preserve unimplemented/new fields. These
         * observed bits do not certify a usable or enabled isolation policy. */
    }
    c->validated_bytes = (uint16_t)n;
    return OCNEXT_PCI_OK;
}
static enum ocnext_pci_result pci_standard(
    struct ocnext_pci_workspace *w, const uint8_t *p) {
    struct ocnext_pci_inventory *o = &w->staged;
    unsigned off = p[0x34];
    o->known_mask |= OCNEXT_PCI_K_STD_CHAIN;
    if (!(o->status & 0x10)) return off ? OCNEXT_PCI_INVALID_CHAIN : OCNEXT_PCI_OK;
    while (off) {
        struct ocnext_pci_capability *c;
        enum ocnext_pci_result result;
        unsigned next, id, count = o->standard_count;
        if (off < 0x40 || off > 0xfc || (off & 3)) return OCNEXT_PCI_INVALID_CHAIN;
        if (count == OCNEXT_PCI_STD_CAP_MAX) return OCNEXT_PCI_CAP_LIMIT;
        id = p[off]; next = p[off + 1];
        if (!id || id == 255 || (next && (next < 0x40 || next > 0xfc || (next & 3))))
            return OCNEXT_PCI_INVALID_CHAIN;
        if (pci_duplicate(o, count, id, OCNEXT_PCI_CAP_CONVENTIONAL))
            return OCNEXT_PCI_DUPLICATE_CAPABILITY;
        c = &o->capabilities[count];
        c->offset = (uint16_t)off; c->next = (uint16_t)next; c->id = (uint16_t)id;
        c->list = OCNEXT_PCI_CAP_CONVENTIONAL; c->known_mask = OCNEXT_PCI_CAP_K_HEADER;
        result = pci_standard_body(p, o, c);
        if (result != OCNEXT_PCI_OK) return result;
        if (!pci_claim(w, off, c->validated_bytes, 256)) return OCNEXT_PCI_CAP_OVERLAP;
        o->standard_count++;
        off = next;
    }
    return OCNEXT_PCI_OK;
}
static enum ocnext_pci_result pci_extended(
    struct ocnext_pci_workspace *w, const uint8_t *p) {
    struct ocnext_pci_inventory *o = &w->staged;
    unsigned off = 0x100;
    uint32_t first = pci_u32(p + off);
    if (first == UINT32_MAX) { o->flags |= OCNEXT_PCI_F_EXT_UNAVAILABLE; return OCNEXT_PCI_OK; }
    o->known_mask |= OCNEXT_PCI_K_EXT_CHAIN;
    if (!first) return OCNEXT_PCI_OK;
    while (off) {
        struct ocnext_pci_capability *c;
        enum ocnext_pci_result result;
        uint32_t h;
        unsigned next, id, version, count = o->standard_count + o->extended_count;
        if (off < 0x100 || off > 0xffc || (off & 3)) return OCNEXT_PCI_INVALID_CHAIN;
        if (o->extended_count == OCNEXT_PCI_EXT_CAP_MAX) return OCNEXT_PCI_CAP_LIMIT;
        h = pci_u32(p + off); id = h & 0xffff; version = (h >> 16) & 15;
        /* Check the raw next12, rather than masking away reserved low bits. */
        next = h >> 20;
        if (!id || id == 0xffff || !version ||
            (next && (next < 0x100 || next > 0xffc || (next & 3))))
            return OCNEXT_PCI_INVALID_CHAIN;
        if (pci_duplicate(o, count, id, OCNEXT_PCI_CAP_EXTENDED))
            return OCNEXT_PCI_DUPLICATE_CAPABILITY;
        c = &o->capabilities[count];
        c->offset = (uint16_t)off; c->next = (uint16_t)next; c->id = (uint16_t)id;
        c->version = (uint8_t)version; c->list = OCNEXT_PCI_CAP_EXTENDED;
        c->known_mask = OCNEXT_PCI_CAP_K_HEADER;
        result = pci_extended_body(p, c);
        if (result != OCNEXT_PCI_OK) return result;
        if (!pci_claim(w, off, c->validated_bytes, 4096)) return OCNEXT_PCI_CAP_OVERLAP;
        o->extended_count++;
        off = next;
    }
    return OCNEXT_PCI_OK;
}
enum ocnext_pci_result ocnext_pci_inventory_parse(
    const struct ocnext_pci_snapshot *s, struct ocnext_pci_workspace *w,
    struct ocnext_pci_inventory *out) {
    const uint8_t *p;
    struct ocnext_pci_inventory *o;
    uint8_t digest[32]; unsigned i; enum ocnext_pci_result result;
    if (!pci_span(s, sizeof(*s), _Alignof(struct ocnext_pci_snapshot)) ||
        !pci_span(w, sizeof(*w), _Alignof(struct ocnext_pci_workspace)) ||
        !pci_span(out, sizeof(*out), _Alignof(struct ocnext_pci_inventory)))
        return OCNEXT_PCI_INVALID_ARGUMENT;
    if (pci_overlap(s, sizeof(*s), w, sizeof(*w)) ||
        pci_overlap(s, sizeof(*s), out, sizeof(*out)) ||
        pci_overlap(w, sizeof(*w), out, sizeof(*out))) return OCNEXT_PCI_ALIAS;
    if ((s->length != 256 && s->length != 4096) || !pci_span(s->bytes, s->length, 1))
        return OCNEXT_PCI_INVALID_ARGUMENT;
    if (pci_overlap(s->bytes, s->length, s, sizeof(*s)) ||
        pci_overlap(s->bytes, s->length, w, sizeof(*w)) ||
        pci_overlap(s->bytes, s->length, out, sizeof(*out))) return OCNEXT_PCI_ALIAS;
    if (!pci_identity(&s->identity)) return OCNEXT_PCI_INVALID_IDENTITY;
    p = s->bytes;
    if (ocnext_sha256_digest(p, s->length, digest)) return OCNEXT_PCI_INVALID_ARGUMENT;
    for (i = 0; i < 32; i++)
        if (digest[i] != s->expected_sha256[i]) return OCNEXT_PCI_DIGEST_MISMATCH;
    if (pci_u16(p) == 0xffff) return OCNEXT_PCI_NO_DEVICE;
    if ((p[0x0e] & 0x7f) > 1) return OCNEXT_PCI_UNSUPPORTED_HEADER;
    pci_zero(w, sizeof(*w)); o = &w->staged;
    pci_copy(&o->identity, &s->identity, sizeof(s->identity));
    pci_copy(o->sha256, digest, sizeof(digest));
    o->abi = OCNEXT_PCI_INVENTORY_ABI; o->config_bytes = (uint32_t)s->length;
    o->known_mask = OCNEXT_PCI_K_HEADER;
    o->vendor = pci_u16(p); o->device = pci_u16(p + 2);
    o->command = pci_u16(p + 4); o->status = pci_u16(p + 6);
    o->revision = p[8]; o->programming_interface = p[9]; o->subclass = p[10];
    o->class_code = p[11]; o->header_type = p[0x0e] & 0x7f;
    o->multifunction = p[0x0e] >> 7; o->bar_slots = o->header_type ? 2 : 6;
    if (!o->header_type) {
        o->subsystem_vendor = pci_u16(p + 0x2c); o->subsystem_device = pci_u16(p + 0x2e);
        o->known_mask |= OCNEXT_PCI_K_SUBSYSTEM;
    }
    result = pci_bars(o, p);
    if (result != OCNEXT_PCI_OK) return result;
    result = pci_standard(w, p);
    if (result != OCNEXT_PCI_OK) return result;
    if (s->length == 4096) {
        result = pci_extended(w, p);
        if (result != OCNEXT_PCI_OK) return result;
    }
    pci_copy(out, o, sizeof(*out));
    return OCNEXT_PCI_OK;
}
