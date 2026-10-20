/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Additional A64 instruction classes needed by the real kernel boot path
 * (M-BOOT): conditional compare, extended-register add/sub, register-offset
 * and literal loads/stores, LSE atomics, CAS, exclusives/acquire/release,
 * BTI/YIELD hints, cache/TLB maintenance by VA. Textually included by a64.c
 * (it uses that file's static helpers and must add no external symbols).
 *
 * Memory model (shared with the rest of the core): one CPU, serialized Normal
 * RAM, no caches and no TLB. Atomics are plain read-modify-write because no
 * other observer exists. Unaligned atomics/exclusives/acquire-release are
 * outside the model (alignment fault delivery is not modeled) and stop.
 */

enum more_status { MORE_NONE = 0, MORE_OK, MORE_UNSUPPORTED, MORE_RESULT };


/* Same FP/SIMD access gate as the existing SIMD load/store branch. */
static int more_fp_access(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
                          uint32_t op, enum ocnext_a64_result *res)
{
    struct ocnext_a64_fp_access_request access = {.current_el = cpu->system.current_el,
        .profile = OCNEXT_A64_FP_CONTROL_FPEN_ONLY};
    struct ocnext_a64_fp_access_effect permission;
    enum ocnext_a64_fp_control_result allowed;
    if (!sync_profile(cpu)) return MORE_UNSUPPORTED;
    if (!valid_system(cpu)) {
        *res = fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        return MORE_RESULT;
    }
    allowed = ocnext_a64_fp_access_prepare(&cpu->fp, &access, &permission);
    if (allowed == OCNEXT_A64_FP_CONTROL_ARGUMENT) {
        *res = fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        return MORE_RESULT;
    }
    if (allowed != OCNEXT_A64_FP_CONTROL_OK) return MORE_UNSUPPORTED;
    if (permission.action == OCNEXT_A64_FP_ACCESS_EXCEPTION) {
        *res = take_sync(cpu, memory, op, permission.esr >> 26, permission.esr & UINT32_C(0x01ffffff), cpu->pc, 0);
        return MORE_RESULT;
    }
    if (permission.action != OCNEXT_A64_FP_ACCESS_ALLOWED) {
        *res = fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
        return MORE_RESULT;
    }
    return MORE_OK;
}

static uint64_t more_extend(uint64_t value, unsigned option, unsigned shift_amount)
{
    unsigned bits = 8u << (option & 3u);
    if (bits < 64) value &= mask_for(bits);
    if (option & 4u) value = sign_extend(value, bits);
    return value << shift_amount;
}

#include "a64_vec.inc"
#include "a64_crypto.inc"

static int more_exec(struct ocnext_a64_cpu *cpu, const struct ocnext_a64_memory *memory,
                     const struct ocnext_a64_hooks *hooks, uint32_t op, struct transaction *tx,
                     uint8_t *bytes, enum ocnext_a64_result *res)
{
    unsigned width = (op >> 31) ? 64u : 32u;
    unsigned rd = op & 31u, rn = (op >> 5) & 31u, rm = (op >> 16) & 31u;
    enum ocnext_a64_fault_code code;

    /* ---- conditional compare (CCMP/CCMN, register and immediate) ---- */
    if ((op & UINT32_C(0x3fe00410)) == UINT32_C(0x3a400000)) {
        int subtract = (op >> 30) & 1u;
        uint64_t a = reg_read(cpu, rn, width, 0);
        uint64_t b = (op & (1u << 11)) ? (uint64_t)((op >> 16) & 31u) : reg_read(cpu, rm, width, 0);
        if (condition_holds(cpu->nzcv, (op >> 12) & 15u)) {
            uint64_t r = (subtract ? a - b : a + b) & mask_for(width);
            tx->nzcv = arithmetic_flags(a, b, r, width, subtract);
        } else tx->nzcv = (op & 15u) << 28;
        tx->set_flags = 1;
        return MORE_OK;
    }

    /* ---- add/sub (extended register) ---- */
    if ((op & UINT32_C(0x1fe00000)) == UINT32_C(0x0b200000)) {
        int subtract = (op >> 30) & 1u, set_flags = (op >> 29) & 1u;
        unsigned option = (op >> 13) & 7u, amount = (op >> 10) & 7u;
        uint64_t a, b, r;
        if (amount > 4) return MORE_UNSUPPORTED;
        a = reg_read(cpu, rn, width, 1);
        b = more_extend(reg_read(cpu, rm, 64, 0), option, amount) & mask_for(width);
        r = (subtract ? a - b : a + b) & mask_for(width);
        stage_write(tx, rd, r, width, !set_flags);
        if (set_flags) { tx->set_flags = 1; tx->nzcv = arithmetic_flags(a, b, r, width, subtract); }
        return MORE_OK;
    }

    /* ---- load/store register offset (GPR and SIMD) ---- */
    if ((op & UINT32_C(0x3b200c00)) == UINT32_C(0x38200800)) {
        unsigned size = op >> 30, opc = (op >> 22) & 3u, option = (op >> 13) & 7u;
        int vec = (op >> 26) & 1u, scaled = (op >> 12) & 1u;
        uint64_t base, address, offset;
        unsigned bytes_n, shift_amount;
        int load;
        enum ocnext_a64_result stopped;
        if (!(option == 2 || option == 3 || option == 6 || option == 7)) return MORE_UNSUPPORTED;
        if (vec) {
            int st = more_fp_access(cpu, memory, op, res);
            if (st != MORE_OK) return st;
            if (opc & 2u) { if (size != 0) return MORE_UNSUPPORTED; bytes_n = 16; }
            else bytes_n = 1u << size;
            load = opc & 1u;
            shift_amount = scaled ? (bytes_n == 16 ? 4u : size) : 0;
        } else {
            if (opc == 2 && size == 3) return MORE_OK; /* PRFM: hint, no architectural effect */
            if ((opc == 3 && size >= 2) || (opc == 2 && size == 3)) return MORE_UNSUPPORTED;
            bytes_n = 1u << size; load = opc != 0; shift_amount = scaled ? size : 0;
        }
        if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) { *res = stopped; return MORE_RESULT; }
        base = reg_read(cpu, rn, 64, 1);
        offset = reg_read(cpu, rm, 64, 0);
        if (option == 2) offset &= UINT64_C(0xffffffff);
        else if (option == 6) offset = sign_extend(offset & UINT64_C(0xffffffff), 32);
        offset <<= shift_amount;
        address = base + offset;
        if (!load) {
            if (vec) {
                unsigned i;
                uint16_t need = (uint16_t)(bytes_n == 16 ? UINT16_MAX : (1u << bytes_n) - 1u);
                if ((cpu->vector.known_bytes[rd] & need) != need) return MORE_UNSUPPORTED;
                for (i = 0; i < bytes_n; ++i) bytes[i] = cpu->vector.bytes[rd][i];
            } else little_write(bytes, reg_read(cpu, rd, size == 3 ? 64 : 32, 0), bytes_n);
        }
        code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, load);
        if (code != OCNEXT_A64_FAULT_NONE) {
            *res = fault(cpu, code, load ? OCNEXT_A64_ACCESS_READ : OCNEXT_A64_ACCESS_WRITE, address, bytes_n, op);
            return MORE_RESULT;
        }
        if (load) {
            if (vec) stage_vector(tx, rd, bytes, bytes_n);
            else {
                uint64_t v = little_read(bytes, bytes_n);
                if (opc >= 2) v = sign_extend(v, bytes_n * 8);
                stage_write(tx, rd, v, (opc == 2 || size == 3) ? 64 : 32, 0);
            }
        }
        return MORE_OK;
    }

    /* ---- load literal (GPR and SIMD) ---- */
    if ((op & UINT32_C(0x3b000000)) == UINT32_C(0x18000000)) {
        unsigned opc = op >> 30;
        int vec = (op >> 26) & 1u;
        uint64_t address = cpu->pc + (sign_extend((op >> 5) & 524287u, 19) << 2);
        unsigned bytes_n;
        if (vec) {
            int st = more_fp_access(cpu, memory, op, res);
            if (st != MORE_OK) return st;
            if (opc == 3) return MORE_UNSUPPORTED;
            bytes_n = 4u << opc;
        } else {
            if (opc == 3) return MORE_OK; /* PRFM literal */
            bytes_n = opc == 1 ? 8 : 4;
        }
        code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 1);
        if (code != OCNEXT_A64_FAULT_NONE) {
            *res = fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, bytes_n, op);
            return MORE_RESULT;
        }
        if (vec) stage_vector(tx, rd, bytes, bytes_n);
        else {
            uint64_t v = little_read(bytes, bytes_n);
            if (opc == 2) v = sign_extend(v, 32);
            stage_write(tx, rd, v, opc == 0 ? 32 : 64, 0);
        }
        return MORE_OK;
    }

    /* ---- LSE atomics (LDADD..LDUMIN, SWP) and LDAPR ---- */
    if ((op & UINT32_C(0x3f200c00)) == UINT32_C(0x38200000)) {
        unsigned size = op >> 30, opc = (op >> 12) & 7u, o3 = (op >> 15) & 1u;
        unsigned bytes_n = 1u << size, bits = bytes_n * 8;
        uint64_t address, old, src, result;
        enum ocnext_a64_result stopped;
        int ldapr = o3 && opc == 4;
        if (!sync_profile(cpu)) return MORE_UNSUPPORTED;
        if (o3 && opc != 0 && !ldapr) return MORE_UNSUPPORTED;
        if (ldapr && (rm != 31 || (op & (1u << 22)) || !(op & (1u << 23)))) return MORE_UNSUPPORTED;
        if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) { *res = stopped; return MORE_RESULT; }
        address = reg_read(cpu, rn, 64, 1);
        if (address & (bytes_n - 1u)) return MORE_UNSUPPORTED;
        code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 1);
        if (code != OCNEXT_A64_FAULT_NONE) {
            *res = fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, bytes_n, op);
            return MORE_RESULT;
        }
        old = little_read(bytes, bytes_n);
        if (!ldapr) {
            src = reg_read(cpu, rm, 64, 0) & mask_for(bits);
            if (o3) result = src;
            else switch (opc) {
            case 0: result = old + src; break;
            case 1: result = old & ~src; break;
            case 2: result = old ^ src; break;
            case 3: result = old | src; break;
            case 4: result = (int64_t)sign_extend(old, bits) > (int64_t)sign_extend(src, bits) ? old : src; break;
            case 5: result = (int64_t)sign_extend(old, bits) < (int64_t)sign_extend(src, bits) ? old : src; break;
            case 6: result = old > src ? old : src; break;
            default: result = old < src ? old : src; break;
            }
            result &= mask_for(bits);
            little_write(bytes, result, bytes_n);
            code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 0);
            if (code != OCNEXT_A64_FAULT_NONE) {
                *res = fault(cpu, code, OCNEXT_A64_ACCESS_WRITE, address, bytes_n, op);
                return MORE_RESULT;
            }
        }
        stage_write(tx, rd, old, size == 3 ? 64 : 32, 0);
        return MORE_OK;
    }

    /* ---- CAS / CASA / CASL / CASAL (byte, half, word, double) ---- */
    if ((op & UINT32_C(0x3fa07c00)) == UINT32_C(0x08a07c00)) {
        unsigned size = op >> 30, bytes_n = 1u << size, bits = bytes_n * 8;
        uint64_t address, old, expect, desired;
        enum ocnext_a64_result stopped;
        if (!sync_profile(cpu)) return MORE_UNSUPPORTED;
        if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) { *res = stopped; return MORE_RESULT; }
        address = reg_read(cpu, rn, 64, 1);
        if (address & (bytes_n - 1u)) return MORE_UNSUPPORTED;
        expect = reg_read(cpu, rm, 64, 0) & mask_for(bits);
        desired = reg_read(cpu, rd, 64, 0) & mask_for(bits);
        code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 1);
        if (code != OCNEXT_A64_FAULT_NONE) {
            *res = fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, bytes_n, op);
            return MORE_RESULT;
        }
        old = little_read(bytes, bytes_n);
        if (old == expect) {
            little_write(bytes, desired, bytes_n);
            code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 0);
            if (code != OCNEXT_A64_FAULT_NONE) {
                *res = fault(cpu, code, OCNEXT_A64_ACCESS_WRITE, address, bytes_n, op);
                return MORE_RESULT;
            }
        }
        stage_write(tx, rm, old, size == 3 ? 64 : 32, 0);
        return MORE_OK;
    }

    /* ---- exclusives and acquire/release (LDXR/STXR/LDAXR/STLXR/LDAR/STLR) ---- */
    if ((op & UINT32_C(0x3f000000)) == UINT32_C(0x08000000)) {
        unsigned size = op >> 30, bytes_n = 1u << size, bits = bytes_n * 8;
        int o2 = (op >> 23) & 1u, load = (op >> 22) & 1u, o1 = (op >> 21) & 1u, o0 = (op >> 15) & 1u;
        unsigned rt2 = (op >> 10) & 31u;
        uint64_t address;
        enum ocnext_a64_result stopped;
        struct ocnext_a64_exclusive *monitor = hooks ? hooks->exclusive : NULL;
        if (!sync_profile(cpu) || o1 || rt2 != 31) return MORE_UNSUPPORTED;
        if (stop_sp_alignment(cpu, memory, op, rn, &stopped)) { *res = stopped; return MORE_RESULT; }
        address = reg_read(cpu, rn, 64, 1);
        if (address & (bytes_n - 1u)) return MORE_UNSUPPORTED;
        if (o2) { /* LDAR/STLR; the LORegion forms (o0=0) are outside the model */
            if (!o0 || rm != 31) return MORE_UNSUPPORTED;
            if (load) {
                code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 1);
                if (code != OCNEXT_A64_FAULT_NONE) { *res = fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, bytes_n, op); return MORE_RESULT; }
                stage_write(tx, rd, little_read(bytes, bytes_n), size == 3 ? 64 : 32, 0);
            } else {
                little_write(bytes, reg_read(cpu, rd, bits == 64 ? 64 : bits, 0), bytes_n);
                code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 0);
                if (code != OCNEXT_A64_FAULT_NONE) { *res = fault(cpu, code, OCNEXT_A64_ACCESS_WRITE, address, bytes_n, op); return MORE_RESULT; }
            }
            return MORE_OK;
        }
        if (!monitor) return MORE_UNSUPPORTED;
        if (load) {
            if (rm != 31) return MORE_UNSUPPORTED;
            code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 1);
            if (code != OCNEXT_A64_FAULT_NONE) { *res = fault(cpu, code, OCNEXT_A64_ACCESS_READ, address, bytes_n, op); return MORE_RESULT; }
            monitor->address = address; monitor->size = (uint8_t)bytes_n; monitor->valid = 1;
            stage_write(tx, rd, little_read(bytes, bytes_n), size == 3 ? 64 : 32, 0);
        } else {
            int ok;
            if (rm == rd || (rm == rn && rn != 31)) return MORE_UNSUPPORTED; /* CONSTRAINED UNPREDICTABLE */
            ok = monitor->valid && monitor->address == address && monitor->size == bytes_n;
            monitor->valid = 0;
            if (ok) {
                little_write(bytes, reg_read(cpu, rd, 64, 0), bytes_n);
                code = memory_transfer(cpu, memory, address, bytes, bytes_n, bytes_n, 0);
                if (code != OCNEXT_A64_FAULT_NONE) { *res = fault(cpu, code, OCNEXT_A64_ACCESS_WRITE, address, bytes_n, op); return MORE_RESULT; }
            }
            stage_write(tx, rm, ok ? 0 : 1, 32, 0);
        }
        return MORE_OK;
    }

    /* ---- hints with no effect in this model: BTI (BT unset), YIELD ---- */
    if ((op & UINT32_C(0xffffff3f)) == UINT32_C(0xd503241f) || op == UINT32_C(0xd503203f))
        return MORE_OK;

    /* ---- CLREX ---- */
    if ((op & UINT32_C(0xfffff0ff)) == UINT32_C(0xd503305f)) {
        if (hooks && hooks->exclusive) hooks->exclusive->valid = 0;
        return MORE_OK;
    }

    /* ---- SYS: AT S1E1RP / S1E1WP (PAN-checked). IC/DC/TLBI/AT S1E1R/W/E0R/W are decoded earlier by
     * a64_sysmaint.inc.c and delegated to the maintenance provider; the remaining SYS forms
     * (e.g. TLBI range ops, DC CVAP) stay unsupported stops, never silent no-ops. ---- */
    if ((op & UINT32_C(0xfff80000)) == UINT32_C(0xd5080000)) {
        unsigned op1 = (op >> 16) & 7u, crn = (op >> 12) & 15u, crm = (op >> 8) & 15u, op2 = (op >> 5) & 7u;
        uint64_t address = reg_read(cpu, rd, 64, 0);
        if (!sync_profile(cpu)) return MORE_UNSUPPORTED;
        if (!valid_system(cpu)) {
            *res = fault(cpu, OCNEXT_A64_FAULT_ARGUMENT, OCNEXT_A64_ACCESS_FETCH, cpu->pc, 4, op);
            return MORE_RESULT;
        }
        if (crn == 7 && op1 == 0 && crm == 9 && op2 < 2) {
            int ok;
            if (cpu->system.current_el == 0) { *res = undefined_access(cpu, memory, op); return MORE_RESULT; }
            if (!hooks || !hooks->at) return MORE_UNSUPPORTED;
            /* The AT hook publishes PAR_EL1 with ocnext_a64_publish_par_el1() while the handshake is open. */
            cpu->ext_at_active = 1;
            ok = hooks->at(hooks->at_context, address, op2 & 1u, 0u, 1u) == 0 && cpu->ext_at_active == 2;
            cpu->ext_at_active = 0;
            return ok ? MORE_OK : MORE_UNSUPPORTED;
        }
        return MORE_UNSUPPORTED;
    }
    {
        int crypto = crypto_exec(cpu, memory, hooks, op, tx, res);
        if (crypto != MORE_NONE) return crypto;
    }
    return vec_exec(cpu, memory, op, tx, bytes, res);
}
