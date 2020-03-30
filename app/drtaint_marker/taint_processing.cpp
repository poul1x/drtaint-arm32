#include "taint_processing.h"

#include "drtaint.h"
#include "drtaint_helper.h"
#include "drtaint_instr_groups.h"

#include <byteswap.h>

static void
save_mem_ldm_taint(void *drcontext, instr_t *where,
                   dr_mcontext_t *mc, tainted_opnd_vec *vec)
{
    // Not implemented
}

static void
save_mem_ldrd_taint(void *drcontext, instr_t *where,
                    dr_mcontext_t *mc, tainted_opnd_vec *vec)
{
    opnd_t mem = instr_get_src(where, 0);
    if (!opnd_is_base_disp(mem))
        return;

    tainted_opnd opnd, opnd4;
    opnd.type = opnd4.type = tainted_opnd::addr;

    app_pc addr = opnd_compute_address(mem, mc);
    opnd4.address = (uint32_t)(addr + 4);
    opnd.address = (uint32_t)addr;

    opnd.value.sz = opnd4.value.sz = u_integer::sz4_bytes;
    opnd.taint.sz = opnd4.taint.sz = u_integer::sz4_bytes;

    size_t bytes_read = 0;
    dr_safe_read(addr, 4, &opnd.value.u32, &bytes_read);
    drtaint_get_app_taint(drcontext, addr, (byte *)&opnd.taint.u32);

    addr += 4;
    dr_safe_read(addr, 4, &opnd4.value.u32, &bytes_read);
    drtaint_get_app_taint(drcontext, addr, (byte *)&opnd4.taint.u32);

    if (opnd.taint.u32 != 0)
        vec->push_back(opnd);

    if (opnd4.taint.u32 != 0)
        vec->push_back(opnd4);
}

static void
save_mem_ldr_taint(void *drcontext, instr_t *where,
                   dr_mcontext_t *mc, tainted_opnd_vec *vec)
{
    opnd_t mem = instr_get_src(where, 0);
    if (!opnd_is_base_disp(mem))
        return;

    tainted_opnd opnd;
    opnd.type = tainted_opnd::addr;

    size_t bytes_read = 0;
    app_pc addr = opnd_compute_address(mem, mc);
    opnd.address = (uint32_t)addr;

    int opcode = instr_get_opcode(where);
    if (instr_group_is_ldrb(opcode))
    {
        opnd.value.sz = u_integer::sz1_byte;
        opnd.taint.sz = u_integer::sz1_byte;

        dr_safe_read(addr, 1, &opnd.value.u8, &bytes_read);
        drtaint_get_app_taint(drcontext, addr, (byte *)&opnd.taint.u8);

        if (opnd.taint.u8 != 0)
            vec->push_back(opnd);
    }

    else if (instr_group_is_ldrh(opcode))
    {
        opnd.value.sz = u_integer::sz2_bytes;
        opnd.taint.sz = u_integer::sz2_bytes;

        dr_safe_read(addr, 2, &opnd.value.u16, &bytes_read);
        drtaint_get_app_taint(drcontext, addr, (byte *)&opnd.taint.u16);

        if (opnd.taint.u16 != 0)
            vec->push_back(opnd);
    }

    else if (instr_group_is_ldr(opcode))
    {
        opnd.value.sz = u_integer::sz4_bytes;
        opnd.taint.sz = u_integer::sz4_bytes;

        dr_safe_read(addr, 4, &opnd.value.u32, &bytes_read);
        drtaint_get_app_taint(drcontext, addr, (byte *)&opnd.taint.u32);

        if (opnd.taint.u32 != 0)
            vec->push_back(opnd);
    }

    else
    {
        instr_disassemble(drcontext, where, STDOUT);
        DR_ASSERT_MSG(false, "\nInstruction not handled!");
    }
}

static void
save_mem_taint(void *drcontext, instr_t *where,
               dr_mcontext_t *mc, tainted_opnd_vec *vec)
{
    int opcode = instr_get_opcode(where);
    if (instr_group_is_ldm(opcode))
        save_mem_ldm_taint(drcontext, where, mc, vec);

    else if (instr_group_is_ldrd(opcode))
        save_mem_ldrd_taint(drcontext, where, mc, vec);

    else
        save_mem_ldr_taint(drcontext, where, mc, vec);
}

void tainted_instr_save_tainted_opnds(void *drcontext, instr_t *where, tainted_instr *instr)
{
    dr_mcontext_t mc = {
        sizeof(dr_mcontext_t),
        DR_MC_INTEGER,
    };

    dr_get_mcontext(drcontext, &mc);

    if (instr_reads_memory(where))
    {
        save_mem_taint(drcontext, where, &mc, &instr->operands);
        return;
    }

    int n = instr_num_srcs(where);
    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_src(where, i);
        if (opnd_is_reg(opnd))
        {
            tainted_opnd opnd_tnt = {};
            opnd_tnt.type = tainted_opnd::reg;
            opnd_tnt.value.sz = u_integer::sz4_bytes;
            opnd_tnt.taint.sz = u_integer::sz4_bytes;

            reg_id_t reg = opnd_get_reg(opnd);

            drtaint_get_reg_taint(drcontext, reg, &opnd_tnt.taint.u32);
            opnd_tnt.value.u32 = reg_get_value(reg, &mc);
            opnd_tnt.reg_num = reg;

            if (opnd_tnt.taint.u32 != 0)
                instr->operands.push_back(opnd_tnt);
        }
    }
}

std::string tainted_opnd_name_str(const tainted_opnd &opnd)
{
    return opnd.type == tainted_opnd::reg
               ? std::string(get_register_name(opnd.reg_num))
               : std::to_string(opnd.address);
}

std::string tainted_opnd_type_str(const tainted_opnd &opnd)
{
    return opnd.type == tainted_opnd::reg
               ? "register"
               : "address";
}

std::string tainted_opnd_value_str(const tainted_opnd &opnd)
{
    return u_integer_hex_str(opnd.value);
}

std::string tainted_opnd_taint_str(const tainted_opnd &opnd)
{
    return u_integer_hex_str(opnd.taint);
}

void tainted_instr_save_bytes(void *drcontext, instr_t *instr, tainted_instr *tnt_instr)
{
    tnt_instr->pc = instr_get_raw_bits(instr);
    return;

    int length = instr_length(drcontext, instr);

    if (length == 2)
    {
        tnt_instr->bytes.sz = u_integer::sz2_bytes;
        tnt_instr->bytes.u16 = bswap_16(*(uint16_t *)instr_get_raw_bits(instr));
    }
    else
    {
        tnt_instr->bytes.sz = u_integer::sz4_bytes;
        tnt_instr->bytes.u32 = bswap_32(*(uint32_t *)instr_get_raw_bits(instr));
    }
}

instr_decoded tainted_instr_decode(void *drcontext, const tainted_instr &instr)
{
    app_pc bytes = (app_pc)instr.bytes.u32;
    return instr_decoded(drcontext, instr.pc);

    if (instr.bytes.sz == u_integer::sz4_bytes)
    {
        uint32_t bytes = instr.bytes.u32; //bswap_32(instr.bytes.u32);
        return instr_decoded(drcontext, (app_pc)&bytes);
    }
    else
    {
        uint16_t bytes = instr.bytes.u16; //bswap_32(instr.bytes.u16);
        return instr_decoded(drcontext, (app_pc)&bytes);
    }
}

std::string tainted_instr_hit_count_str(const tainted_instr &instr)
{
    return std::to_string(instr.hit_count);
}

std::string tainted_instr_bytes_str(const tainted_instr &instr)
{
    return u_integer_hex_str(instr.bytes);
}

std::string u_integer_hex_str(const u_integer &itgr)
{
    if (itgr.sz == u_integer::sz1_byte)
    {
        char buf[2];
        dr_snprintf(buf, sizeof(buf), "%02hhX", itgr.u8);
        return std::string(buf, sizeof(buf));
    }

    if (itgr.sz == u_integer::sz2_bytes)
    {
        char buf[4];
        dr_snprintf(buf, sizeof(buf), "%04hX", itgr.u16);
        return std::string(buf, sizeof(buf));
    }

    else
    {
        char buf[8];
        dr_snprintf(buf, sizeof(buf), "%08lX", itgr.u32);
        return std::string(buf, sizeof(buf));
    }
}