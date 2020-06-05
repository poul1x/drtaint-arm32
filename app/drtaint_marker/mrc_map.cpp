#include "mrc_map.h"
#include "taint_processing.h"
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <sstream>
#include <string>

bool operator==(const mrc &left, const mrc &right)
{
    return left.pc == right.pc;
}

std::vector<mrc> g_instrs;

bool mrc_reads_coproc(instr_t *instr)
{
    int opcode = instr_get_opcode(instr);
    return opcode == OP_mrc || opcode == OP_mrc2;
}

bool mrc_has_instr(const struct mrc *item)
{
    auto it = std::find(g_instrs.begin(), g_instrs.end(), *item);
    return it != g_instrs.end();
}

void mrc_clear()
{
    g_instrs.clear();
}

void mrc_iterate_elements(mrc_func f, void *user_data)
{
    for (const auto &item : g_instrs)
        f(&item, user_data);
}

static void
on_mrc_instr(app_pc pc, reg_id_t reg)
{
    void *drcontext = dr_get_current_drcontext();
    dr_isa_mode_t mode = dr_get_isa_mode(drcontext);
    dr_mcontext_t mc = {
        sizeof(dr_mcontext_t),
        DR_MC_INTEGER};

    dr_get_mcontext(drcontext, &mc);

    mrc item;
    item.reg = get_register_name(reg);
    item.value = reg_get_value(reg, &mc);

    if (mode == DR_ISA_ARM_THUMB)
        item.pc = pc + 1;
    else
        item.pc = pc;

    // dr_printf("pc=%08x\nreg=%s\nval=%08x\n",item.pc, item.reg, item.value);

    if (!mrc_has_instr(&item))
        g_instrs.push_back(item);

    // dr_printf("mrc sz = %d\n", g_instrs.size());
}

void mrc_insert_save_arm_reg(void *drcontext, instrlist_t *ilist, instr_t *instr)
{
    // dr_printf("BBBBB\n");
    // instr_disassemble(drcontext, instr, STDOUT);
    // dr_printf("AAAAA ----- %d\n", instr_num_dsts(instr));

    instr_t *next_instr = instr_get_next(instr);
    app_pc pc = instr_get_app_pc(instr);
    reg_id_t reg = opnd_get_reg(instr_get_dst(instr, 0));

    dr_insert_clean_call(drcontext, ilist, next_instr, (void *)on_mrc_instr,
                         false, 2, OPND_CREATE_INTPTR(pc), OPND_CREATE_INTPTR(reg));
}