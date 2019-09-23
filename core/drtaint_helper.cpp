#include "include/drtaint_helper.h"
#include "drmgr.h"

drreg_reservation::
    drreg_reservation(void* drcontext, instrlist_t *ilist, instr_t *where)
    : drcontext_(drcontext), ilist_(ilist), where_(where)
{
    bool status = drreg_reserve_register(drcontext_, ilist_, where_, NULL, &reg_);
    DR_ASSERT(status == DRREG_SUCCESS);
}

drreg_reservation::
    ~drreg_reservation()
{
    drreg_unreserve_register(drcontext_, ilist_, where_, reg_);
}

bool is_offs_addr(uint raw_instr_bits)
{
    return IS_BIT_UP(raw_instr_bits, 24) &&
           IS_BIT_DOWN(raw_instr_bits, 21);
}

bool is_pre_addr(uint raw_instr_bits)
{
    return IS_BIT_UP(raw_instr_bits, 24) &&
           IS_BIT_UP(raw_instr_bits, 21);
}

bool is_pre_or_offs_addr(uint raw_instr_bits)
{
    return IS_BIT_UP(raw_instr_bits, 24);
}

bool is_post_addr(uint raw_instr_bits)
{
    return IS_BIT_DOWN(raw_instr_bits, 24);
}

void unimplemented_opcode(instr_t *where)
{
    /* N/A */
}

void instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert)
{
    instrlist_meta_preinsert(ilist, where, INSTR_XL8(insert, instr_get_app_pc(where)));
}

void what_are_srcs(instr_t *where)
{
    int n = instr_num_srcs(where);

    if (n == 0)
        dr_printf("No args\n");
    else
    {
        dr_printf("%d args:", n);
        for (int i = 0; i < n; i++)
        {
            opnd_t opnd = instr_get_src(where, i);
            const char *s = opnd_is_reg(opnd)
                                ? "reg"
                                : opnd_is_null(opnd)
                                      ? "null"
                                      : opnd_is_immed(opnd)
                                            ? "imm"
                                            : opnd_is_memory_reference(opnd)
                                                  ? "mem"
                                                  : "unknown";

            dr_printf("%s ", s);
        }

        dr_printf("\n");
    }
}

void what_are_dsts(instr_t *where)
{
    int n = instr_num_dsts(where);

    if (n == 0)
        dr_printf("No args\n");
    else
    {
        dr_printf("%d args:", n);
        for (int i = 0; i < n; i++)
        {
            opnd_t opnd = instr_get_dst(where, i);
            const char *s = opnd_is_reg(opnd)
                                ? "reg"
                                : opnd_is_null(opnd)
                                      ? "null"
                                      : opnd_is_immed(opnd)
                                            ? "imm"
                                            : opnd_is_memory_reference(opnd)
                                                  ? "mem"
                                                  : "unknown";

            dr_printf("%s ", s);
        }

        dr_printf("\n");
    }
}