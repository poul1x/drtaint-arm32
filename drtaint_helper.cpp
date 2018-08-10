#include "drtaint_helper.h"

#define TEST_BIT_UP(word, bit) ((word & (1 << bit)))
#define TEST_BIT_DOWN(word, bit) (!(word & (1 << bit)))

drreg_reservation::
    drreg_reservation(instrlist_t *ilist, instr_t *where)
    : drcontext_(dr_get_current_drcontext()),
      ilist_(ilist), where_(where)
{
    DR_ASSERT(drreg_reserve_register(drcontext_, ilist_, where_, NULL, &reg_) == DRREG_SUCCESS);
}

drreg_reservation::
    ~drreg_reservation()
{
    drreg_unreserve_register(drcontext_, ilist_, where_, reg_);
}

load_store_helper::
    load_store_helper(instr_t *where)
    : raw_instr_bits(instr_get_raw_word(where, 0))
{
    type1 = TEST_BIT_DOWN(this->raw_instr_bits, 25) &&
            TEST_BIT_DOWN(this->raw_instr_bits, 26);
}

load_store_helper::
    ~load_store_helper() = default;

bool load_store_helper::
    is_offs_addr()
{
    return TEST_BIT_UP(this->raw_instr_bits, 24) &&
           TEST_BIT_DOWN(this->raw_instr_bits, 21);
}

bool load_store_helper::
    is_pre_addr()
{
    return TEST_BIT_UP(this->raw_instr_bits, 24) &&
           TEST_BIT_UP(this->raw_instr_bits, 21);
}

bool load_store_helper::
    is_pre_or_offs_addr()
{
    return TEST_BIT_UP(this->raw_instr_bits, 24);
}

bool load_store_helper::
    is_post_addr()
{
    return TEST_BIT_DOWN(this->raw_instr_bits, 24);
}

bool load_store_helper::
    is_imm_offs()
{
    return type1 ? TEST_BIT_UP(this->raw_instr_bits, 22)
                 : TEST_BIT_DOWN(this->raw_instr_bits, 25);
}

bool load_store_helper::
    is_reg_offs()
{
    return type1 ? TEST_BIT_DOWN(this->raw_instr_bits, 22)
                 : TEST_BIT_UP(this->raw_instr_bits, 25);
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

void load_store_info(instr_t *where)
{

    load_store_helper lsh(where);
    if (lsh.is_imm_offs())
    {
        dr_printf("Imm offs\n");

        if (lsh.is_offs_addr())
            dr_printf("Offs addr\n");
        else if (lsh.is_pre_addr())
            dr_printf("Pre addr\n");
        else if (lsh.is_post_addr())
            dr_printf("Post addr\n");
    }

    else if (lsh.is_reg_offs())
    {
        dr_printf("Reg offs\n");

        if (lsh.is_offs_addr())
            dr_printf("Offs addr\n");
        else if (lsh.is_pre_addr())
            dr_printf("Pre addr\n");
        else if (lsh.is_post_addr())
            dr_printf("Post addr\n");
    }
}