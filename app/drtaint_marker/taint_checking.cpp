#include "taint_checking.h"
#include "drtaint.h"
#include "drtaint_template_utils.h"
#include "drtaint_instr_groups.h"
#include "drtaint_helper.h"
#include "drutil.h"

#define MINSERT instrlist_meta_preinsert
#define MINSERT_xl8 instrlist_meta_preinsert_xl8

tc_callback_t g_tc_callback = nullptr;

static void
insert_check_reg_tainted(void *drcontext, instrlist_t *ilist, instr_t *where,
                         reg_id_t reg_param, reg_id_t reg_taint)
{
    DR_ASSERT(reg_param - DR_REG_R0 < DR_NUM_GPR_REGS);
    auto reg_scratch = drreg_reservation{drcontext, ilist, where};

    // store register taint value to reg_scratch
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg_param, reg_scratch);

    // update taint status
    MINSERT(ilist, where,
            INSTR_CREATE_orr(drcontext,
                             opnd_create_reg(reg_taint),
                             opnd_create_reg(reg_taint),
                             opnd_create_reg(reg_scratch)));
}

template <opnd_sz_t sz>
void insert_save_app_taint_to_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                  opnd_t mem, reg_id_t reg_result)

{
    auto sreg = drreg_reservation{drcontext, ilist, where};

    // save taint adress of mem to reg_result
    drutil_insert_get_mem_addr(drcontext, ilist, where, mem, reg_result, sreg);
    drtaint_insert_app_to_taint(drcontext, ilist, where, reg_result, sreg);

    // load memory taint value to reg_result
    MINSERT(ilist, where,
            instr_load<sz>(drcontext, // ldrXX sapp2, [sapp2]
                           opnd_create_reg(reg_result),
                           opnd_mem<sz>(reg_result, 0)));
}

static void
insert_check_mem_ldrd_tainted(void *drcontext, instrlist_t *ilist,
                              instr_t *where, reg_id_t reg_result)

{
    opnd_t mem = instr_get_src(where, 0);
    if (!opnd_is_base_disp(mem))
        return;

    auto sreg1 = drreg_reservation{drcontext, ilist, where};
    auto sreg2 = drreg_reservation{drcontext, ilist, where};
    auto reg_taint = drreg_reservation{drcontext, ilist, where};

    // save address of mem to reg_taint
    // also duplicate it to sreg1
    drutil_insert_get_mem_addr(drcontext, ilist, where, mem, reg_taint, sreg1);
    MINSERT(ilist, where,
            INSTR_CREATE_mov(drcontext,
                             opnd_create_reg(sreg1),
                             opnd_create_reg(reg_taint)));

    // load [mem] taint value to reg_taint
    drtaint_insert_app_to_taint(drcontext, ilist, where, reg_taint, sreg2);
    sreg2.unreserve();

    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, // ldr reg_taint, [reg_taint]
                              opnd_create_reg(reg_taint),
                              OPND_CREATE_MEM32(reg_taint, 0)));

    // combine taint of [mem]
    MINSERT(ilist, where,
            INSTR_CREATE_orr(drcontext,
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_taint)));

    // load [mem + 4] taint value to reg_taint
    MINSERT(ilist, where,
            XINST_CREATE_add_2src(drcontext,
                                  opnd_create_reg(reg_taint),
                                  opnd_create_reg(sreg1),
                                  OPND_CREATE_INT(4)));

    drtaint_insert_app_to_taint(drcontext, ilist, where, reg_taint, sreg1);
    sreg1.unreserve();

    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, // ldr reg_taint, [reg_taint]
                              opnd_create_reg(reg_taint),
                              OPND_CREATE_MEM32(reg_taint, 0)));

    // combine taint of [mem + 4]
    MINSERT(ilist, where,
            INSTR_CREATE_orr(drcontext,
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_taint)));
}

static void
insert_check_mem_ldr_tainted(void *drcontext, instrlist_t *ilist,
                             instr_t *where, reg_id_t reg_result)

{
    opnd_t mem = instr_get_src(where, 0);
    if (!opnd_is_base_disp(mem))
        return;

    int opcode = instr_get_opcode(where);
    auto reg_taint = drreg_reservation{drcontext, ilist, where};

    if (instr_group_is_ldrb(opcode))
        insert_save_app_taint_to_reg<BYTE>(drcontext, ilist, where, mem, reg_taint);

    else if (instr_group_is_ldrh(opcode))
        insert_save_app_taint_to_reg<HALF>(drcontext, ilist, where, mem, reg_taint);

    else if (instr_group_is_ldr(opcode))
        insert_save_app_taint_to_reg<WORD>(drcontext, ilist, where, mem, reg_taint);

    else
    {
        instr_disassemble(drcontext, where, STDOUT);
        dr_printf(" - failed to process\n");
        DR_ASSERT(false);
    }

    MINSERT(ilist, where,
            INSTR_CREATE_orr(drcontext,
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_result),
                             opnd_create_reg(reg_taint)));
}

static void
insert_check_mem_ldm_tainted(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    // Not implemented now
}

static void
insert_check_mem_tainted(void *drcontext, instrlist_t *ilist, instr_t *where,
                         reg_id_t reg_result)

{
    int opcode = instr_get_opcode(where);
    if (instr_group_is_ldm(opcode))
        insert_check_mem_ldm_tainted(drcontext, ilist, where);

    else if (instr_group_is_ldrd(opcode))
        insert_check_mem_ldrd_tainted(drcontext, ilist, where, reg_result);

    else
        insert_check_mem_ldr_tainted(drcontext, ilist, where, reg_result);
}

static bool
instr_reg_in_dsts(instr_t *where)
{
    int n = instr_num_dsts(where);
    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_dst(where, i);
        if (opnd_is_reg(opnd))
            return true;
    }

    return false;
}

static void
insert_handle_tainted_srcs(void *drcontext, instrlist_t *ilist,
                           instr_t *where, reg_id_t reg_result)
{
    if (instr_reads_memory(where))
    {
        if (!instr_reg_in_dsts(where))
            return;

        insert_check_mem_tainted(drcontext, ilist, where, reg_result);
        return;
    }

    int n = instr_num_srcs(where);
    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_src(where, i);
        if (opnd_is_reg(opnd))
        {
            insert_check_reg_tainted(drcontext, ilist, where,
                                     opnd_get_reg(opnd), reg_result);
        }
    }
}

static void
insert_zero_result(void *drcontext, instrlist_t *ilist,
                   instr_t *where, reg_id_t reg_result)
{
    auto pred = disabled_autopredication(ilist);

    MINSERT(ilist, where,
            XINST_CREATE_move(drcontext, // mov reg_result, 0
                              opnd_create_reg(reg_result),
                              OPND_CREATE_INT(0)));
}

static void
clean_call_cb(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
    auto instr = instr_decoded(drcontext, pc);
    DR_ASSERT((instr_t *)instr != NULL);
    instr_set_translation(instr, pc);

    DR_ASSERT(g_tc_callback != NULL);
    g_tc_callback(drcontext, instr);
}

static void
insert_clean_call_if_result_tainted(void *drcontext, instrlist_t *ilist,
                                    instr_t *where, reg_id_t reg_result)
{
    auto pred = disabled_autopredication(ilist);
    auto reg_flags = drreg_reservation{drcontext, ilist, where};

    instr_t *skip = INSTR_CREATE_label(drcontext);
    dr_save_arith_flags_to_reg(drcontext, ilist, where, reg_flags);

    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_result), OPND_CREATE_INT(0)));

    MINSERT(ilist, where,
            XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(skip)));

    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_cb,
                         false, 1, OPND_CREATE_INTPTR(instr_get_app_pc(where)));

    MINSERT(ilist, where, skip);
    dr_restore_arith_flags_from_reg(drcontext, ilist, where, reg_flags);
}

void tc_perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    // reserve register indicating that instr is tainted
    // set value to 0 (not tainted)
    auto reg_result = drreg_reservation{drcontext, ilist, where};
    insert_zero_result(drcontext, ilist, where, reg_result);

    // walk instr operands, check they are tainted
    // place final result to reg_result
    insert_handle_tainted_srcs(drcontext, ilist, where, reg_result);

    // if instr is tainted, then insert clean call to save info
    insert_clean_call_if_result_tainted(drcontext, ilist, where, reg_result);
}


void tc_set_callback(tc_callback_t cb) {
    g_tc_callback = cb;
}