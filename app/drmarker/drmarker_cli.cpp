#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

#include "../../core/include/drtaint.h"
#include "../../core/include/drtaint_shadow.h"
#include "../../core/include/drtaint_helper.h"
#include <syscall.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define IS_TAINTED(val, tag) ((val) & (tag))
#define TAG_VISITED 0x04
#define TAG_TAINTED 0x02

#define MINSERT instrlist_meta_preinsert
#define MINSERT_xl8 instrlist_meta_preinsert_xl8

static int tls_index;

#pragma region structs

struct data_reg
{
    uint32_t value;
    uint32_t taint;
};

struct data_mem
{
    uint32_t addr;
    uint32_t value;
    uint32_t taint;
};

struct per_thread_t
{
    data_reg dr[DR_NUM_GPR_REGS];
    data_mem dm[DR_NUM_GPR_REGS + 1];
};

#pragma endregion structs

#pragma region func_prototypes

static void
exit_event(void);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
record_tainted_instr(app_pc pc, void *is_tainted);

static void
insert_conditional_skip(void *drcontext, instrlist_t *ilist, instr_t *where,
                        reg_id_t reg_skip_if_zero, instr_t *skip_label);

static void
insert_write_reg_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                      reg_id_t reg_param, reg_id_t reg_tls, reg_id_t reg_scratch);

static void
insert_write_null_mem_entry(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t reg_tls, reg_id_t reg_scratch, int idx);

static void
insert_write_mem_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                      opnd_t mem, reg_id_t reg_tls, int idx, uint8_t add = 0);

static void
insert_handle_tainted_srcs(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t reg_tls, reg_id_t reg_result);

static void
insert_handle_tainted_dsts(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t reg_tls, reg_id_t reg_result);

static void
insert_handle_tainted_operands(void *drcontext, instrlist_t *ilist, instr_t *where);

static void
get_instr_taint_info(void *drcontext, app_pc pc, int instr_len,
                     bool *is_visited, bool *is_tainted);

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

#pragma endregion func_prototypes

#pragma region clean_call

static void
record_tainted_instr(app_pc pc, void *is_tainted)
{
    if (is_tainted == NULL)
        return;

    void *drcontext = dr_get_current_drcontext();
    per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    drtaint_set_app_taint(drcontext, pc, TAG_TAINTED);
    
    dr_printf("Memory: ");
    for (uint i = 0; i < sizeof(tls->dm) / sizeof(tls->dm[0]); i++)
    {
        data_mem dm = tls->dm[i];
        if (dm.taint != 0)
            dr_printf("\t{address=0x%08X, taint=0x%08X}; ", dm.addr, dm.taint);
    }

    dr_printf("\nRegisters:");
    for (uint i = 0; i < sizeof(tls->dr) / sizeof(tls->dr[0]); i++)
    {
        data_reg dr = tls->dr[i];
        if (dr.taint != 0)
            dr_printf("\t{name=r%d, value=0x%08X, taint=0x%08X}", i, dr.value, dr.taint);
    }

    instr_t *instr = instr_create(drcontext);
    decode(drcontext, (byte *)pc, instr);
    
    dr_printf("\n");
    disassemble(drcontext, pc, STDOUT);
    dr_printf("\n");
    dr_printf("\n");
    instr_destroy(drcontext, instr);
}

#pragma endregion clean_call

#pragma region handle_tainted

/** 
 * Inserts a conditional branch that jumps 
 * to skip_label if reg_skip_if_zero's value is zero.
 * This function may changes arith flags
 */
static void
insert_conditional_skip(void *drcontext, instrlist_t *ilist, instr_t *where,
                        reg_id_t reg_skip_if_zero, instr_t *skip_label)
{
    MINSERT(ilist, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_reg(reg_skip_if_zero),
                             OPND_CREATE_INT(0)));

    MINSERT(ilist, where,
            instr_set_predicate(
                XINST_CREATE_jump(drcontext, opnd_create_instr(skip_label)), DR_PRED_EQ));
}

/**
 * Inserts instructions to save reg_param's 
 * real and taint values. Stores taint value
 * to reg_scratch register
 */
static void
insert_write_reg_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                      reg_id_t reg_param, reg_id_t reg_tls, reg_id_t reg_scratch)
{
    DR_ASSERT(reg_param - DR_REG_R0 < DR_NUM_GPR_REGS);
    uint32_t offs_value = offsetof(per_thread_t, dr[reg_param - DR_REG_R0].value);
    uint32_t offs_taint = offsetof(per_thread_t, dr[reg_param - DR_REG_R0].taint);

    // copy to reserved reg, because store
    // operation directly from reg_param may fault
    MINSERT(ilist, where,
            XINST_CREATE_move(drcontext, /* mov reg_scratch, reg_param */
                              opnd_create_reg(reg_scratch),
                              opnd_create_reg(reg_param)));

    // store register value
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str reg_param, [reg_tls, #offs_value] */
                               OPND_CREATE_MEM32(reg_tls, offs_value),
                               opnd_create_reg(reg_scratch)));

    // store register taint value
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg_param, reg_scratch);

    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str reg_scratch, [reg_tls, #offs_taint] */
                               OPND_CREATE_MEM32(reg_tls, offs_taint),
                               opnd_create_reg(reg_scratch)));
}

static void
insert_write_null_mem_entry(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t reg_tls, reg_id_t reg_scratch, int idx)
{
    DR_ASSERT(idx < DR_NUM_GPR_REGS);
    uint32_t offs_addr = offsetof(per_thread_t, dm[idx].addr);
    uint32_t offs_value = offsetof(per_thread_t, dm[idx].value);
    uint32_t offs_taint = offsetof(per_thread_t, dm[idx].taint);

    MINSERT(ilist, where,
            XINST_CREATE_move(drcontext, /* mov scratch_reg, #0 */
                              opnd_create_reg(reg_scratch),
                              OPND_CREATE_INT32(0)));

    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str scratch_reg, [reg_tls, #offs_addr] */
                               OPND_CREATE_MEM32(reg_tls, offs_addr),
                               opnd_create_reg(reg_scratch)));

    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str scratch_reg, [reg_tls, #offs_value] */
                               OPND_CREATE_MEM32(reg_tls, offs_value),
                               opnd_create_reg(reg_scratch)));
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str scratch_reg, [reg_tls, #offs_taint] */
                               OPND_CREATE_MEM32(reg_tls, offs_taint),
                               opnd_create_reg(reg_scratch)));
}

/**
 * Inserts instructions to save mem's 
 * address, real and taint values. 
 */
static void
insert_write_mem_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                      opnd_t mem, reg_id_t reg_tls, int idx, uint8_t add)
{
    DR_ASSERT(idx < DR_NUM_GPR_REGS);
    uint32_t offs_addr = offsetof(per_thread_t, dm[idx].addr);
    uint32_t offs_taint = offsetof(per_thread_t, dm[idx].taint);

    // get the memory address at mem and store the result to sreg1 register
    auto sreg1 = drreg_reservation{drcontext, ilist, where};
    auto sreg2 = drreg_reservation{drcontext, ilist, where};
    drutil_insert_get_mem_addr(drcontext, ilist, where, mem, sreg1, sreg2);

    // if need, add an offset
    if (add != 0)
    {
        MINSERT(ilist, where,
                XINST_CREATE_add_2src(drcontext,
                                      opnd_create_reg(sreg1),
                                      opnd_create_reg(sreg1),
                                      OPND_CREATE_INT8(add)));
    }

    // store mem address
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str sreg1, [reg_tls, #offs_addr] */
                               OPND_CREATE_MEM32(reg_tls, offs_addr),
                               opnd_create_reg(sreg1)));

    // store address taint:
    // first load taint value to sreg1, then store to per_thread_t
    drtaint_insert_app_to_taint(drcontext, ilist, where, sreg1, sreg2);

    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, /* ldr sreg1, [sreg1, #0] */
                              opnd_create_reg(sreg1),
                              OPND_CREATE_MEM32(sreg1, 0)));

    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, /* str sreg1, [reg_tls, #offs_taint] */
                               OPND_CREATE_MEM32(reg_tls, offs_taint),
                               opnd_create_reg(sreg1)));

    // set null terminator
    insert_write_null_mem_entry(drcontext, ilist, where, reg_tls, sreg1, idx + 1);
}

static void
insert_handle_tainted_srcs(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t reg_tls, reg_id_t reg_result)
{
    int n = instr_num_srcs(where);
    int mem_opnd_cnt = 0;
    if (n == 0)
        return;

    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_src(where, i);
        if (opnd_is_reg(opnd))
        {
            reg_id_t param_reg = opnd_get_reg(opnd);
            auto scratch_reg = drreg_reservation{drcontext, ilist, where};

            // write info about register
            insert_write_reg_info(drcontext, ilist, where, param_reg, reg_tls, scratch_reg);

            // update taint status
            MINSERT(ilist, where,
                    INSTR_CREATE_orr(drcontext,
                                     opnd_create_reg(reg_result),
                                     opnd_create_reg(reg_result),
                                     opnd_create_reg(scratch_reg)));
        }

        else if (opnd_is_base_disp(opnd))
        {
            // write info about mem
            insert_write_mem_info(drcontext, ilist, where, opnd, reg_tls, mem_opnd_cnt);
            mem_opnd_cnt++;
        }
    }
}

static void
insert_handle_tainted_dsts(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t reg_tls, reg_id_t reg_result)
{
    int n = instr_num_dsts(where);
    int mem_opnd_cnt = 0;
    if (n == 0)
        return;

    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_dst(where, i);
        if (opnd_is_reg(opnd))
        {
            reg_id_t param_reg = opnd_get_reg(opnd);
            auto scratch_reg = drreg_reservation{drcontext, ilist, where};

            // write info about register
            insert_write_reg_info(drcontext, ilist, where, param_reg, reg_tls, scratch_reg);

            // update taint status
            MINSERT(ilist, where,
                    INSTR_CREATE_orr(drcontext,
                                     opnd_create_reg(reg_result),
                                     opnd_create_reg(reg_result),
                                     opnd_create_reg(scratch_reg)));
        }

        else if (opnd_is_base_disp(opnd))
        {
            // write info about mem
            insert_write_mem_info(drcontext, ilist, where, opnd, reg_tls, mem_opnd_cnt);
            mem_opnd_cnt++;
        }
    }
}

// #TODO: insert_conditional_skip

static void
insert_handle_tainted_operands(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    auto reg_result = drreg_reservation{drcontext, ilist, where};
    auto reg_tls = drreg_reservation{drcontext, ilist, where};

    // read thread local storage field to reg_tls
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_tls);

    // denote that there's no tainted mem opnds
    // additionally assign 0 to reg_result
    insert_write_null_mem_entry(drcontext, ilist, where, reg_tls, reg_result, 0);

    // save info about tainted~ operands
    insert_handle_tainted_srcs(drcontext, ilist, where, reg_tls, reg_result);
    insert_handle_tainted_dsts(drcontext, ilist, where, reg_tls, reg_result);

    dr_insert_clean_call(drcontext, ilist, where, (void *)record_tainted_instr, false, 2,
                         OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                         opnd_create_reg(reg_result));
}

/*static void
insert_handle_tainted_operands(void *drcontext, instrlist_t *ilist, instr_t *where)
{    
    auto reg_result = drreg_reservation{drcontext, ilist, where};
    auto reg_tls = drreg_reservation{drcontext, ilist, where};
    instr_t *after_call = INSTR_CREATE_label(drcontext);
    reg_id_t reg_saved_flags = reg_tls;

    // read thread local storage field to reg_tls
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_tls);

    // denote that there's no tainted mem opnds
    // additionally assign 0 to reg_result
    insert_write_null_mem_entry(drcontext, ilist, where, reg_tls, reg_result, 0);

    // save info about tainted operands
    insert_handle_tainted_srcs(drcontext, ilist, where, reg_tls, reg_result);
    //insert_handle_tainted_dsts(drcontext, ilist, where, reg_tls, reg_result);

    // save flags before cmp-jmp
    dr_save_arith_flags_to_reg(drcontext, ilist, where, reg_saved_flags);

    // skip call if no taint info
    insert_conditional_skip(drcontext, ilist, where, reg_result, after_call);

    dr_insert_clean_call(drcontext, ilist, where, (void *)record_tainted_instr, false, 1,
                         OPND_CREATE_INTPTR(instr_get_app_pc(where)));

    MINSERT(ilist, where, after_call);

    // restore flags after cmp-jmp
    dr_restore_arith_flags_from_reg(drcontext, ilist, where, reg_saved_flags);
}*/

#pragma endregion handle_tainted

#pragma region main_and_events

static void
get_instr_taint_info(void *drcontext, app_pc pc,
                     bool *is_visited, bool *is_tainted)
{
    bool ok;
    uint8_t taint_val = 0;

    ok = drtaint_get_app_taint(drcontext, pc, &taint_val);
    DR_ASSERT(ok);

    *is_visited = IS_TAINTED(taint_val, TAG_VISITED);
    *is_tainted = IS_TAINTED(taint_val, TAG_TAINTED);
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
         bool for_trace, bool translating, void *user_data)
{
    if (instr_is_meta(where))
        return DR_EMIT_DEFAULT;

    int opcode = instr_get_opcode(where);

    // no simd instructions supported
    if (opcode >= 315)
        return DR_EMIT_DEFAULT;

    // no coproc instructions supported
    if (opcode >= OP_mcr && opcode <= OP_mcrr2)
        return DR_EMIT_DEFAULT;
    if (opcode >= OP_mrc && opcode <= OP_mrrc2)
        return DR_EMIT_DEFAULT;
    if (opcode == OP_cdp || opcode == OP_cdp2)
        return DR_EMIT_DEFAULT;
    if (opcode >= OP_ldc && opcode <= OP_ldcl)
        return DR_EMIT_DEFAULT;
    if (opcode >= OP_stc && opcode <= OP_stcl)
        return DR_EMIT_DEFAULT;

    bool visited = true, tainted = true;
    app_pc pc = instr_get_app_pc(where);
    get_instr_taint_info(drcontext, pc, &visited, &tainted);

    if (!visited)
    {
        // disassemble to buffer
        drtaint_set_app_taint(drcontext, pc, TAG_VISITED);

        //if (drmgr_is_first_instr(drcontext, where))
        //    dr_printf("\n\n[tag=%08x]\n\n", tag);
        //
        //instr_disassemble(drcontext, where, STDOUT);
        //dr_printf("\n");
    }

    if (!tainted)
    {
        // get info about operands and
        // mark instruction tainted
        // if its operands are tainted
        insert_handle_tainted_operands(drcontext, ilist, where);
    }

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    bool ok;
    ok = drtaint_init(id);
    DR_ASSERT(ok);

    // init before drtaint
    drmgr_priority_t init_pri = {
        sizeof(init_pri), "drmarker.init", DRMGR_PRIORITY_NAME_DRTAINT_INIT, NULL,
        DRMGR_PRIORITY_THREAD_INIT_DRTAINT};

    // exit before drtaint
    drmgr_priority_t exit_pri = {
        sizeof(exit_pri), "drmarker.exit", DRMGR_PRIORITY_NAME_DRTAINT_EXIT, NULL,
        DRMGR_PRIORITY_THREAD_EXIT_DRTAINT};

    // we want to add our instrumentation before drtaint's one
    drmgr_priority_t instru_pri = {
        sizeof(instru_pri), "drmarker.pc", DRMGR_PRIORITY_NAME_DRTAINT, NULL,
        DRMGR_PRIORITY_INSERT_DRTAINT};

    ok = drmgr_init();
    DR_ASSERT(ok);

    ok = drmgr_register_thread_init_event_ex(event_thread_init, &init_pri) &&
         drmgr_register_thread_exit_event_ex(event_thread_exit, &exit_pri) &&
         drmgr_register_bb_instrumentation_event(NULL, event_bb, &instru_pri);
    DR_ASSERT(ok);

    // initialize tls for per-thread data
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    // init drreg extension
    drreg_options_t drreg_opts = {sizeof(drreg_opts), 3, false};
    auto drreg_ret = drreg_init(&drreg_opts);
    DR_ASSERT(drreg_ret == DRREG_SUCCESS);

    // initialize syscall filtering
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);

    disassemble_set_syntax(DR_DISASM_ARM);
    dr_register_exit_event(exit_event);

    dr_printf("\n----- DrMarker is running -----\n\n");
}

static void
exit_event(void)
{
    drmgr_unregister_tls_field(tls_index);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    drmgr_exit();

    drtaint_exit();
    drreg_exit();

    dr_printf("\n----- DrMarker is exitting -----\n\n");
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

#pragma endregion main_and_events

#pragma region syscalls

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_read)
    {
        int fd = (int)dr_syscall_get_param(drcontext, 0);
        if (fd == STDIN)
        {
            char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
            uint len = dr_syscall_get_param(drcontext, 2);
            byte res = 0;
            
            drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, TAG_TAINTED);

            dr_printf("Tainted buffer:");
            for (uint i = 0; i < len; i++)
            {
                if (i % 30 == 0)
                    dr_printf("\n");

                drtaint_get_app_taint(drcontext, (byte*)buffer, &res);
                dr_printf("0x%02X (0x%02X) ", buffer[i], res);
            }
            dr_printf("\n");
        }
    }

    if (sysnum == SYS_write)
    {
        int fd = (int)dr_syscall_get_param(drcontext, 0);
        if (fd == STDOUT)
        {
            char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
            uint len = dr_syscall_get_param(drcontext, 2);
            byte res = 0;

            dr_printf("Buffer:");
            for (uint i = 0; i < len; i++)
            {
                if (i % 30 == 0)
                    dr_printf("\n");

                drtaint_get_app_taint(drcontext, (byte*)buffer, &res);
                dr_printf("0x%02X (0x%02X) ", buffer[i], res);
            }
            dr_printf("\n");
        }
    }

    return true;
}


#pragma endregion syscalls