#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

#include "drtaint.h"
#include "drtaint_shadow.h"
#include "drtaint_helper.h"
#include "drtaint_template_utils.h"
#include "drtaint_instr_groups.h"

#include "taint_processing.h"

#include <syscall.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <map>
#include <vector>

#include <byteswap.h>

#define IS_TAINTED(val, tag) ((val) & (tag))
#define TAG_TAINTED 0x02

#define MINSERT instrlist_meta_preinsert
#define MINSERT_xl8 instrlist_meta_preinsert_xl8

static int tls_index;

// must be 1-byte
#define OPND_NONE 0x00
#define OPND_REG 0x10
#define OPND_MEM 0x20

struct buffer_t
{
    char *ptr;
    int len;
};

using taint_info_t = std::map<app_pc, tainted_instr>;

struct per_thread_t
{
    /*
    * We will store there buffer
    * that will be saved in pre_syscall event
    */
    buffer_t syscall_buf;

    taint_info_t *tainted_instrs;
};

#pragma region prototypes

static void
exit_event(void);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
event_post_syscall(void *drcontext, int sysnum);

static void
perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where);

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static void
dump_tainted_instrs(void *drcontext, const taint_info_t &tmap);

#pragma endregion prototypes

#pragma region clean_call

static void
save_taint_info(void *drcontext, app_pc pc, taint_info_t *info)
{
    auto instr = instr_decoded(drcontext, pc);
    auto it = info->find(pc);

    if (it != info->end())
        it->second.hit_count++;
    else
    {
        tainted_instr instr_info;
        instr_info.hit_count = 1;

        tainted_instr_save_bytes(drcontext, instr, &instr_info);
        tainted_instr_save_tainted_opnds(drcontext, instr, &instr_info);
        info->emplace(pc, instr_info);
    }
}

static void
clean_call_cb(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
    auto instr = instr_decoded{drcontext, pc};
    DR_ASSERT((instr_t *)instr != NULL);

    dr_printf("%08lx\t", pc);

    int length = instr_length(drcontext, instr);

    if (length == 2)
    {
        dr_printf("%04hX\n", bswap_16(*(uint16_t *)instr_get_raw_bits(instr)));
    }
    else
    {
        dr_printf("%08lX\n", bswap_32(*(uint32_t *)instr_get_raw_bits(instr)));
    }

    //instr_disassemble(drcontext, instr, STDOUT);
    //dr_printf("\n");

    per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    save_taint_info(drcontext, pc, tls->tainted_instrs);
}

#pragma endregion clean_call

#pragma region handle_tainted

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
        dr_printf("\n");
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

static void
perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where)
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

#pragma endregion handle_tainted

#pragma region main_and_events

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

    per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    app_pc pc = instr_get_app_pc(where);
    auto it = tls->tainted_instrs->find(pc);

    // do not add instrumentation to known tainted instructions
    if (it == tls->tainted_instrs->end())
        perform_instrumentation(drcontext, ilist, where);
    else
        it->second.hit_count++;

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    bool ok;
    ok = drtaint_init(id);
    DR_ASSERT(ok);

    // We want to add our instrumentation before drtaint's one
    drmgr_priority_t instru_pri = {
        sizeof(instru_pri), "drmarker.pc", NULL, NULL,
        DRMGR_PRIORITY_INSERT_DRTAINT + 1};

    ok = drmgr_init();
    DR_ASSERT(ok);

    ok = drmgr_register_thread_init_event(event_thread_init) &&
         drmgr_register_thread_exit_event(event_thread_exit) &&
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
    drmgr_register_post_syscall_event(event_post_syscall);

    disassemble_set_syntax(DR_DISASM_ARM);
    dr_register_exit_event(exit_event);

    dr_printf("\n----- drtaint marker is running -----\n\n");

    module_data_t *exe = dr_get_main_module();
    DR_ASSERT(exe != NULL);
    dr_printf("Start address: 0x%08X\n\n", exe->start);
    dr_free_module_data(exe);
}

static void
exit_event(void)
{
    drmgr_unregister_tls_field(tls_index);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    drmgr_unregister_post_syscall_event(event_post_syscall);

    drreg_exit();
    drmgr_exit();
    drtaint_exit();

    dr_printf("\n----- drtaint marker is exitting -----\n\n");
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));

    data->tainted_instrs = new taint_info_t();
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    dump_tainted_instrs(drcontext, *(data->tainted_instrs));

    delete data->tainted_instrs;
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
dump_tainted_instrs(void *drcontext, const taint_info_t &info_map)
{
    dr_printf("\n\n---------------------------------\n");
    for (const auto &elem : info_map)
    {
        app_pc address = elem.first;
        auto tainted_instr = elem.second;
        //auto instr = tainted_instr_decode(drcontext, tainted_instr);

        auto instr = instr_decoded(drcontext, address);

        //auto str = tainted_instr_bytes_str(tainted_instr);
        //dr_printf("%08lx\t%s\n", address, str.c_str());

        dr_printf("%08lx\t", address);
        int length = instr_length(drcontext, instr);

        if (length == 2)
        {
            dr_printf("%04hX\n", *(uint16_t*)instr_get_raw_bits(instr));
        }
        else
        {
            dr_printf("%08lX\n", *(uint32_t*)instr_get_raw_bits(instr));
        }

        //instr_disassemble(drcontext, instr, STDOUT);
        //dr_printf("\n");
    }
}

#pragma endregion main_and_events

#pragma region syscalls

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return sysnum == SYS_read;
}

/*
static void 
dump_buffer(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    uint len = dr_syscall_get_param(drcontext, 2);
    byte res = 0;

    dr_printf("Buffer: 0x%08X", buffer);
    for (uint i = 0; i < len; i++)
    {
        if (i % 30 == 0)
            dr_printf("\n");

        drtaint_get_app_taint(drcontext, (byte *)buffer, &res);
        dr_printf("0x%02X (0x%02X) ", buffer[i], res);
    }
    dr_printf("\n\n");
}*/

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_read)
    {
        int fd = (int)dr_syscall_get_param(drcontext, 0);
        if (fd == STDIN)
        {
            /*
             * dynamorio API does not allow to use 
             * dr_syscall_get_param in event_post_syscall,
             * so we save syscall arguments there
             */

            per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
            tls->syscall_buf.ptr = (char *)dr_syscall_get_param(drcontext, 1);
            tls->syscall_buf.len = (int)dr_syscall_get_param(drcontext, 2);

            printf("pre syscall buf %08X\n", (unsigned)tls->syscall_buf.ptr);
            printf("pre syscall len %08X\n", (unsigned)tls->syscall_buf.len);
        }
    }

    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_read)
    {
        per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);

        if (tls->syscall_buf.ptr != NULL)
        {
            dr_printf("post syscall buf %08X\n", (unsigned)tls->syscall_buf.ptr);
            dr_printf("post syscall len %08X\n", (unsigned)tls->syscall_buf.len);
            drtaint_set_app_area_taint(drcontext, (app_pc)tls->syscall_buf.ptr,
                                       tls->syscall_buf.len, TAG_TAINTED);

            tls->syscall_buf.ptr = NULL;
            tls->syscall_buf.len = 0;
        }
    }
}

#pragma endregion syscalls