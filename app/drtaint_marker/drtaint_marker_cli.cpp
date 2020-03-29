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

#include <map>
#include <vector>

#define IS_TAINTED(val, tag) ((val) & (tag))
#define TAG_TAINTED 0x02

#define MINSERT instrlist_meta_preinsert
#define MINSERT_xl8 instrlist_meta_preinsert_xl8

static int tls_index;

#pragma region structs

// must be 1-byte
#define OPND_NONE 0x00
#define OPND_REG 0x10
#define OPND_MEM 0x20

using u32 = unsigned int;
using u8 = unsigned char;

struct buffer_t
{
    char *ptr;
    int len;
};

enum class opnd_type
{
    unknown,
    reg,
    addr,
};

struct opnd_taint_info_t
{
    opnd_type type = opnd_type::unknown;
    union {
        reg_id_t reg_num;
        u32 address;
    };

    u32 value = 0;
    u32 taint = 0;
};

struct instr_taint_info_t
{
    u32 hit_count = 0;
    std::vector<opnd_taint_info_t> operands;
};

using taint_info_t = std::map<app_pc, instr_taint_info_t>;

struct per_thread_t
{
    /*
    * We will store there buffer
    * that will be saved in pre_syscall event
    */
    buffer_t syscall_buf;

    taint_info_t *tainted_instrs;
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
event_post_syscall(void *drcontext, int sysnum);

/** 
 * Function passed to dr_insert_clean_call routine
 * when handling tainted instructions
 */
//static void
//clean_call_cb(app_pc pc, void *);

static void
perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc);

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static void
dump_tainted_instrs(void *drcontext, const taint_info_t &tmap);

#pragma endregion func_prototypes

#pragma region clean_call

static void
get_taint_info(void *drcontext, app_pc pc, taint_info_t *info)
{
    auto instr = instr_decoded(drcontext, pc);
    auto it = info->find(pc);

    if (it != info->end())
        it->second.hit_count++;
    else
    {
        instr_taint_info_t instr_info;
        info->emplace(pc, instr_info);
    }
}

static void
clean_call_cb(app_pc pc, unsigned x)
{
    //if (res == 0) 
    //    return;

    void *drcontext = dr_get_current_drcontext();
    auto instr = instr_decoded{drcontext, pc};

    DR_ASSERT(x > 0 && x < 10);

    //instr_disassemble(drcontext,instr, STDOUT);
    //dr_printf("\nClean call x = %d\n", x);

    //void *drcontext = dr_get_current_drcontext();
    //per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    //get_taint_info(drcontext, pc, tls->tainted_instrs);
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

static void
insert_check_mem_tainted(void *drcontext, instrlist_t *ilist, instr_t *where,
                         opnd_t mem, reg_id_t reg_taint, byte offset)

{
    auto sreg1 = drreg_reservation{drcontext, ilist, where};
    auto sreg2 = drreg_reservation{drcontext, ilist, where};

    // get the memory address at mem and store the result to sreg1 register
    drutil_insert_get_mem_addr(drcontext, ilist, where, mem, sreg1, sreg2);

    // if need, add an offset
    if (offset != 0)
    {
        MINSERT(ilist, where,
                XINST_CREATE_add_2src(drcontext,
                                      opnd_create_reg(sreg1),
                                      opnd_create_reg(sreg1),
                                      OPND_CREATE_INT(offset)));
    }

    // Convert sreg1 address to it's taint address
    drtaint_insert_app_to_taint(drcontext, ilist, where, sreg1, sreg2);
    sreg2.unreserve();

    instr_disassemble(drcontext, where, STDOUT);
    dr_printf("sz = %d\n", opnd_size_in_bytes(opnd_get_size(mem)));

    int opcode = instr_get_opcode(where);

    if (opcode == OP_ldrb)
    {

        // ldrXX sreg1, [sreg1, #0]
        opnd_size_t opsz = opnd_get_size(mem);
        opnd_t opnd_mem_taint = opnd_create_base_disp(sreg1, DR_REG_NULL, 0, 0, opsz);

        MINSERT(ilist, where,
                instr_create_1dst_1src(drcontext, opcode,
                    opnd_create_reg(sreg1), opnd_mem_taint));
    }

    //// update taint status
    //MINSERT(ilist, where,
    //        INSTR_CREATE_orr(drcontext,
    //                         opnd_create_reg(reg_taint),
    //                         opnd_create_reg(reg_taint),
    //                         opnd_create_reg(sreg1)));
}

static void
insert_handle_tainted_srcs(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t reg_taint)
{
    int opcode = instr_get_opcode(where);
    int n = instr_num_srcs(where);

    if (opcode >= OP_ldmia && opcode <= OP_ldmib)
        return;

    for (int i = 0; i < n; i++)
    {
        opnd_t opnd = instr_get_src(where, i);
        if (opnd_is_reg(opnd))
        {
            reg_id_t param_reg = opnd_get_reg(opnd);

            insert_check_reg_tainted(drcontext, ilist, where,
                                     param_reg, reg_taint);
        }

        else if (opnd_is_base_disp(opnd))
        {
            //insert_check_mem_tainted(drcontext, ilist, where, opnd, reg_taint, 0);

            if (opcode == OP_ldrd || opcode == OP_ldrexd)
            {
                //insert_check_mem_tainted(drcontext, ilist, where,
                //                         opnd, reg_taint, 4);
            }
        }
    }
}

static void
perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc)
{
    auto reg_result = drreg_reservation{drcontext, ilist, where};
    auto reg_flags = drreg_reservation{drcontext, ilist, where};

    dr_pred_type_t pred = instrlist_get_auto_predicate(ilist);
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);

    // place constant
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_move(drcontext, // mov simm2, 0
                                               opnd_create_reg(reg_result),
                                               OPND_CREATE_INT(0)));

    instrlist_set_auto_predicate(ilist, pred);


    unsigned x = dr_get_random_value(10);
    DR_ASSERT(x >= 0 && x < 10);
    //dr_printf("Generated x = %d\n", x);

    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_move(drcontext, // mov simm2, 0
                                               opnd_create_reg(reg_result),
                                               OPND_CREATE_INT(x)));

    //insert_handle_tainted_srcs(drcontext, ilist, where, reg_result);

    pred = instrlist_get_auto_predicate(ilist);
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);

    instr_t *skip = INSTR_CREATE_label(drcontext);
    //dr_pred_type_t pred = instrlist_get_auto_predicate(ilist);
    //instrlist_set_auto_predicate(ilist, DR_PRED_NONE);

    dr_save_arith_flags_to_reg(drcontext, ilist, where, reg_flags);
    
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_result), OPND_CREATE_INT32(0)));
    MINSERT(ilist, where,
            XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(skip)));
    

    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_cb, false, 2,
                         OPND_CREATE_INTPTR(pc), opnd_create_reg(reg_result));

    MINSERT(ilist, where, skip);
    dr_restore_arith_flags_from_reg(drcontext, ilist, where, reg_flags);
    instrlist_set_auto_predicate(ilist, pred);
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

    // do not need tainted instructions
    app_pc pc = instr_get_app_pc(where);
    if (tls->tainted_instrs->find(pc) != tls->tainted_instrs->end())
        return DR_EMIT_DEFAULT;

    perform_instrumentation(drcontext, ilist, where, pc);
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
    dump_tainted_instrs(drcontext, *data->tainted_instrs);

    delete data->tainted_instrs;
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
dump_tainted_instrs(void *drcontext, const taint_info_t &tmap)
{
    for (const auto &elem : tmap)
    {
        app_pc pc = elem.first;
        auto instr = instr_decoded(drcontext, pc);

        dr_printf("0x%08X:  ", pc);
        int length = instr_length(drcontext, instr);
        if (length == 2)
        {
            dr_printf("\\x%02X\\x%02X          ",
                      instr_get_raw_byte(instr, 0),
                      instr_get_raw_byte(instr, 1));
        }
        else
        {
            dr_printf("\\x%02X\\x%02X\\x%02X\\x%02X  ",
                      instr_get_raw_byte(instr, 0),
                      instr_get_raw_byte(instr, 1),
                      instr_get_raw_byte(instr, 2),
                      instr_get_raw_byte(instr, 3));
        }

        instr_disassemble(drcontext, instr, STDOUT);
        dr_printf("\n");
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

/*
dr_pred_type_t pred = instrlist_get_auto_predicate(ilist);
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);

    auto reg1 = drreg_reservation(drcontext, ilist, where);
    auto reg2 = drreg_reservation(drcontext, ilist, where);
    instr_t* skip =  INSTR_CREATE_label(drcontext);

    dr_save_arith_flags_to_reg(drcontext, ilist, where, reg2);

    MINSERT(ilist, where,
            XINST_CREATE_move(drcontext, opnd_create_reg(reg1), OPND_CREATE_INT32(1)));
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg1), OPND_CREATE_INT32(0)));
    MINSERT(ilist, where,

            XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(skip)));
    
    dr_insert_clean_call(drcontext, ilist, where, (void*)callee, false, 1, opnd_create_reg(reg1));

    MINSERT(ilist, where, skip);
    dr_restore_arith_flags_from_reg(drcontext, ilist, where, reg2);
    instrlist_set_auto_predicate(ilist, pred);
*/