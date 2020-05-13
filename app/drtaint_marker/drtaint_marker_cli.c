#include "dr_api.h"
#include "drmgr.h"
#include "drfuzz.h"
#include <stdint.h>

#include "drtaint.h"
#include "drreg.h"

#include "taint_checking.h"

#define TAG_TAINTED 0x02
#define TARGET_FUNCTION "target"
#define MAX_LEN 4

// struct per_thread_t
// {
//     int a;
// };

// static int tls_index;

#pragma region prototypes

extern int
cmn_send_load_request(dr_mcontext_t *mc, ptr_uint_t buffer_addr, ptr_uint_t target_addr);

extern int
cmn_send_solve_request(app_pc cmp_addr, uint32_t taint, const char *buf_concrete);

static void
exit_event(void);

// static void
// event_thread_init(void *drcontext);

// static void
// event_thread_exit(void *drcontext);

#pragma endregion prototypes

static void reset_taint(app_pc buf)
{
    void* drcontext = dr_get_current_drcontext();
    for (int i = 0; i<10; i++)
        drtaint_set_app_taint(drcontext, &buf[i], i + 2);

    drtaint_set_reg_taint(drcontext, DR_REG_R0, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R1, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R2, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R3, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R4, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R5, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R6, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R7, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R8, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R9, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R10, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R11, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_R12, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_SP, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_LR, 0);
    drtaint_set_reg_taint(drcontext, DR_REG_PC, 0);
}

static void
on_tainted_cmp(void *drcontext, instr_t *instr)
{
    dr_printf("On tainted cmp\n");
}

inline static bool
instr_is_cmp(int opcode)
{
    return opcode == OP_cmp || opcode == OP_cmn ||
           opcode == OP_teq || opcode == OP_tst;
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
         bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(where))
        return DR_EMIT_DEFAULT;

    if (!instr_is_cmp(instr_get_opcode(where)))
        return DR_EMIT_DEFAULT;

    // per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    // app_pc pc = instr_get_app_pc(where);
    // auto it = tls->instrs->find(pc);

    // do not add instrumentation to known tainted instructions
    // if (it == tls->instrs->end())
    tc_perform_instrumentation(drcontext, ilist, where);

    // dr_printf("Here\n");
    return DR_EMIT_DEFAULT;
}

int g_init = false;
int g_init_success = false;

static void
pre_fuzz_cb(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    app_pc buf;
    drmf_status_t status;

    status = drfuzz_get_arg(fuzzcxt, target_pc, 0, false, (void **)&buf);
    DR_ASSERT(status == DRMF_SUCCESS);

    reset_taint(buf);
    if (g_init == false)
    {
        g_init_success = cmn_send_load_request(
            mc, (ptr_uint_t)target_pc, (ptr_uint_t)buf);
    }
}

static bool
post_fuzz_cb(void *fuzzcxt, generic_func_t target_pc)
{
    return false;
}

static generic_func_t
get_target_address()
{
    module_data_t *app;
    generic_func_t addr;

    app = dr_get_main_module();
    DR_ASSERT(app != NULL);

    addr = dr_get_proc_address(app->handle, TARGET_FUNCTION);
    DR_ASSERT(addr != 0);

    dr_free_module_data(app);
    return addr;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    bool ok;
    ok = drtaint_init(id);
    DR_ASSERT(ok);

    // We want to add our instrumentation before drtaint's one
    drmgr_priority_t instru_pri = {
        sizeof(instru_pri), "drfuzzer.pc", NULL, NULL,
        DRMGR_PRIORITY_INSERT_DRTAINT + 1};

    ok = drmgr_init();
    DR_ASSERT(ok);

    // ok = drmgr_register_thread_init_event(event_thread_init) &&
    //      drmgr_register_thread_exit_event(event_thread_exit) &&
    //      drmgr_register_bb_instrumentation_event(NULL, event_bb, &instru_pri);
    ok = drmgr_register_bb_instrumentation_event(NULL, event_bb, &instru_pri);
    DR_ASSERT(ok);

    // initialize tls for per-thread data
    // tls_index = drmgr_register_tls_field();
    // DR_ASSERT(tls_index != -1);

    // init drreg extension
    drreg_options_t drreg_opts = {sizeof(drreg_opts), 3, false};
    drreg_status_t drreg_ret = drreg_init(&drreg_opts);
    DR_ASSERT(drreg_ret == DRREG_SUCCESS);

    // Add taint check and module load handlers
    tc_set_callback(on_tainted_cmp);
    dr_register_exit_event(exit_event);

    // Init fuzzer API
    drmf_status_t status = drfuzz_init(id);
    DR_ASSERT(status == DRMF_SUCCESS);

    generic_func_t target = get_target_address();
    status = drfuzz_fuzz_target(target, 1, 0, DRWRAP_CALLCONV_DEFAULT,
                                pre_fuzz_cb, post_fuzz_cb);

    dr_printf("Address = %p\n", target);

    DR_ASSERT(status == DRMF_SUCCESS);
    dr_printf("\n----- drtaint fuzzer is running -----\n\n");
}

static void
exit_event()
{
    dr_printf("\n----- drtaint fuzzer is exitting -----\n\n");

    // drmgr_unregister_thread_init_event(event_thread_init);
    // drmgr_unregister_thread_exit_event(event_thread_exit);
    // drmgr_unregister_tls_field(tls_index);

    drfuzz_exit();
    drreg_exit();
    drmgr_exit();
    drtaint_exit();
}

volatile int t = 0;

// static void
// event_thread_init(void *drcontext)
// {
//     // per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
//     // memset(data, 0, sizeof(per_thread_t));
//     // drmgr_set_tls_field(drcontext, tls_index, data);
//     int t1 = dr_atomic_add32_return_sum(&t, 1);
//     dr_printf("t1=%d\n", t1);
// }

// static void
// event_thread_exit(void *drcontext)
// {
//     per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
//     dr_thread_free(drcontext, data, sizeof(per_thread_t));
// }