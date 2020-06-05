#include "dr_api.h"
#include "drmgr.h"
#include "drfuzz.h"
#include <stdint.h>

#include "drtaint.h"
#include "drreg.h"

#include "taint_checking.h"

#include "communication.h"
#include "taint_map.h"
// #include "mrc_map.h"
#include <string.h>

#define TARGET_FUNCTION "target"

struct user_data_t
{
    uint32_t num_arg_buf;
    uint32_t num_arg_len;

    char *target_buf;
    uint32_t target_buf_length;
};

// static int tls_index;

#pragma region prototypes

static void
exit_event(void);

// static void
// event_thread_init(void *drcontext);

// static void
// event_thread_exit(void *drcontext);

#pragma endregion prototypes

// #define MAX_MUTATION_CNT 10000
#define MAX_MUTATION_CNT 1
#define NO_TESTCASES_CNT 10

int g_init = false;
char *g_target_buf = NULL;
uint32_t g_target_buf_len = 64;
uint32_t g_num_mutations = 0;
uint32_t g_num_no_testcases = 0;
static drfuzz_mutator_t *mutator = NULL;

static void
fault_event(void *fuzzcxt, drfuzz_fault_t *fault, drfuzz_fault_ex_t *fault_ex)
{
    drfuzz_target_frame_t *target_frame;
    drfuzz_target_iterator_t *iter = drfuzz_target_iterator_start(fuzzcxt);

    char filename[30] = {0};
    dr_snprintf(filename, sizeof(filename), "crash.bin");
    file_t f = dr_open_file(filename, DR_FILE_WRITE_OVERWRITE);

    dr_fprintf(f, "Trace:\n");
    while ((target_frame = drfuzz_target_iterator_next(iter)) != NULL)
    {
        uint32_t i;
        dr_fprintf(f, "Function: %08X; Args: ",
                   (ptr_uint_t)target_frame->func_pc);

        for (i = 0; i < target_frame->arg_count; i++)
        {
            dr_fprintf(f, PIFX, target_frame->arg_values[i]);
            if (i < (target_frame->arg_count - 1))
                dr_fprintf(f, ", ");
        }
        dr_fprintf(f, "\n");
    }
    drfuzz_target_iterator_stop(iter);

    dr_fprintf(f, "\nContext:\n");
    dr_mcontext_t *mc = fault_ex->mcontext;
    dr_fprintf(f, "r0\t0x%08x\n", mc->r0);
    dr_fprintf(f, "r1\t0x%08x\n", mc->r1);
    dr_fprintf(f, "r2\t0x%08x\n", mc->r2);
    dr_fprintf(f, "r3\t0x%08x\n", mc->r3);
    dr_fprintf(f, "r4\t0x%08x\n", mc->r4);
    dr_fprintf(f, "r5\t0x%08x\n", mc->r5);
    dr_fprintf(f, "r6\t0x%08x\n", mc->r6);
    dr_fprintf(f, "r7\t0x%08x\n", mc->r7);
    dr_fprintf(f, "r8\t0x%08x\n", mc->r8);
    dr_fprintf(f, "r9\t0x%08x\n", mc->r9);
    dr_fprintf(f, "r10\t0x%08x\n", mc->r10);
    dr_fprintf(f, "r11\t0x%08x\n", mc->r11);
    dr_fprintf(f, "r12\t0x%08x\n", mc->r12);
    dr_fprintf(f, "pc\t0x%08x\n", mc->pc);
    dr_fprintf(f, "sp\t0x%08x\n", mc->sp);
    dr_fprintf(f, "lr\t0x%08x\n", mc->lr);

    dr_fprintf(f, "\nInput:\n");
    for (uint32_t i = 0; i < g_target_buf_len; i++)
        dr_fprintf(f, "%02X", g_target_buf[i]);

    dr_fprintf(f, "\n");
    dr_close_file(f);
}

static void reset_taint(char *buf, uint32_t len)
{
    void *drcontext = dr_get_current_drcontext();
    for (int i = 0; i < len; i++)
    {
        int j = (i % 255) + 1;
        drtaint_set_app_taint(drcontext, (byte *)&buf[i], j);
    }

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
    uint32_t taint;
    opnd_t opnd;
    int opcode = instr_get_opcode(instr);

    // instr_disassemble(drcontext, instr, STDOUT);
    // dr_printf("tainted instr -- \n");

    switch (opcode)
    {
    // General cmp
    case OP_cmp:
    case OP_cmn:
    case OP_teq:
    case OP_tst:

        if (instr_num_srcs(instr) == 1)
        {
            opnd = instr_get_src(instr, 0);
            drtaint_get_reg_taint(drcontext, opnd_get_reg(opnd), &taint);
        }
        else // must be 2
        {
            opnd = instr_get_src(instr, 0);
            drtaint_get_reg_taint(drcontext, opnd_get_reg(opnd), &taint);

            if (taint == 0)
            {
                opnd = instr_get_src(instr, 1);
                drtaint_get_reg_taint(drcontext, opnd_get_reg(opnd), &taint);
            }
        }
        break;

    // Compare and jump
    case OP_cbz:
    case OP_cbnz:

        opnd = instr_get_src(instr, 1);
        drtaint_get_reg_taint(drcontext, opnd_get_reg(opnd), &taint);
        break;

    // Affect flags
    case OP_adcs:
    case OP_adds:
    case OP_ands:
    case OP_asrs:
    case OP_bics:
    case OP_eors:
    case OP_lsls:
    case OP_lsrs:
    case OP_mlas:
    case OP_movs:
    case OP_muls:
    case OP_mvns:
    case OP_orrs:
    case OP_orns:
    case OP_rors:
    case OP_rrxs:
    case OP_rsbs:
    case OP_rscs:
    case OP_smlals:
    case OP_smulls:
    case OP_subs:
    case OP_umlals:
    case OP_umulls:

        // dr_printf("dsts = %d\n", instr_num_dsts(instr));
        opnd = instr_get_dst(instr, 0);
        drtaint_get_reg_taint(drcontext, opnd_get_reg(opnd), &taint);
        break;
    }

    DR_ASSERT(taint != 0);
    if (!tmap_has(instr, taint))
    {
        uint32_t pc = (uint32_t)instr_get_app_pc(instr);
        dr_isa_mode_t mode = dr_get_isa_mode(drcontext);

        if (mode == DR_ISA_ARM_THUMB)
            pc += 1;

        cmn_send_solve_request(g_target_buf, g_target_buf_len, taint, 0, pc);
        tmap_emplace(instr, taint);
    }
}

inline static bool
instr_affects_flags(int opcode)
{
    switch (opcode)
    {
    // General cmp
    case OP_cmp:
    case OP_cmn:
    case OP_teq:
    case OP_tst:

    // Compare and jump
    case OP_cbz:
    case OP_cbnz:

    // Affect flags
    case OP_adcs:
    case OP_adds:
    case OP_ands:
    case OP_asrs:
    case OP_bics:
    case OP_eors:
    case OP_lsls:
    case OP_lsrs:
    case OP_mlas:
    case OP_movs:
    case OP_muls:
    case OP_mvns:
    case OP_orrs:
    case OP_orns:
    case OP_rors:
    case OP_rrxs:
    case OP_rsbs:
    case OP_rscs:
    case OP_smlals:
    case OP_smulls:
    case OP_subs:
    case OP_umlals:
    case OP_umulls:
        return true;
    }

    return false;
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
         bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(where))
        return DR_EMIT_DEFAULT;

    // if (mrc_reads_coproc(where))
    // {
    //     mrc_insert_save_arm_reg(drcontext, ilist, where);
    //     return DR_EMIT_DEFAULT;
    // }

    if (!instr_affects_flags(instr_get_opcode(where)))
        return DR_EMIT_DEFAULT;

    tc_perform_instrumentation(drcontext, ilist, where);
    return DR_EMIT_DEFAULT;
}

static void
setup_mutator(drfuzz_mutator_t **mut, char *seed, uint32_t size)
{
    const char *argv[] = {"-alg", "random", "-unit", "bits", "-flags", "1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    if (*mut != NULL)
    {
        drfuzz_mutator_stop(*mut);
        *mut = NULL;
    }

    drmf_status_t status = drfuzz_mutator_start(mut, seed, size, argc, argv);
    DR_ASSERT(status == DRMF_SUCCESS);
}

static void
pre_fuzz_cb(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    if (g_init == true)
    {
        drmf_status_t status;
        if (g_num_mutations == 0)
        {
            bool res = cmn_send_next_tc_request(g_target_buf, g_target_buf_len);
            dr_printf("End of fuzzing cycle\n");

            if (res == true)
            {
                g_num_no_testcases = 0;
                setup_mutator(&mutator, g_target_buf, g_target_buf_len);
                dr_printf("Got new testcase! Begin new cycle\n");
            }
            else
            {
                dr_printf("No more testcases. Continue with previous one\n");
                g_num_mutations = MAX_MUTATION_CNT;
                g_num_no_testcases++;

                dr_sleep(5000);
                status = drfuzz_mutator_get_next_value(mutator, g_target_buf);
                DR_ASSERT(status == DRMF_SUCCESS);
            }
        }
        else
        {
            dr_sleep(3000);
            g_num_mutations--;
            status = drfuzz_mutator_get_next_value(mutator, g_target_buf);
            DR_ASSERT(status == DRMF_SUCCESS);
        }

        reset_taint(g_target_buf, g_target_buf_len);
    }
    else
    {
        char *buf;
        drmf_status_t status;
        dr_printf("Loading binary\n");

        // mrc_clear();
        status = drfuzz_get_arg(fuzzcxt, target_pc, 0, false, (void **)&buf);
        DR_ASSERT(status == DRMF_SUCCESS);
        g_target_buf = buf;

        dr_isa_mode_t mode = dr_get_isa_mode(drfuzz_get_drcontext(fuzzcxt));
        ptr_uint_t target_pc_ = (ptr_uint_t)target_pc;

        if (mode == DR_ISA_ARM_THUMB)
            target_pc_ += 1;

        g_init = cmn_send_load_request(
            mc, target_pc_, g_target_buf_len);

        g_num_no_testcases = 0;
        setup_mutator(&mutator, g_target_buf, g_target_buf_len);
    }
}

static bool
post_fuzz_cb(void *fuzzcxt, generic_func_t target_pc)
{
    return g_init == true && g_num_no_testcases < NO_TESTCASES_CNT;
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
    status = drfuzz_fuzz_target(target, 2, 0, DRWRAP_CALLCONV_DEFAULT,
                                pre_fuzz_cb, post_fuzz_cb);
    DR_ASSERT(status == DRMF_SUCCESS);

    status = drfuzz_register_fault_event(fault_event);
    DR_ASSERT(status == DRMF_SUCCESS);

    tmap_load();

    dr_printf("\ntarget = %p\n", target);
    dr_printf("\n----- drtaint fuzzer is running -----\n\n");
}

static void
exit_event()
{
    dr_printf("\n----- drtaint fuzzer is exitting -----\n\n");

    // drmgr_unregister_thread_init_event(event_thread_init);
    // drmgr_unregister_thread_exit_event(event_thread_exit);
    // drmgr_unregister_tls_field(tls_index);

    tmap_dump();
    dr_sleep(1000);
    if (mutator != NULL)
    {
        drfuzz_mutator_stop(mutator);
        mutator = NULL;
    }

    drfuzz_unregister_fault_event(fault_event);
    drfuzz_exit();
    drreg_exit();
    drmgr_exit();
    drtaint_exit();
}

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