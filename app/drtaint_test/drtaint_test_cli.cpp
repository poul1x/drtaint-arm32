#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "../../core/include/drtaint.h"
#include <syscall.h>
#include <string.h>

/*
 *    drtaint_test is a client library testing drtaint capabilities.
 *    It can make tainted a region of memory and trace distribution of tainted fragments
 *
 *    To make memory region tainted or check this region is tainted
 *    user has to call write syscall with unused fd. Syscall will be failed but 
 *    it let this library client "hear" the user and process his requests   
 */

#define DRTAINT_SUCCESS 0xAA
#define DRTAINT_FAILURE 0xBB

#define IS_TAINTED(mem) (mem != 0)
#define TAINT_TAG 0x80

#define FD_APP_START_TRACE 0xFFFFEEEE
#define FD_APP_STOP_TRACE 0xFFFFEEED
#define FD_APP_IS_TRACED 0xFFFFEEEF

#define FD_APP_START_DISASM 0xFFFFEEBB
#define FD_APP_STOP_DISASM 0xFFFFEECC

static void
exit_event(void);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
handle_start_trace(void *drcontext);

static void
handle_stop_trace(void *drcontext);

static void
handle_check_trace(void *drcontext);

int32_t gb_disasm_on = false;

dr_emit_flags_t event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    if (gb_disasm_on)
        instrlist_disassemble(drcontext, (app_pc)tag, bb, STDERR);

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drtaint_init(id);
    drmgr_init();

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);

    drmgr_register_bb_instrumentation_event(NULL, event_bb, NULL);
    disassemble_set_syntax(DR_DISASM_ARM);

    dr_register_exit_event(exit_event);
    dr_printf("\n----- DrTaint test client is running -----\n\n");
}

static void
exit_event(void)
{
    dr_printf("\n----- DrTaint test client is exitting -----\n\n");

    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    dr_unregister_filter_syscall_event(event_filter_syscall);

    drtaint_exit();
    drmgr_exit();
    drreg_exit();
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_write)
    {
        uint fd = dr_syscall_get_param(drcontext, 0);

        switch (fd)
        {
        case FD_APP_START_TRACE:
            handle_start_trace(drcontext);
            return false;

        case FD_APP_IS_TRACED:
            handle_check_trace(drcontext);
            return false;

        case FD_APP_STOP_TRACE:
            handle_stop_trace(drcontext);
            return false;

        case FD_APP_START_DISASM:
            gb_disasm_on = true;
            dr_syscall_set_result(drcontext, DRTAINT_SUCCESS);
            return false;

        case FD_APP_STOP_DISASM:
            gb_disasm_on = false;
            dr_syscall_set_result(drcontext, DRTAINT_SUCCESS);
            return false;
        }
    }

    return true;
}

static void
handle_start_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    uint len = dr_syscall_get_param(drcontext, 2);

    // taint buffer
    drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, TAINT_TAG);
    dr_syscall_set_result(drcontext, DRTAINT_SUCCESS);
}

static void
handle_stop_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    uint len = dr_syscall_get_param(drcontext, 2);

    // untaint buffer
    drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, 0);
    dr_syscall_set_result(drcontext, DRTAINT_SUCCESS);
}

static void
handle_check_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    reg_t len = dr_syscall_get_param(drcontext, 2);
    byte result;
    bool ok;

    // check the buffer is tainted
    for (reg_t i = 0; i < len; ++i)
    {
        ok = drtaint_get_app_taint(drcontext, (app_pc)&buffer[i], &result);
        DR_ASSERT(ok);

        if (!IS_TAINTED(result))
        {
            dr_syscall_set_result(drcontext, DRTAINT_FAILURE);
            return;
        }
    }

    dr_syscall_set_result(drcontext, DRTAINT_SUCCESS);
}