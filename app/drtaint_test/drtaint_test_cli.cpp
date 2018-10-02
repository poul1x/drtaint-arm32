#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "../../core/include/drtaint.h"
#include <syscall.h>
#include <string.h>

/*
    This is a client library testing drtaint capabilities.
    It can make taint a region of memory and trace its distribution

    To make memory region tainted or check this region is tainted
    user has to call write syscall with unused fd. Syscall will be failed but 
    it let this library client "hear" the user and process his requests   
*/

//#define VERBOSE
#define DRTAINT_SUCCESS 0xAA
#define DRTAINT_FAILURE 0xBB

#define IS_TAINTED(mem) (mem != 0)
#define TAINT_TAG 0x80

#define FD_APP_START_TRACE 0xFFFFEEEE
#define FD_APP_STOP_TRACE 0xFFFFEEED
#define FD_APP_IS_TRACED 0xFFFFEEEF

static void
exit_event(void);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
set_syscall_retval(void *drcontext, bool ok);

static bool
handle_start_trace(void *drcontext);

static bool
handle_stop_trace(void *drcontext);

static bool
handle_check_trace(void *drcontext);

dr_emit_flags_t event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    instrlist_disassemble(drcontext, (app_pc)tag, bb, STDOUT);

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drtaint_init(id);
    drmgr_init();

    drreg_options_t drreg_ops = {sizeof(drreg_ops), 3, false};
    auto drreg_ret = drreg_init(&drreg_ops);
    DR_ASSERT(drreg_ret == DRREG_SUCCESS);

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    //drmgr_register_bb_instrumentation_event(NULL, event_bb, NULL);
    dr_register_exit_event(exit_event);

    disassemble_set_syntax(DR_DISASM_ARM);

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

        if (fd == FD_APP_START_TRACE)
            return handle_start_trace(drcontext);
        else if (fd == FD_APP_IS_TRACED)
            return handle_check_trace(drcontext);
        else if (fd == FD_APP_STOP_TRACE)
            return handle_stop_trace(drcontext);
        else
            return true;
    }

    return true;
}

static void
set_syscall_retval(void *drcontext, bool ok)
{
    // set a special exit code to signal
    // that data was tracked successfully or not
    dr_syscall_result_info_t info = {
        sizeof(info),
    };

    dr_syscall_get_result_ex(drcontext, &info);
    info.value = ok ? DRTAINT_SUCCESS : DRTAINT_FAILURE;
    dr_syscall_set_result_ex(drcontext, &info);
}


static bool
handle_start_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    uint len = dr_syscall_get_param(drcontext, 2);

    // taint buffer
    drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, TAINT_TAG);
    set_syscall_retval(drcontext, true);
    return false;
}

static bool
handle_stop_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    uint len = dr_syscall_get_param(drcontext, 2);
    bool ok;

    // untaint buffer
    drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, 0);
    set_syscall_retval(drcontext, true);
    return false;
}

static bool
handle_check_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    size_t len = dr_syscall_get_param(drcontext, 2);
    byte result;
    bool ok;

    // check the buffer is tainted
    for (int i = 0; i < len; ++i)
    {
        ok = drtaint_get_app_taint(drcontext, (app_pc)&buffer[i], &result);
        DR_ASSERT(ok);
        
        if (!IS_TAINTED(result))
        {
            set_syscall_retval(drcontext, false);
            return false;
        }
    }

    set_syscall_retval(drcontext, true);
    return false;
}