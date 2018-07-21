#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drvector.h"

#include "../drtaint.h"
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
#define TAINT_TAG 0x45

#define FD_APP_START_TRACE 0xFFFFEEEE
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
handle_check_trace(void *drcontext);

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

        if (fd == FD_APP_START_TRACE)
            return handle_start_trace(drcontext);
        else if (fd == FD_APP_IS_TRACED)
            return handle_check_trace(drcontext);
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

#ifdef VERBOSE

static bool
handle_start_trace(void *drcontext)
{
    // get arguments of read syscall
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    size_t len = dr_syscall_get_param(drcontext, 2);

    dr_printf("Making tainted buffer: ");

    // taint buffer
    for (int i = 0; i < len; ++i)
    {
        DR_ASSERT_MSG(
            drtaint_set_app_taint(drcontext, (app_pc)&buffer[i], TAINT_TAG),
            "Unable to set app tainted");

        dr_printf("%c", buffer[i]);
    }

    dr_printf("\n\n");
    return false;
}

static bool
handle_check_trace(void *drcontext)
{
    // get arguments of write syscall
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    size_t len = dr_syscall_get_param(drcontext, 2);
    byte result;

    dr_printf("Check buffer is tainted: ");

    // check the buffer is tainted
    for (int i = 0; i < len; ++i)
    {
        dr_printf("%c", buffer[i]);

        if (!drtaint_get_app_taint(drcontext, (app_pc)&buffer[i], &result) ||
            !IS_TAINTED(result))
        {
            set_syscall_retval(drcontext, false);
            dr_printf("\n\n");
            return false;
        }
    }

    set_syscall_retval(drcontext, true);
    dr_printf("\n\n");
    return false;
}

#else

static bool
handle_start_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    size_t len = dr_syscall_get_param(drcontext, 2);

    // taint buffer
    for (int i = 0; i < len; ++i)
    {
        DR_ASSERT_MSG(
            drtaint_set_app_taint(drcontext, (app_pc)&buffer[i], TAINT_TAG),
            "Unable to set app tainted");
    }

    return false;
}

static bool
handle_check_trace(void *drcontext)
{
    char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
    size_t len = dr_syscall_get_param(drcontext, 2);
    byte result;

    // check the buffer is tainted
    for (int i = 0; i < len; ++i)
    {
        if (!drtaint_get_app_taint(drcontext, (app_pc)&buffer[i], &result) ||
            !IS_TAINTED(result))
        {
            set_syscall_retval(drcontext, false);
            return false;
        }
    }

    set_syscall_retval(drcontext, true);
    return false;
}

#endif