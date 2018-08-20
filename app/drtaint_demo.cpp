#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "../drtaint.h"
#include <syscall.h>
#include <string.h>
#include <time.h>

/*
    This is a client library showing drtaint capabilities.
    It can make tainted a region of memory, trace taint distribution
    and register a callback function which will get information about
    tainted registers and tainted memory areas after every instruction execution
*/

#define TAINT_TAG 0x80
static int tls_index;
clock_t g_clock;

struct per_thread_t
{
    file_t fd;
    thread_id_t tid;
};

static void
exit_event(void);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static void
event_post_syscall(void *drcontext, int sysnum);

static void
event_post_taint(void *drcontext, const instr_opnds_t *taint_info);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drtaint_init(id);
    drmgr_init();

    drreg_options_t drreg_ops = {sizeof(drreg_ops), 3, false};
    auto drreg_ret = drreg_init(&drreg_ops);
    DR_ASSERT(drreg_ret == DRREG_SUCCESS);

    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    // initialize tls for per-thread data
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    dr_register_exit_event(exit_event);

    // register callback
    drtaint_register_post_taint_event(event_post_taint);
    disassemble_set_syntax(DR_DISASM_ARM);

    g_clock = -clock();
    dr_printf("\n----- DrTaint demo client is running -----\n\n");
}

static void
exit_event(void)
{
    g_clock += clock();
    dr_printf("\ntime = %.3lfs\n", (double)g_clock / CLOCKS_PER_SEC);
    dr_printf("\n----- DrTaint demo client is exitting -----\n\n");

    drmgr_unregister_post_syscall_event(event_post_syscall);
    dr_unregister_filter_syscall_event(event_filter_syscall);

    drmgr_unregister_tls_field(tls_index);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);

    drtaint_exit();
    drmgr_exit();
    drreg_exit();
}

static void
event_thread_init(void *drcontext)
{
    thread_id_t tid = dr_get_thread_id(drcontext);
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));

    char fname[64];
    // for each thread write file
    dr_snprintf(fname, sizeof(fname), "drtaint_demo_tid_%d.txt", tid);

    data->tid = tid;
    data->fd = dr_open_file(fname, DR_FILE_WRITE_OVERWRITE);
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    dr_close_file(data->fd);

    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    // if SYS_read is successfull then taint
    if (sysnum == SYS_read)
    {
        dr_syscall_result_info_t info = {
            sizeof(info),
        };

        dr_syscall_get_result_ex(drcontext, &info);
        if (info.succeeded)
        {
            char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
            uint len = dr_syscall_get_param(drcontext, 2);

            drtaint_set_app_area_taint(drcontext, (app_pc)buffer, len, TAINT_TAG);
        }
    }
}

static char *
handle_reg(void *drcontext, char *p, const instr_opnds_t *taint_info, bool *rb)
{
    uint res;
    bool ok;
    bool bt = false;

    for (int r = DR_REG_R0; r <= DR_REG_R15; r++)
    {
        if (taint_info->reg_list & (1 << r))
        {
            ok = drtaint_get_reg_taint(drcontext, r, &res);
            DR_ASSERT(ok);

            if (res != 0)
            {
                p += dr_snprintf(p, 30, "r%d{tag = 0x%08X}  ", r - 2, res);
                bt = true;
            }
        }
    }

    *rb = *rb || bt;
    return p;
}

static char *
handle_app(void *drcontext, char *p, const instr_opnds_t *taint_info, bool *rb)
{
    bool ok;
    bool bt = false;
    app_pc m;
    byte i;

    DR_ASSERT(taint_info->app_start != 0 &&
              taint_info->app_iters != 0 &&
              taint_info->app_delta != 0);

    // ldr, ldrb, ldrh, strb ...
    if (taint_info->app_delta == 1)
    {
        byte res = 0;
        for (m = taint_info->app_start, i = 0;
             i < taint_info->app_iters;
             m += taint_info->app_delta, i++)
        {
            ok = drtaint_get_app_taint(drcontext, m, &res);
            DR_ASSERT(ok);

            if (res != 0)
            {
                p += dr_snprintf(p, 30, "m0x%08X{tag = 0x%02X}  ", m, res);
                bt = true;
            }
        }
    }

    // ldrd strd stm ldm
    else if (taint_info->app_delta == 4)
    {
        uint res = 0;
        for (m = taint_info->app_start, i = 0;
             i < taint_info->app_iters;
             m += taint_info->app_delta, i++)
        {
            ok = drtaint_get_app_taint4(drcontext, m, &res);
            DR_ASSERT(ok);

            if (res != 0)
            {
                p += dr_snprintf(p, 40, "m0x%08X{tag = 0x%08X}  ", m, res);
                bt = true;
            }
        }
    }

    *rb = *rb || bt;
    return p;
}

// our callback
static void
event_post_taint(void *drcontext, const instr_opnds_t *taint_info)
{
    if (taint_info->what == SUPPOSE_TAINTED_NONE)
        return;

    bool rb = false;
    char buf[1024];
    char *p = buf;

    if (taint_info->what == SUPPOSE_TAINTED_REG)
        p = handle_reg(drcontext, p, taint_info, &rb);
    else
        p = handle_app(drcontext, p, taint_info, &rb);

    if (rb)
    {
        per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
        instr_t *instr = instr_create(drcontext);
        decode(drcontext, taint_info->pc, instr);

        // write to file
        p += dr_snprintf(p, 20, "\n0x%08X  ", taint_info->pc);
        p += instr_disassemble_to_buffer(drcontext, instr, p, 256);
        p += dr_snprintf(p, 2, "\n\n");
        dr_write_file(data->fd, buf, p - buf);
        instr_destroy(drcontext, instr);
    }
}
