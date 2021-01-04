#include "drtaint.h"
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "taint_checking.h"
#include "taint_processing.h"

#include <set>
#include <vector>

#include <ios>
#include <sstream>
#include <cstring>
#include <syscall.h>

#define IS_TAINTED(val, tag) ((val) & (tag))
#define TAG_TAINTED 0x02

struct buffer_t
{
    char *ptr;
    int len;
};

// Output modules info to file
file_t g_fd_modules = 0;
app_pc g_base_addr = 0;

struct per_thread_t
{
    // We will store there buffer
    // that will be saved in pre_syscall event
    buffer_t syscall_buf;

    // We will store there addresses of tainted instructions
    std::set<app_pc> *instrs;

    // Output taint info to file
    file_t fd_instrs;
};

static int tls_index;

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
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static void
dump_tainted_instrs(void *drcontext, file_t file,
                    const tainted_instr &instr, bool is_first_instr);

static void
save_taint_info(void *drcontext, instr_t *instr);

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded);

#pragma endregion prototypes

class JsonObject
{

private:
    std::stringstream m_ss;
    char m_close_token;
    bool m_is_first;

public:
    JsonObject(std::string key, char open_token, char close_token, bool comma = false)
    {
        m_is_first = true;
        m_close_token = close_token;

        if (comma)
            m_ss << ",";

        m_ss << "\"" << key << "\":" << open_token;
    }

    JsonObject(char open_token, char close_token, bool comma = false)
    {
        m_is_first = true;
        m_close_token = close_token;

        if (comma)
            m_ss << ",";

        m_ss << open_token;
    }

    std::string dump() const
    {
        return m_ss.str() + m_close_token;
    }

    void append(const JsonObject &obj)
    {
        if (m_is_first)
            m_is_first = false;
        else
            m_ss << ",";

        m_ss << obj.dump();
    }

    void append(std::string key, std::string val)
    {
        if (m_is_first)
            m_is_first = false;
        else
            m_ss << ",";

        m_ss << "\"" << key << "\":"
             << "\"" << val << "\"";
    }
};

static void
dump_tainted_instrs(void *drcontext, file_t file,
                    const tainted_instr &instr, bool is_first_instr)
{
    JsonObject dict_instr('{', '}', is_first_instr);
    dict_instr.append("address", tainted_instr_addr_str(instr));
    dict_instr.append("bytes", tainted_instr_bytes_str(instr));

    JsonObject list_opnds("operands", '[', ']');
    for (const auto &opnd : instr.operands)
    {
        JsonObject dict_opnd('{', '}');
        dict_opnd.append("type", tainted_opnd_type_str(opnd));
        dict_opnd.append("name", tainted_opnd_name_str(opnd));
        dict_opnd.append("value", tainted_opnd_value_str(opnd));
        dict_opnd.append("taint", tainted_opnd_taint_str(opnd));

        list_opnds.append(dict_opnd);
    }

    dict_instr.append(list_opnds);
    std::string json = dict_instr.dump();
    dr_write_file(file, json.c_str(), json.length());
}

static void
save_taint_info(void *drcontext, instr_t *instr)
{
    per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    app_pc pc = instr_get_app_pc(instr);
    auto instrs = tls->instrs;

    auto it = instrs->find(pc);
    if (it == instrs->end())
    {
        tainted_instr instr_info;
        tainted_instr_save_bytes_addr(drcontext, instr, &instr_info);
        tainted_instr_save_tainted_opnds(drcontext, instr, &instr_info);
        dump_tainted_instrs(drcontext, tls->fd_instrs,
                            instr_info, instrs->size() > 0);

        instrs->emplace(pc);
    }
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

    per_thread_t *tls = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    app_pc pc = instr_get_app_pc(where);
    auto it = tls->instrs->find(pc);

    // do not add instrumentation to known tainted instructions
    if (it == tls->instrs->end())
        tc_perform_instrumentation(drcontext, ilist, where);

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

    // Save main module info
    module_data_t *info = dr_get_main_module();
    g_base_addr = info->start;

    JsonObject dict_main('{', '}');
    dict_main.append("address", u32_to_hex_string((uint32_t)g_base_addr));
    dict_main.append("name", dr_module_preferred_name(info));
    dict_main.append("filepath", info->full_path);
    dr_free_module_data(info);

    g_fd_modules = dr_open_file("modules.json", DR_FILE_WRITE_OVERWRITE);
    std::string json = dict_main.dump();
    dr_write_file(g_fd_modules, "[", 1);
    dr_write_file(g_fd_modules, json.c_str(), json.length());

    // Add taint check and module load handlers
    drmgr_register_module_load_event(event_module_load);
    tc_set_callback(save_taint_info);

    dr_printf("\n----- drtaint marker is running -----\n\n");
}

static void
exit_event()
{
    dr_printf("\n----- drtaint marker is exitting -----\n\n");

    drmgr_unregister_module_load_event(event_module_load);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    drmgr_unregister_post_syscall_event(event_post_syscall);
    drmgr_unregister_tls_field(tls_index);

    drreg_exit();
    drmgr_exit();
    drtaint_exit();

    dr_write_file(g_fd_modules, "]", 1);
    dr_close_file(g_fd_modules);
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));

    std::string tid_str = u32_to_hex_string(dr_get_thread_id(drcontext));
    std::string filename = "instructions." + tid_str + ".json";

    data->fd_instrs = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    dr_write_file(data->fd_instrs, "[", 1);
    data->instrs = new std::set<app_pc>();

    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);

    delete data->instrs;
    dr_write_file(data->fd_instrs, "]", 1);
    dr_close_file(data->fd_instrs);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

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

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext;

    if (!loaded)
        return;

    if (info->start == g_base_addr)
        return;

    JsonObject dict_main('{', '}', true);
    dict_main.append("address", u32_to_hex_string((uint32_t)info->start));
    dict_main.append("name", dr_module_preferred_name(info));
    dict_main.append("filepath", info->full_path);

    std::string json = dict_main.dump();
    dr_write_file(g_fd_modules, json.c_str(), json.length());
}