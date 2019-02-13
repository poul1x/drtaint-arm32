#include <string.h>
#include <signal.h>
#include <stddef.h>

#include "include/drtaint.h"

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"

static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc);

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc,
                            app_pc app_shadow);

static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info);

static bool
ds_mem_init(int id);

static void
ds_mem_exit(void);

static bool
ds_reg_init(void);

static void
ds_reg_exit(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static void
event_thread_exit(void *drcontext);

static int num_shadow_count;
static umbra_map_t *umbra_map;
static int tls_index;

typedef struct _per_thread_t
{
    /* Holds shadow values for general purpose registers. The shadow memory
     * currently uses UMBRA_MAP_SCALE_SAME_1x, which implies that each 1-byte
     * aligned location is represented as one byte. We imitate this here.
     */
    uint shadow_gprs[DR_NUM_GPR_REGS];

    /* holds shadow flags */
    uint shadow_cpsr;

    /* holds previous instruction opcode */
    int prev_opcode;

} per_thread_t;

bool ds_init(int id)
{
    /* XXX: we only support a single umbra mapping */
    if (dr_atomic_add32_return_sum(&num_shadow_count, 1) > 1)
        return false;
    if (!ds_mem_init(id) || !ds_reg_init())
        return false;
    return true;
}

void ds_exit(void)
{
    ds_mem_exit();
    ds_reg_exit();
}

/* ======================================================================================
 * shadow memory API
 * ==================================================================================== */

bool ds_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                             reg_id_t regaddr, reg_id_t scratch)
/*
 *    Save original application address in %regaddr% to SPILL_SLOT_2 
 *    and translate value of %regaddr% to its shadow address
 *
 *    out <- %regaddr% - address of register where the value is/will be stored
 */
{
    /* XXX: we shouldn't have to do this */
    /* Save the app address to a well-known spill slot, so that the fault handler
     * can recover if no shadow memory was installed yet.
     */
    dr_save_reg(drcontext, ilist, where, regaddr, SPILL_SLOT_2);
    drmf_status_t status = umbra_insert_app_to_shadow(drcontext, umbra_map,
                                                      ilist, where, regaddr, &scratch, 1);

    return status == DRMF_SUCCESS;
}

bool ds_get_app_taint(void *drcontext, app_pc app, byte *result)
{
    size_t sz = 1;
    drmf_status_t status = umbra_read_shadow_memory(umbra_map, app, 1, &sz, result);
    return status == DRMF_SUCCESS;
}

bool ds_get_app_taint4(void *drcontext, app_pc app, uint *result)
{
    size_t sz = sizeof(uint);
    drmf_status_t status = umbra_read_shadow_memory(umbra_map, app,
                                                    sizeof(uint), &sz, (byte *)result);
    return status == DRMF_SUCCESS;
}

bool ds_set_app_taint(void *drcontext, app_pc app, byte result)
{
    size_t sz = 1;
    drmf_status_t status = umbra_write_shadow_memory(umbra_map, app, 1, &sz, &result);
    return status == DRMF_SUCCESS;
}

bool ds_set_app_taint4(void *drcontext, app_pc app, uint result)
{
    size_t sz = sizeof(uint);
    drmf_status_t status = umbra_write_shadow_memory(umbra_map, app,
                                                     sizeof(uint), &sz, (byte *)&result);
    return status == DRMF_SUCCESS;
}

void ds_set_app_area_taint(void *drcontext, app_pc app, uint size, byte tag)
/*
 *  Set linear memory area tainted, 
 *  beginning from %app% and filling %size% bytes 
 */
{
    uint cnt4 = size / 4, cnt1 = size % 4;
    uint start = 0, end = cnt4 * 4, i;
    uint tag4 = tag + (tag << 8) + (tag << 16) + (tag << 24);
    bool ok;

    for (i = start; i < end; i += 4)
    {
        ok = ds_set_app_taint4(drcontext, &app[i], tag4);
        DR_ASSERT(ok);
    }

    start = end;
    end += cnt1;
    for (i = start; i < end; i++)
    {
        ok = ds_set_app_taint(drcontext, &app[i], tag);
        DR_ASSERT(ok);
    }
}

/* ======================================================================================
 * shadow memory implementation
 * ==================================================================================== */

static bool
ds_mem_init(int id)
{
    umbra_map_options_t umbra_map_ops;
    drmgr_init();

    /* initialize umbra and lazy page handling */
    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale = UMBRA_MAP_SCALE_SAME_1X;
    umbra_map_ops.flags = UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
                          UMBRA_MAP_SHADOW_SHARED_READONLY;

    umbra_map_ops.default_value = 0;
    umbra_map_ops.default_value_size = 1;

    if (umbra_init(id) != DRMF_SUCCESS)
        return false;
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        return false;

    drmgr_register_signal_event(event_signal_instrumentation);
    return true;
}

static void
ds_mem_exit(void)
{
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);

    drmgr_unregister_signal_event(event_signal_instrumentation);
    umbra_exit();
    drmgr_exit();
}

static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc)
{
    instr_t inst;
    reg_id_t reg;

    instr_init(drcontext, &inst);
    decode(drcontext, mc->pc, &inst);

    DR_ASSERT_MSG(opnd_is_base_disp(instr_get_dst(&inst, 0)), "Emulation error");
    reg = opnd_get_base(instr_get_dst(&inst, 0));
    DR_ASSERT_MSG(reg != DR_REG_NULL, "Emulation error");

    instr_free(drcontext, &inst);
    return reg;
}

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc, app_pc app_shadow)
{
    umbra_shadow_memory_type_t shadow_type;
    app_pc app_target;
    reg_id_t reg;

    /* If a fault occured, it is probably because we computed the
     * address of shadow memory which was initialized to a shared
     * readonly shadow block. We allocate a shadow page there and
     * replace the reg value used by the faulting instr.
     */

    /* handle faults from writes to special shadow blocks */
    if (umbra_shadow_memory_is_shared(umbra_map, app_shadow,
                                      &shadow_type) != DRMF_SUCCESS)
    {
        DR_ASSERT(false);
        return true;
    }
    if (shadow_type != UMBRA_SHADOW_MEMORY_TYPE_SHARED)
        return true;

    /* Grab the original app target out of the spill slot so we
     * don't have to compute the app target ourselves (this is
     * difficult).
     */
    app_target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);

    /* replace the shared block, and record the new app shadow */
    if (umbra_replace_shared_shadow_memory(umbra_map, app_target,
                                           &app_shadow) != DRMF_SUCCESS)
    {
        DR_ASSERT(false);
        return true;
    }

    /* Replace the faulting register value to reflect the new shadow
     * memory.
     */
    reg = get_faulting_shadow_reg(drcontext, raw_mc);
    reg_set_value(reg, raw_mc, (reg_t)app_shadow);
    return false;
}

static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig != SIGSEGV && info->sig != SIGBUS)
        return DR_SIGNAL_DELIVER;

    DR_ASSERT(info->raw_mcontext_valid);
    return handle_special_shadow_fault(drcontext, info->raw_mcontext,
                                       info->access_address)
               ? DR_SIGNAL_DELIVER
               : DR_SIGNAL_SUPPRESS;
}

/* ======================================================================================
 * shadow registers implementation
 * ==================================================================================== */
static bool
ds_reg_init(void)
{
    drmgr_priority_t exit_priority = {
        sizeof(exit_priority), DRMGR_PRIORITY_NAME_DRTAINT_EXIT, NULL, NULL,
        DRMGR_PRIORITY_THREAD_EXIT_DRTAINT};

    drmgr_priority_t init_priority = {
        sizeof(init_priority), DRMGR_PRIORITY_NAME_DRTAINT_INIT, NULL, NULL,
        DRMGR_PRIORITY_THREAD_INIT_DRTAINT};

    drmgr_init();
    drmgr_register_thread_init_event_ex(event_thread_init, &init_priority);
    drmgr_register_thread_exit_event_ex(event_thread_exit, &exit_priority);

    /* initialize tls for per-thread data */
    tls_index = drmgr_register_tls_field();
    if (tls_index == -1)
        return false;
    return true;
}

bool ds_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                             reg_id_t shadow, reg_id_t regaddr)
/*
 *    Inserts instructions to gain shadow %shadow% register's address 
 *    of the current thread and place result to register of %regaddr% 
 */
{
    DR_ASSERT(shadow - DR_REG_R0 < DR_NUM_GPR_REGS);
    unsigned int offs = offsetof(per_thread_t, shadow_gprs[shadow - DR_REG_R0]);

    /* Load the per_thread data structure holding
     * the thread-local taint values of each register to %regaddr%
     */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, regaddr);

    /* out <- %regaddr% = &shadow_gprs[offs] */
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_add(drcontext, /* regaddr = regaddr + offs */
                                              opnd_create_reg(regaddr),
                                              OPND_CREATE_INT8(offs)));
    return true;
}

bool ds_insert_reg_to_shadow_load(void *drcontext, instrlist_t *ilist,
                                  instr_t *where, reg_id_t shadow,
                                  reg_id_t regaddr)
/*
 *    Inserts instructions to gain shadow %shadow% register's value 
 *    of the current thread and place result to register of %regaddr% 
 */
{
    DR_ASSERT(shadow - DR_REG_R0 < DR_NUM_GPR_REGS);
    unsigned int offs = offsetof(per_thread_t, shadow_gprs[shadow - DR_REG_R0]);

    /* Load the per_thread data structure holding
     * the thread-local taint values of each register to %regaddr%
     */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, regaddr);

    /* out <- %regaddr% = shadow_gprs[offs] */
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_load(drcontext, /* ldr regaddr, [regaddr, #offs] */
                                               opnd_create_reg(regaddr),
                                               OPND_CREATE_MEM32(regaddr, offs)));

    return true;
}

bool ds_get_reg_taint(void *drcontext, reg_id_t reg, uint *result)
/*
 *    Get the value of shadow register %reg% and store it in %result%
 */
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    if (reg - DR_REG_R0 >= DR_NUM_GPR_REGS)
        return false;

    *result = data->shadow_gprs[reg - DR_REG_R0];
    return true;
}

bool ds_set_reg_taint(void *drcontext, reg_id_t reg, uint value)
/*
 *    Set the value of shadow register %reg% to value %value%
 */
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    if (reg - DR_REG_R0 >= DR_NUM_GPR_REGS)
        return false;

    data->shadow_gprs[reg - DR_REG_R0] = value;
    return true;
}

static void
ds_reg_exit(void)
{
    drmgr_unregister_tls_field(tls_index);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

/* ======================================================================================
 * routines for tracking arith flags (for supporting conditional execution)
 * ==================================================================================== */

void ds_save_instr(void *drcontext, int opcode)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    data->prev_opcode = opcode;
}

int ds_get_prev_instr(void *drcontext)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    return data->prev_opcode;
}

void ds_update_cpsr(void *drcontext, uint new_flags)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    data->shadow_cpsr = new_flags;
}

uint ds_get_cpsr(void *drcontext)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    return data->shadow_cpsr;
}