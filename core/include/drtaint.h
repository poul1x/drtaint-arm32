#ifndef DRTAINT_H_
#define DRTAINT_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        DRMGR_PRIORITY_INSERT_DRTAINT = -7500,
        DRMGR_PRIORITY_THREAD_INIT_DRTAINT = -7500,
        DRMGR_PRIORITY_THREAD_EXIT_DRTAINT = 7500,
    };

#define DRMGR_PRIORITY_NAME_DRTAINT "drtaint"
#define DRMGR_PRIORITY_NAME_DRTAINT_EXIT "drtaint.exit"
#define DRMGR_PRIORITY_NAME_DRTAINT_INIT "drtaint.init"

#ifdef ASM_TAINT

    typedef enum
    {
        SUPPOSE_TAINTED_NONE,
        SUPPOSE_TAINTED_REG,
        SUPPOSE_TAINTED_APP,
    } suppose_tainted_t;

    typedef struct _instr_opnds_t
    {
        suppose_tainted_t what;
        byte* app_start;
        byte app_delta;
        byte app_iters; 
        byte* pc;
        uint reg_list;

    } instr_opnds_t;

    typedef void (*drtaint_track_t)(void *drcontext, const instr_opnds_t *taint_info);

    void drtaint_register_post_taint_event(drtaint_track_t func);

#endif

    bool drtaint_init(client_id_t id);

    void drtaint_exit(void);

    bool drtaint_insert_app_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                                     reg_id_t reg_addr, reg_id_t scratch);

    bool drtaint_insert_reg_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                                     reg_id_t shadow, reg_id_t regaddr);

    bool drtaint_get_reg_taint(void *drcontext, reg_id_t reg, uint *result);

    bool drtaint_set_reg_taint(void *drcontext, reg_id_t reg, uint value);

    bool drtaint_get_app_taint(void *drcontext, app_pc app, byte *result);

    bool drtaint_set_app_taint(void *drcontext, app_pc app, byte result);

    bool drtaint_get_app_taint4(void *drcontext, app_pc app, uint *result);

    bool drtaint_set_app_taint4(void *drcontext, app_pc app, uint result);

    void drtaint_set_app_area_taint(void *drcontext, app_pc app, uint size, byte tag);

#ifdef __cplusplus
}
#endif

#endif
