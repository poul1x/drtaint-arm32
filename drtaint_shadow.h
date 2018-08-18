#ifndef SHADOW_H_
#define SHADOW_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define DRT_SET_FLAGS_UP(cpsr, flags) (cpsr |= (flags))
#define DRT_SET_FLAGS_DOWN(cpsr, flags) (cpsr &= ~(flags))
#define DRT_TEST_FLAGS_UP(cpsr, flags) ((cpsr & (flags)) >= (flags))
#define DRT_TEST_FLAGS_DOWN(cpsr, flags) (!(cpsr & (flags)))

#define DRT_SET_FLAG_UP(cpsr, flag) DRT_SET_FLAGS_UP(cpsr, flag)
#define DRT_SET_FLAG_DOWN(cpsr, flag) DRT_SET_FLAGS_DOWN(cpsr, flag)
#define DRT_TEST_FLAG_UP(cpsr, flag) ((cpsr & (flag)))
#define DRT_TEST_FLAG_DOWN(cpsr, flag) DRT_TEST_FLAGS_DOWN(cpsr, flag)

    bool
    ds_init(int id);

    void
    ds_exit(void);

    bool
    ds_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t regaddr, reg_id_t scratch);

    bool
    ds_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t shadow, reg_id_t regaddr);

    bool
    ds_insert_reg_to_shadow_load(void *drcontext, instrlist_t *ilist,
                                 instr_t *where, reg_id_t shadow,
                                 reg_id_t regaddr);

    bool
    ds_get_reg_taint(void *drcontext, reg_id_t reg, uint *result);

    bool
    ds_set_reg_taint(void *drcontext, reg_id_t reg, uint value);

    bool
    ds_get_app_taint(void *drcontext, app_pc app, byte *result);

    bool
    ds_set_app_taint(void *drcontext, app_pc app, byte result);

    bool
    ds_get_app_taint4(void *drcontext, app_pc app, uint *result);

    bool
    ds_set_app_taint4(void *drcontext, app_pc app, uint result);

    void
    ds_save_instr(void *drcontext, int opcode);

    int
    ds_get_prev_instr(void *drcontext);

    void
    ds_update_cpsr(void *drcontext, uint new_flags);

    uint
    ds_get_cpsr(void *drcontext);

    void
    ds_set_app_area_taint(void *drcontext, app_pc app, uint size, byte tag);

#ifdef ASM_TAINT

    void
    ds_opnds_insert_callback(void *drcontext, instrlist_t *ilist, instr_t *where);

    void
    ds_opnds_insert_app_area_to_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                                     reg_id_t regaddr, byte app_delta, byte app_iters);

    void
    ds_opnds_insert_reg_id_to_info(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg);

    void
    ds_opnds_insert_tainted_to_info(void *drcontext, instrlist_t *ilist, instr_t *where,
                                    suppose_tainted_t opnd_type);

    void
    ds_opnds_insert_clear_info(void *drcontext, instrlist_t *ilist, instr_t *where);

    void
    ds_opnds_tainted_to_info(void *drcontext, suppose_tainted_t opnd_type);

    void
    ds_opnds_app_area_to_info(void *drcontext, byte *app_start, byte app_delta, byte app_iters);

    void
    ds_opnds_reg_id_to_info(void *drcontext, reg_id_t reg);

#endif

#ifdef __cplusplus
}
#endif

#endif
