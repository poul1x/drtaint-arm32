#ifndef SHADOW_H_
#define SHADOW_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ds_init(int id);

void ds_exit(void);

bool ds_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                             reg_id_t regaddr, reg_id_t scratch);

bool ds_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                             reg_id_t shadow, reg_id_t regaddr);

bool ds_insert_reg_to_shadow_load(void *drcontext, instrlist_t *ilist,
                                  instr_t *where, reg_id_t shadow,
                                  reg_id_t regaddr);

bool ds_get_reg_taint(void *drcontext, reg_id_t reg, uint *result);

bool ds_set_reg_taint(void *drcontext, reg_id_t reg, uint value);

bool ds_get_app_taint(void *drcontext, app_pc app, byte *result);

bool ds_set_app_taint(void *drcontext, app_pc app, byte value);

bool ds_get_app_taint4(void *drcontext, app_pc app, uint *result);

bool ds_set_app_taint4(void *drcontext, app_pc app, uint value);

void ds_set_app_area_taint(void *drcontext, app_pc app, uint size, byte value);

#ifdef __cplusplus
}
#endif

#endif
