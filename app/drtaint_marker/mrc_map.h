
#ifndef MRC_MAP_H_
#define MRC_MAP_H_

#include "dr_api.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mrc
{
    app_pc pc;
    const char* reg;
    uint32_t value;
};

typedef void(*mrc_func)(const struct mrc* item, void* user_data);

bool mrc_reads_coproc(instr_t* instr);

bool mrc_has_instr(const struct mrc* item);

void mrc_insert_save_arm_reg(void* drcontext, instrlist_t* ilist, instr_t *instr);

void mrc_clear();

void mrc_iterate_elements(mrc_func f, void* user_data);

#ifdef __cplusplus
}
#endif

#endif