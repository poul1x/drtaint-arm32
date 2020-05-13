
#ifndef TAINTED_CHECKING_H_
#define TAINTED_CHECKING_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void(*tc_callback_t)(void* drcontext, instr_t* instr);

void tc_perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where);

void tc_set_callback(tc_callback_t cb);

#ifdef __cplusplus
}
#endif

#endif