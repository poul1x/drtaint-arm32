
#ifndef TAINTED_CHECKING_H_
#define TAINTED_CHECKING_H_

#include "dr_api.h"

using tc_callback_t = void(*)(void* drcontext, instr_t* instr);

void tc_perform_instrumentation(void *drcontext, instrlist_t *ilist, instr_t *where);

void tc_set_callback(tc_callback_t cb);

#endif