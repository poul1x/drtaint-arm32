#ifndef TAINT_MAP_H_
#define TAINT_MAP_H_

#include "dr_api.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    bool tmap_has(instr_t *instr, uint32_t taint);

    void tmap_emplace(instr_t *instr, uint32_t taint);

    void tmap_print();

#ifdef __cplusplus
}
#endif

#endif