#ifndef TEMPLATES_H_
#define TEMPLATES_H_

#include "dr_api.h"

typedef enum {
    BYTE,
    HALF,
    WORD,
} opnd_sz_t;

// decrement before, increment after, decrement after, increment before
typedef enum {
    DB,
    IA,
    DA,
    IB
} stack_dir_t;

template <opnd_sz_t T>
inline instr_t *instr_load(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return NULL;
}

template <>
inline instr_t *instr_load<BYTE>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load_1byte(drcontext, dst_reg, mem);
}

template <>
inline instr_t *instr_load<HALF>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load_2bytes(drcontext, dst_reg, mem);
}

template <>
inline instr_t *instr_load<WORD>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load(drcontext, dst_reg, mem);
}

template <opnd_sz_t T>
inline instr_t *instr_store(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return NULL;
}

template <>
inline instr_t *instr_store<BYTE>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store_1byte(drcontext, mem, src_reg);
}

template <>
inline instr_t *instr_store<HALF>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store_2bytes(drcontext, mem, src_reg);
}

template <>
inline instr_t *instr_store<WORD>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store(drcontext, mem, src_reg);
}

template <opnd_sz_t T>
inline opnd_t opnd_mem(reg_id_t base_reg, int disp)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return {0};
}

template <>
inline opnd_t opnd_mem<BYTE>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM8(base_reg, disp);
}

template <>
inline opnd_t opnd_mem<HALF>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM16(base_reg, disp);
}

template <>
inline opnd_t opnd_mem<WORD>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM32(base_reg, disp);
}

template <stack_dir_t T>
inline app_pc calculate_addr(instr_t *instr, void *base, int i, int top)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return 0;
}

template <>
inline app_pc calculate_addr<DB>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base - 4 * (top - i);
}

template <>
inline app_pc calculate_addr<IA>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base + 4 * i;
}

template <>
inline app_pc calculate_addr<DA>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base - 4 * (top - i - 1);
}

template <>
inline app_pc calculate_addr<IB>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base + 4 * (i + 1);
}

#endif