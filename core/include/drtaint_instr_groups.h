#ifndef INSTR_GROUPS_H_
#define INSTR_GROUPS_H_

#include "dr_api.h"

inline bool instr_group_is_ldm(int opcode)
{
    return opcode >= OP_ldm && opcode <= OP_ldmib_priv;
}

inline bool instr_group_is_stm(int opcode)
{
    return opcode >= OP_stm && opcode <= OP_stmib_priv;
}

inline bool instr_group_is_load(int opcode)
{
    return opcode >= OP_ldr && opcode <= OP_ldrt;
}

inline bool instr_group_is_ldrb(int opcode)
{
    switch (opcode)
    {
    case OP_ldrb:
    case OP_ldrsb:
    case OP_ldrexb:
    case OP_ldrbt:
    case OP_ldrsbt:
        return true;
    }

    return false;
}

inline bool instr_group_is_ldrh(int opcode)
{
    switch (opcode)
    {
    case OP_ldrh:
    case OP_ldrsh:
    case OP_ldrexh:
    case OP_ldrht:
    case OP_ldrsht:
        return true;
    }

    return false;
}

inline bool instr_group_is_ldr(int opcode)
{
    return opcode == OP_ldr ||
           opcode == OP_ldrex ||
           opcode == OP_ldrt;
}

inline bool instr_group_is_ldrd(int opcode)
{
    return opcode == OP_ldrd ||
           opcode == OP_ldrexd;
}

inline bool instr_group_is_store(int opcode)
{
    return opcode >= OP_str && opcode <= OP_strt;
}

inline bool instr_group_is_strb(int opcode)
{
    return opcode == OP_strb ||
           opcode == OP_strexb ||
           opcode == OP_strbt;
}

inline bool instr_group_is_strh(int opcode)
{
    return opcode == OP_strh ||
           opcode == OP_strexh ||
           opcode == OP_strht;
}

inline bool instr_group_is_str(int opcode)
{
    return opcode == OP_str ||
           opcode == OP_strex ||
           opcode == OP_strt;
}

inline bool instr_group_is_strd(int opcode)
{
    return opcode == OP_strd ||
           opcode == OP_strexd;
}

inline bool instr_group_is_jump(int opcode)
{
    return opcode == OP_b || opcode == OP_b_short ||
           (opcode >= OP_bl && opcode <= OP_cbz);
}

inline bool instr_group_is_cmp(int opcode)
{
    return opcode == OP_cmp || opcode == OP_cmn ||
           opcode == OP_teq || opcode == OP_tst;
}

#endif