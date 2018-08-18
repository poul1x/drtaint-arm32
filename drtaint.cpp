#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

#include "umbra.h"
#include "drsyscall.h"
#include "drtaint.h"
#include "drtaint_shadow.h"
#include "drtaint_helper.h"

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);
static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
event_post_syscall(void *drcontext, int sysnum);

static bool
propagate_default_isa(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      int opcode, void *user_data);

extern bool
propagate_simd_isa(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                   int opcode, void *user_data);

static int drtaint_init_count;
static client_id_t client_id;

bool drtaint_init(client_id_t id)
{
    drreg_options_t drreg_ops = {sizeof(drreg_ops), 4, false};
    drsys_options_t drsys_ops = {sizeof(drsys_ops), 0};
    drmgr_priority_t pri = {sizeof(pri),
                            DRMGR_PRIORITY_NAME_DRTAINT, NULL, NULL,
                            DRMGR_PRIORITY_INSERT_DRTAINT};

    int count = dr_atomic_add32_return_sum(&drtaint_init_count, 1);
    if (count > 1)
        return true;

    client_id = id;
    drmgr_init();
    if (!ds_init(id) ||
        drreg_init(&drreg_ops) != DRREG_SUCCESS ||
        drsys_init(id, &drsys_ops) != DRMF_SUCCESS)
        return false;
    drsys_filter_all_syscalls();
    if (!drmgr_register_bb_instrumentation_event(NULL,
                                                 event_app_instruction,
                                                 &pri) ||
        !drmgr_register_pre_syscall_event(event_pre_syscall) ||
        !drmgr_register_post_syscall_event(event_post_syscall))
        return false;

    return true;
}

void drtaint_exit(void)
{
    int count = dr_atomic_add32_return_sum(&drtaint_init_count, -1);
    if (count != 0)
        return;
    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    drmgr_unregister_post_syscall_event(event_post_syscall);
    ds_exit();
    drmgr_exit();
    drreg_exit();
    drsys_exit();
}

bool drtaint_insert_app_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                                 reg_id_t reg_addr, reg_id_t scratch)
{
    return ds_insert_app_to_shadow(drcontext, ilist, where,
                                   reg_addr, scratch);
}

bool drtaint_insert_reg_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                                 reg_id_t shadow, reg_id_t regaddr)
{
    return ds_insert_reg_to_shadow(drcontext, ilist, where,
                                   shadow, regaddr);
}

bool drtaint_insert_reg_to_taint_load(void *drcontext, instrlist_t *ilist, instr_t *where,
                                      reg_id_t shadow, reg_id_t regaddr)
{
    return ds_insert_reg_to_shadow_load(drcontext, ilist, where,
                                        shadow, regaddr);
}

bool drtaint_get_reg_taint(void *drcontext, reg_id_t reg, uint *result)
{
    return ds_get_reg_taint(drcontext, reg, result);
}

bool drtaint_set_reg_taint(void *drcontext, reg_id_t reg, uint value)
{
    return ds_set_reg_taint(drcontext, reg, value);
}

bool drtaint_get_app_taint(void *drcontext, app_pc app, byte *result)
{
    return ds_get_app_taint(drcontext, app, result);
}

bool drtaint_set_app_taint(void *drcontext, app_pc app, byte result)
{
    return ds_set_app_taint(drcontext, app, result);
}

bool drtaint_get_app_taint4(void *drcontext, app_pc app, uint *result)
{
    return ds_get_app_taint4(drcontext, app, result);
}

bool drtaint_set_app_taint4(void *drcontext, app_pc app, uint result)
{
    return ds_set_app_taint4(drcontext, app, result);
}

void drtaint_set_app_area_taint(void *drcontext, app_pc app, uint size, byte tag)
{
    ds_set_app_area_taint(drcontext, app, size, tag);
}

/* ======================================================================================
 * main implementation, taint propagation step
 * ==================================================================================== */

typedef enum
{
    BYTE,
    HALF,
    WORD,
} opnd_sz_t;

template <opnd_sz_t T>
instr_t *instr_load(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return NULL;
}

template <>
instr_t *instr_load<BYTE>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load_1byte(drcontext, dst_reg, mem);
}

template <>
instr_t *instr_load<HALF>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load_2bytes(drcontext, dst_reg, mem);
}

template <>
instr_t *instr_load<WORD>(void *drcontext, opnd_t dst_reg, opnd_t mem)
{
    return XINST_CREATE_load(drcontext, dst_reg, mem);
}

template <opnd_sz_t T>
instr_t *instr_store(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return NULL;
}

template <>
instr_t *instr_store<BYTE>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store_1byte(drcontext, mem, src_reg);
}

template <>
instr_t *instr_store<HALF>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store_2bytes(drcontext, mem, src_reg);
}

template <>
instr_t *instr_store<WORD>(void *drcontext, opnd_t mem, opnd_t src_reg)
{
    return XINST_CREATE_store(drcontext, mem, src_reg);
}

template <opnd_sz_t T>
opnd_t opnd_mem(reg_id_t base_reg, int disp)
{
    DR_ASSERT_MSG(false, "Unreachable");
    return {0};
}

template <>
opnd_t opnd_mem<BYTE>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM8(base_reg, disp);
}

template <>
opnd_t opnd_mem<HALF>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM16(base_reg, disp);
}

template <>
opnd_t opnd_mem<WORD>(reg_id_t base_reg, int disp)
{
    return OPND_CREATE_MEM32(base_reg, disp);
}

#ifdef ASM_TAINT

template <opnd_sz_t T>
byte get_app_iters()
{
    DR_ASSERT_MSG(false, "Unreachable");
    return {0};
}

template <>
byte get_app_iters<BYTE>()
{
    return sizeof(char);
}

template <>
byte get_app_iters<HALF>()
{
    return sizeof(short);
}

template <>
byte get_app_iters<WORD>()
{
    return sizeof(int);
}

#endif

template <opnd_sz_t sz>
void propagate_ldr(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    ldr reg1, [mem2]

    We need to save the tag value stored at
    [mem2] shadow address to shadow register of reg1
*/
{
    opnd_t mem2 = instr_get_src(where, 0);
    if (opnd_is_base_disp(mem2))
    {
        auto sreg1 = drreg_reservation{ilist, where};
        auto sapp2 = drreg_reservation{ilist, where};
        reg_id_t reg1 = opnd_get_reg(instr_get_dst(where, 0));

        // get the memory address at mem2 and store the result to %sapp2% register
        drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);

#ifdef ASM_TAINT
        ds_opnds_insert_app_area_to_info(drcontext, ilist, where, sapp2, 1, get_app_iters<sz>());
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
        ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

        // get shadow memory addresses of reg1 and [mem2] and place them to %sreg1% and %sapp2%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);
        drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);

        // place to %sapp2% the value placed at [mem2] shadow address
        instrlist_meta_preinsert(ilist, where,
                                 instr_load<sz>(drcontext, // ldrXX sapp2, [sapp2]
                                                opnd_create_reg(sapp2),
                                                opnd_mem<sz>(sapp2, 0)));

        // determine if need to propagate 3d policy
        bool need_3p = false;
        if (dr_get_isa_mode(drcontext) == DR_ISA_ARM_THUMB &&
            opnd_num_regs_used(mem2) == 2)
        {
            need_3p = true;
        }

        else
        {
            uint raw_bits = instr_get_raw_word(where, 0);
            if (opnd_num_regs_used(mem2) == 2 && is_pre_or_offs_addr(raw_bits))
                need_3p = true;
        }

        // propagate 3d policy: ldr r0, [r1, r2].
        // If r2 is tainted then r0 is tainted too
        if (need_3p)
        {
            reg_id_t reg_ind = opnd_get_index(mem2);
            auto sreg_ind = drreg_reservation{ilist, where};

#ifdef ASM_TAINT
            ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg_ind);
#endif

            // get value of %reg_ind% shadow register and place it to %sreg_ind%
            drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg_ind, sreg_ind);

            instrlist_meta_preinsert(ilist, where,
                                     INSTR_CREATE_orr(drcontext, // sapp2 |= sreg_ind
                                                      opnd_create_reg(sapp2),
                                                      opnd_create_reg(sapp2),
                                                      opnd_create_reg(sreg_ind)));
        }

        // save the value of %sapp2% to shadow register of reg1
        instrlist_meta_preinsert_xl8(ilist, where,
                                     XINST_CREATE_store(drcontext, // str sapp2, [sreg1]
                                                        OPND_CREATE_MEM32(sreg1, 0),
                                                        opnd_create_reg(sapp2)));
    }
}

static void
propagate_ldrd(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    ldrd reg1, reg2, [mem2]

    We need to save the tag value stored at
    [mem2] shadow address to shadow registers reg1, reg2
*/
{
    opnd_t mem2 = instr_get_src(where, 0);
    if (opnd_is_base_disp(mem2))
    {
        auto sreg1 = drreg_reservation{ilist, where};
        auto sapp2 = drreg_reservation{ilist, where};
        auto sapp2n = drreg_reservation{ilist, where};

        reg_id_t reg1 = opnd_get_reg(instr_get_dst(where, 0));
        reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 1));
        reg_id_t sreg2 = sreg1;

        // dereference the memory address at mem2 and store the result to %sapp2% register
        drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);

#ifdef ASM_TAINT
        ds_opnds_insert_app_area_to_info(drcontext, ilist, where, sapp2, sizeof(int), 2);
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
        ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

        // get [mem2 + 4] address
        instrlist_meta_preinsert(ilist, where,
                                 XINST_CREATE_add_2src(drcontext, // add sapp2n, sapp2, #4
                                                       opnd_create_reg(sapp2n),
                                                       opnd_create_reg(sapp2),
                                                       OPND_CREATE_INT32(4)));

        // get shadow memory addresses of reg1 and [mem2] and place them to %sreg1% and %sapp2%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);
        drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);

        // place to %sapp2% the value placed at [mem2] shadow address
        instrlist_meta_preinsert(ilist, where,
                                 XINST_CREATE_load(drcontext, // ldr sapp2, [sapp2]
                                                   opnd_create_reg(sapp2),
                                                   OPND_CREATE_MEM32(sapp2, 0)));

        // save the value of %sapp2% to shadow register of reg1
        instrlist_meta_preinsert_xl8(ilist, where,
                                     XINST_CREATE_store(drcontext, // str sapp2, [sreg1]
                                                        OPND_CREATE_MEM32(sreg1, 0),
                                                        opnd_create_reg(sapp2)));

        // get shadow memory addresses of reg2 and [mem2 + 4] and place them to %sreg2% and %sapp2n%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2n, sreg2);
        drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);

        // place to %sapp2n% the value placed at [mem2 + 4] shadow address
        instrlist_meta_preinsert(ilist, where,
                                 XINST_CREATE_load(drcontext, // ldr sapp2n, [sapp2n]
                                                   opnd_create_reg(sapp2n),
                                                   OPND_CREATE_MEM32(sapp2n, 0)));

        // save the value of %sapp2n% to shadow register of reg2
        instrlist_meta_preinsert_xl8(ilist, where,
                                     XINST_CREATE_store(drcontext, // str sapp2n, [sreg2]
                                                        OPND_CREATE_MEM32(sreg2, 0),
                                                        opnd_create_reg(sapp2n)));
    }
}

template <opnd_sz_t sz>
void propagate_str(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    str reg1, [mem2]  

    We need to save the tag value stored in 
    shadow register of reg1 to shadow address of [mem2] 
*/
{
    opnd_t mem2 = instr_get_dst(where, 0);
    if (opnd_is_base_disp(mem2))
    {
        auto sreg1 = drreg_reservation{ilist, where};
        auto sapp2 = drreg_reservation{ilist, where};
        reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));

        // dereference the memory address at mem2 and store the result to %sapp2% register
        drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);

#ifdef ASM_TAINT
        ds_opnds_insert_app_area_to_info(drcontext, ilist, where, sapp2, 1, get_app_iters<sz>());
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
        ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_APP);
#endif

        // get shadow memory address of [mem2] and place it to %sapp2%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);

        // get value of shadow register of reg1 and place it to %sreg1%
        drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);

        // write the value of reg1 to [mem2] shadow address
        instrlist_meta_preinsert_xl8(ilist, where,
                                     instr_store<sz>(drcontext, // str sreg1, [sapp2]
                                                     opnd_mem<sz>(sapp2, 0),
                                                     opnd_create_reg(sreg1)));

        // if it's a strex then we have to untaint return status register
        // however, return status register becomes untainted without our help (magic?)
        // so, these instructions are optional
        /*
        int opcode = instr_get_opcode(where);
        if (opcode == OP_strex ||
            opcode == OP_strexb ||
            opcode == OP_strexh)
        {
            reg_id_t rd = opnd_get_reg(instr_get_dst(where, 1));
            reg_id_t srd = sreg1;
            reg_id_t nullreg = sapp2;
        
            // nullreg = 0
            instrlist_meta_preinsert(ilist, where,
                                     XINST_CREATE_move(drcontext, // mov nullreg , 0
                                                       opnd_create_reg(nullreg),
                                                       OPND_CREATE_INT32(0)));
        
            // get shadow register address of %rd% and place it to %srd%
            drtaint_insert_reg_to_taint(drcontext, ilist, where, rd, srd);
        
            // write 0 to shadow value of %rd%
            instrlist_meta_preinsert_xl8(ilist, where,
                                         XINST_CREATE_store(drcontext,
                                                           OPND_CREATE_MEM32(srd, 0),
                                                           opnd_create_reg(nullreg)));
        }
        */
    }
}

static void
propagate_strd(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    strd reg1, reg2, [mem2]  

    We need to save the tag values stored in 
    shadow registers of reg2 and reg3 to shadow addresses of [mem2] and [mem2 + 4] 
*/
{
    opnd_t mem2 = instr_get_dst(where, 0);
    if (opnd_is_base_disp(mem2))
    {
        auto sreg1 = drreg_reservation{ilist, where};
        auto sapp2 = drreg_reservation{ilist, where};
        auto sapp2n = drreg_reservation{ilist, where};

        reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
        reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 1));

        // dereference the memory address at mem2 and store the result to %sapp2% register
        drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);

#ifdef ASM_TAINT
        ds_opnds_insert_app_area_to_info(drcontext, ilist, where, sapp2, sizeof(int), 2);
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
        ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
        ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_APP);
#endif

        // get next 4 bytes after [mem2]
        instrlist_meta_preinsert(ilist, where,
                                 XINST_CREATE_add_2src(drcontext, // sapp2n = sapp2 + 4
                                                       opnd_create_reg(sapp2n),
                                                       opnd_create_reg(sapp2),
                                                       OPND_CREATE_INT32(4)));

        // get shadow memory address of [mem2] and place it to %sapp2%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);

        // get value of shadow register of reg1 and place it to %sreg1%
        drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);

        // write the value of reg1 to [mem2] shadow address
        instrlist_meta_preinsert_xl8(ilist, where,
                                     XINST_CREATE_store(drcontext, // str sreg1, [sapp2]
                                                        OPND_CREATE_MEM32(sapp2, 0),
                                                        opnd_create_reg(sreg1)));

        // get shadow memory address of [mem2 + 4] and place it to %sapp2n%
        drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2n, sapp2);

        // get value of shadow register of reg2 and place it to %sreg1%
        drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg1);

        // write the shadow value of reg2 to [mem2 + 4] shadow address
        instrlist_meta_preinsert_xl8(ilist, where,
                                     XINST_CREATE_store(drcontext, // str sreg1, [sapp2n]
                                                        OPND_CREATE_MEM32(sapp2n, 0),
                                                        opnd_create_reg(sreg1)));

        // if it's a strexd then we have to untaint return status register
        // however, return status register becomes untainted without our help (magic?)
        // so, these instructions are optional
        /*if (instr_get_opcode(where) == OP_strexd)
        {
            reg_id_t rd = opnd_get_reg(instr_get_dst(where, 1));
            reg_id_t srd = sreg1;
            reg_id_t nullreg = sapp2;

            // nullreg = 0
            instrlist_meta_preinsert(ilist, where,
                                     XINST_CREATE_move(drcontext,
                                                       opnd_create_reg(nullreg),
                                                       OPND_CREATE_INT32(0)));

            // get shadow register address of %rd% and place it to %srd%
            drtaint_insert_reg_to_taint(drcontext, ilist, where, rd, srd);

            // write 0 to shadow value of %rd%
            instrlist_meta_preinsert_xl8(ilist, where,
                                         XINST_CREATE_store(drcontext, // str nullreg, [strd]
                                                            OPND_CREATE_MEM32(srd, 0),
                                                            opnd_create_reg(nullreg)));
        }*/
    }
}

static void
propagate_mov_regs(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                   reg_id_t reg1, reg_id_t reg2)
/*
    mov reg2, reg1

    Need to save the tag value of reg1's 
    shadow register to reg2's shadow register
*/
{
#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg2 = drreg_reservation{ilist, where};
    auto sreg1 = drreg_reservation{ilist, where};

    // get value of shadow register of reg1 and place it to %sreg1%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);

    // get shadow register address of reg2 and place it to %sreg2%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);

    // write shadow value of reg1 to shadow value of reg2
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg2]
                                                OPND_CREATE_MEM32(sreg2, 0),
                                                opnd_create_reg(sreg1)));
}

static void
propagate_mov_reg_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* mov reg2, reg1 */
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
    propagate_mov_regs(drcontext, tag, ilist, where, reg1, reg2);
}

static void
propagate_mov_imm_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    mov reg2, imm1

    Saves the value of 0 to the shadow register 
    of reg2 because moving constant to reg2 untaints reg2
*/
{
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg2 = drreg_reservation{ilist, where};
    auto simm2 = drreg_reservation{ilist, where};

    // get shadow register address of reg2 and place it to %sreg2%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);

    // place constant imm to register %simm2%
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_move(drcontext, // mov simm2, 0
                                               opnd_create_reg(simm2),
                                               OPND_CREATE_INT32(0)));

    // move to shadow register of reg2 the value of imm1
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str simm2, [sreg2]
                                                OPND_CREATE_MEM32(sreg2, 0),
                                                opnd_create_reg(simm2)));
}

static void
propagate_arith_reg_imm(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    [add | sub | ... ] reg2, reg1, imm

    Need to mark reg2 tainted by tag of reg1
*/
{
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg2 = drreg_reservation{ilist, where};
    auto sreg1 = drreg_reservation{ilist, where};

    // get value of shadow register of reg1 and place it to %sreg1%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);

    // get shadow register address of reg2 and place it to %sreg2%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);

    // write the result to shadow register of reg2
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg2]
                                                OPND_CREATE_MEM32(sreg2, 0),
                                                opnd_create_reg(sreg1)));
}

static void
propagate_arith_reg_reg(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/*
    [add | sub | ... ] reg3, reg2, reg1

    Need to mark reg3 tainted. 
    Because its value depends on values of reg2, reg1, 
    we use OR to combine their impacts to reg3
*/
{
    reg_id_t reg3 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 1));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg3);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg2 = drreg_reservation{ilist, where};
    auto sreg1 = drreg_reservation{ilist, where};
    reg_id_t sreg3 = sreg2; /* we reuse a register for this */

    // get value of shadow registers of reg1, reg2 and place it to %sreg1%, %sreg2%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg2);

    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= sreg2
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg1)));

    // get shadow address of reg3 and place it to %sreg3%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg3, sreg3);

    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg3]
                                                OPND_CREATE_MEM32(sreg3, 0),
                                                opnd_create_reg(sreg1)));
}

static void
propagate_1rd_3rs(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/* 
    mla reg4, reg3, reg2, reg1 

    Need to mark reg4 tainted. 
    Because its value depends on values of reg3, reg2, reg1, 
    we use OR to combine their impacts to reg4
*/
{
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 2));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 1));
    reg_id_t reg3 = opnd_get_reg(instr_get_src(where, 0));
    reg_id_t reg4 = opnd_get_reg(instr_get_dst(where, 0));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg3);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg4);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg1 = drreg_reservation{ilist, where};
    auto sreg2 = drreg_reservation{ilist, where};
    reg_id_t sreg3 = sreg2;
    reg_id_t sreg4 = sreg3; /* we reuse a register for this */

    // get value of shadow registers of reg1, reg2 and place it to %sreg1%, %sreg2%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg2);

    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= sreg2
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg1)));

    // get value of shadow register of reg3 and place it to %sreg3%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg3, sreg3);

    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= sreg3
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg3),
                                              opnd_create_reg(sreg1)));

    // get address of shadow register of reg4 and place it to %sreg4%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg4, sreg4);

    // save the result to shadow register of reg4
    instrlist_meta_preinsert_xl8(ilist, where,
                                 XINST_CREATE_store(drcontext, // str sreg1, [sreg4]
                                                    OPND_CREATE_MEM32(sreg4, 0),
                                                    opnd_create_reg(sreg1)));
}

static void
propagate_mull(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/* 
    umull reg4, reg3, reg2, reg1 

    Need to mark reg3 and reg4 tainted. 
    Because their values depend on values of reg2, reg1, 
    we use OR to combine their impacts to reg3 and reg4
*/
{
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 1));
    reg_id_t reg3 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg4 = opnd_get_reg(instr_get_dst(where, 1));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg3);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg4);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg1 = drreg_reservation{ilist, where};
    auto sreg2 = drreg_reservation{ilist, where};
    reg_id_t sreg3 = sreg2; /* we reuse a register for this */
    reg_id_t sreg4 = sreg3;

    // get value of shadow registers of reg1, reg2 and place it to %sreg1%, %sreg2%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg2);

    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= sreg2
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg1)));

    // get address of shadow register of reg3 and place it to %sreg3%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg3, sreg3);

    // save the higher part of result to shadow register of reg3
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg3]
                                                OPND_CREATE_MEM32(sreg3, 0),
                                                opnd_create_reg(sreg1)));

    // get address of shadow register of reg4 and place it to %sreg4%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg4, sreg4);

    // save the the lower part of result to shadow register of reg4
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg4]
                                                OPND_CREATE_MEM32(sreg4, 0),
                                                opnd_create_reg(sreg1)));
}

static void
propagate_smlal(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
/* 
    smlal rdlo, rdhi, reg1, reg2 

    rdlo, rdhi - source and destination registers 

    Need to mark rdlo and rdhi tainted. 
    Because their values depend on values of reg2, reg1
    we use OR to combine their impacts to rdlo and rdhi    
*/
{
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 2));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 3));
    reg_id_t rdlo = opnd_get_reg(instr_get_src(where, 1));
    reg_id_t rdhi = opnd_get_reg(instr_get_src(where, 0));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, rdlo);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, rdhi);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg1 = drreg_reservation{ilist, where};
    auto sreg2 = drreg_reservation{ilist, where};
    auto sreg3 = drreg_reservation{ilist, where};
    reg_id_t srdlo = sreg2;
    reg_id_t srdhi = srdlo;

    // get value of shadow registers of reg1, reg2 and place it to %sreg1%, %sreg2%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg2);

    // combine tags of reg1, reg2
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= sreg2
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg1)));

    // copy tag1 | tag2 to sreg3
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_mov(drcontext, // sreg3 = reg1
                                              opnd_create_reg(sreg3),
                                              opnd_create_reg(sreg1)));

    // get value of shadow register of rdlo and place it to %srdlo%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, rdlo, srdlo);

    // combine tags of reg1, reg2, rdlo
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg1 |= srdlo
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(srdlo),
                                              opnd_create_reg(sreg1)));

    // get address of shadow register of rdlo and place it to %srdlo%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, rdlo, srdlo);

    // save the the lower part of result to shadow register of rdlo
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [srdlo]
                                                OPND_CREATE_MEM32(srdlo, 0),
                                                opnd_create_reg(sreg1)));

    // get value of shadow register of rdhi and place it to %srdhi%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, rdhi, srdhi);

    // combine tags of reg1, reg2, rdhi
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext, // sreg3 |= srdhi
                                              opnd_create_reg(sreg3),
                                              opnd_create_reg(srdhi),
                                              opnd_create_reg(sreg3)));

    // get address of shadow register of rdlo and place it to %srdlo%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, rdhi, srdhi);

    // save the the higher part of result to shadow register of rdhi
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [srdhi]
                                                OPND_CREATE_MEM32(srdhi, 0),
                                                opnd_create_reg(sreg3)));
}

static void
propagate_pkhXX(void *drcontext, void *tag, instrlist_t *ilist,
                instr_t *where, bool is_pkhbt)
/*
    pkh [bt | tb] r0, r1, r2
    Need to mark r0 tainted. 
    r0's tag value depends on 0:15, 16:31 bits of r1, r2
*/
{
    reg_id_t reg0 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 1));

#ifdef ASM_TAINT
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg0);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg1);
    ds_opnds_insert_reg_id_to_info(drcontext, ilist, where, reg2);
    ds_opnds_insert_tainted_to_info(drcontext, ilist, where, SUPPOSE_TAINTED_REG);
#endif

    auto sreg1 = drreg_reservation{ilist, where};
    auto sreg2 = drreg_reservation{ilist, where};
    auto simm = drreg_reservation{ilist, where};
    reg_id_t sreg0 = simm;

    // ---- get 0xFFFF constant and place it to %simm%
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_mov(drcontext,
                                              opnd_create_reg(simm),
                                              OPND_CREATE_INT32(0x10000)));

    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_sub(drcontext,
                                              opnd_create_reg(simm),
                                              opnd_create_reg(simm),
                                              OPND_CREATE_INT32(1)));

    // shift %simm% left if pkhbt
    if (!is_pkhbt)
        instrlist_meta_preinsert(ilist, where,
                                 INSTR_CREATE_lsl(drcontext,
                                                  opnd_create_reg(simm),
                                                  opnd_create_reg(simm),
                                                  OPND_CREATE_INT32(16)));

    // get value of shadow register of reg1 and place it to %sreg1%
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg1, sreg1);
    drtaint_insert_reg_to_taint_load(drcontext, ilist, where, reg2, sreg2);

    // get bits x:y of %sreg1%
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_and(drcontext,
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(simm)));

    // shift %simm% right if pkhtb
    // shift %simm% left if pkhbt
    if (!is_pkhbt)
        instrlist_meta_preinsert(ilist, where,
                                 INSTR_CREATE_lsr(drcontext,
                                                  opnd_create_reg(simm),
                                                  opnd_create_reg(simm),
                                                  OPND_CREATE_INT32(16)));
    else
        instrlist_meta_preinsert(ilist, where,
                                 INSTR_CREATE_lsl(drcontext,
                                                  opnd_create_reg(simm),
                                                  opnd_create_reg(simm),
                                                  OPND_CREATE_INT32(16)));

    // get bits x:y of %sreg2%
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_and(drcontext,
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(simm)));
    // combine tags of %sreg1%, %sreg2%
    instrlist_meta_preinsert(ilist, where,
                             INSTR_CREATE_orr(drcontext,
                                              opnd_create_reg(sreg1),
                                              opnd_create_reg(sreg2),
                                              opnd_create_reg(sreg1)));

    // get shadow register address of reg0 and place it to %sreg0%
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg0, sreg0);

    // write shadow value of reg1 to shadow value of reg2
    instrlist_meta_preinsert(ilist, where,
                             XINST_CREATE_store(drcontext, // str sreg1, [sreg0]
                                                OPND_CREATE_MEM32(sreg0, 0),
                                                opnd_create_reg(sreg1)));
}

// decrement before, increment after, decrement after, increment before
typedef enum
{
    DB,
    IA,
    DA,
    IB
} stack_dir_t;

template <stack_dir_t T>
app_pc calculate_addr(instr_t *instr, void *base, int i, int top)
{
    DR_ASSERT_MSG(false, "Unreachable");
}

template <>
app_pc calculate_addr<DB>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base - 4 * (top - i);
}

template <>
app_pc calculate_addr<IA>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base + 4 * i;
}

template <>
app_pc calculate_addr<DA>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base - 4 * (top - i - 1);
}

template <>
app_pc calculate_addr<IB>(instr_t *instr, void *base, int i, int top)
{
    return (app_pc)base + 4 * (i + 1);
}

#ifdef ASM_TAINT

template <stack_dir_t T>
byte get_delta()
{
    DR_ASSERT_MSG(false, "Unreachable");
    return 0;
}

template <>
byte get_delta<DB>()
{
    return -4;
}

template <>
byte get_delta<IA>()
{
    return 4;
}

template <>
byte get_delta<DA>()
{
    return -4;
}

template <>
byte get_delta<IB>()
{
    return 4;
}

#endif

template <stack_dir_t c>
void propagate_ldm_cc_template(void *pc, void *base, bool writeback)
/*
    ldm r, { regs }

    When handling a ldm command we have to save all values of registers
    that will be popped from a stack to their shadow registers
*/
{
    void *drcontext = dr_get_current_drcontext();
    instr_t *instr = instr_create(drcontext);
    decode(drcontext, (byte *)pc, instr);

    int num_dsts = instr_num_dsts(instr);
    if (writeback)
        num_dsts--;

#ifdef ASM_TAINT
    ds_opnds_tainted_to_info(drcontext, SUPPOSE_TAINTED_REG);
    ds_opnds_app_area_to_info(drcontext,
                              calculate_addr<c>(instr, base, 0, num_dsts),
                              get_delta<c>(),
                              num_dsts);
#endif

    for (int i = 0; i < num_dsts; ++i)
    {
        bool ok;

        // ? why 1 instead of 0
        // ? why do we need this
        if (writeback &&
            (opnd_get_reg(instr_get_dst(instr, i)) ==
             opnd_get_reg(instr_get_src(instr, 1))))
            break;

        // set taint from stack to the appropriate register
        uint res;
        ok = drtaint_get_app_taint4(drcontext, calculate_addr<c>(instr, base, i, num_dsts), &res);
        DR_ASSERT(ok);
        ok = drtaint_set_reg_taint(drcontext, opnd_get_reg(instr_get_dst(instr, i)), res);
        DR_ASSERT(ok);

#ifdef ASM_TAINT
        ds_opnds_reg_id_to_info(drcontext, opnd_get_reg(instr_get_dst(instr, i)));
#endif
    }

    instr_destroy(drcontext, instr);
}

template <stack_dir_t c>
void propagate_stm_cc_template(void *pc, void *base, bool writeback)
/*
    stm r, { regs }
    
    When handling a stm command we have to set all memory 
    in the stack where the register values will be written tainted
*/
{
    void *drcontext = dr_get_current_drcontext();
    instr_t *instr = instr_create(drcontext);
    decode(drcontext, (byte *)pc, instr);

    int num_srcs = instr_num_srcs(instr);
    if (writeback)
        num_srcs--;

#ifdef ASM_TAINT
    ds_opnds_tainted_to_info(drcontext, SUPPOSE_TAINTED_APP);
    ds_opnds_app_area_to_info(drcontext,
                              calculate_addr<c>(instr, base, 0, num_srcs),
                              get_delta<c>(),
                              num_srcs);
#endif

    for (int i = 0; i < num_srcs; ++i)
    {
        bool ok;

        // ? why 1 instead of 0
        // ? why do we need this
        if (writeback &&
            (opnd_get_reg(instr_get_src(instr, i)) ==
             opnd_get_reg(instr_get_dst(instr, 1))))
            break;

        // set taint from registers to the stack
        uint res;
        ok = drtaint_get_reg_taint(drcontext, opnd_get_reg(instr_get_src(instr, i)), &res);
        DR_ASSERT(ok);
        ok = drtaint_set_app_taint4(drcontext, calculate_addr<c>(instr, base, i, num_srcs), res);
        DR_ASSERT(ok);

#ifdef ASM_TAINT
        ds_opnds_reg_id_to_info(drcontext, opnd_get_reg(instr_get_src(instr, i)));
#endif
    }
    instr_destroy(drcontext, instr);
}

static bool
instr_handle_constant_func(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    short opcode = instr_get_opcode(where);

    if (opcode == OP_eor ||
        opcode == OP_eors ||
        opcode == OP_sub ||
        opcode == OP_subs ||
        opcode == OP_sbc ||
        opcode == OP_sbcs)
    {
        // xor r1, r0, r0 causes r1 to be untainted
        if (!opnd_is_reg(instr_get_src(where, 0)))
            return false;

        if (!opnd_is_reg(instr_get_src(where, 1)))
            return false;

        if (opnd_get_reg(instr_get_src(where, 0)) !=
            opnd_get_reg(instr_get_src(where, 1)))
            return false;

        // mov r1, imm
        propagate_mov_imm_src(drcontext, tag, ilist, where);
        return true;
    }
    return false;
}

static void
untaint_stack(void *drcontext, app_pc sp_val, ptr_int_t imm)
{
    drtaint_set_app_area_taint(drcontext, sp_val - imm, imm, 0);
}

static bool
instr_affects_on_flags(int opcode)
{
    switch (opcode)
    {
    // these four instruction always update flags
    case OP_cmp:
    case OP_cmn:
    case OP_tst:
    case OP_teq:

    // other instructions must have {S} suffix
    case OP_adcs:
    case OP_adds:
    case OP_ands:
    case OP_asrs:
    case OP_bics:
    case OP_eors:
    case OP_lsls:
    case OP_lsrs:
    case OP_mlas:
    case OP_mls:
    case OP_movs:
    case OP_muls:
    case OP_mvns:
    case OP_orns:
    case OP_orrs:
    case OP_rors:
    case OP_rrxs:
    case OP_rsbs:
    case OP_rscs:
    case OP_msr: // writes to cspr directly
    case OP_sbcs:
    case OP_subs:

    case OP_smlals:
    case OP_smmls:
    case OP_smulls:
    case OP_umlals:
    case OP_umulls:

        return true;
    }

    return false;
}

static bool
instr_predicate_is_true(instr_t *where, uint cspr)
{
    switch (instr_get_predicate(where))
    {
    case DR_PRED_EQ:
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_Z);

    case DR_PRED_NE:
        return DRT_TEST_FLAG_DOWN(cspr, EFLAGS_Z);

    case DR_PRED_CS:
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_C);

    case DR_PRED_CC:
        return DRT_TEST_FLAG_DOWN(cspr, EFLAGS_C);

    case DR_PRED_MI:
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_N);

    case DR_PRED_PL:
        return DRT_TEST_FLAG_DOWN(cspr, EFLAGS_N);

    case DR_PRED_VS:
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_V);

    case DR_PRED_VC:
        return DRT_TEST_FLAG_DOWN(cspr, EFLAGS_V);

    case DR_PRED_HI: //+
        return DRT_TEST_FLAG_DOWN(cspr, EFLAGS_Z) && DRT_TEST_FLAG_UP(cspr, EFLAGS_C);

    case DR_PRED_LS: //+
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_Z) || DRT_TEST_FLAG_DOWN(cspr, EFLAGS_C);

    case DR_PRED_GE: //+
        return DRT_TEST_FLAGS_UP(cspr, EFLAGS_N | EFLAGS_V) ||
               DRT_TEST_FLAGS_DOWN(cspr, EFLAGS_N | EFLAGS_V);

    case DR_PRED_LT: //+
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_N) && DRT_TEST_FLAG_DOWN(cspr, EFLAGS_V) ||
               DRT_TEST_FLAG_DOWN(cspr, EFLAGS_N) && DRT_TEST_FLAG_UP(cspr, EFLAGS_V);

    case DR_PRED_GT: //+
        return (DRT_TEST_FLAGS_UP(cspr, EFLAGS_N | EFLAGS_V) && DRT_TEST_FLAG_DOWN(cspr, EFLAGS_Z)) ||
               DRT_TEST_FLAGS_DOWN(cspr, EFLAGS_N | EFLAGS_V | EFLAGS_Z);

    case DR_PRED_LE: //+
        return DRT_TEST_FLAG_UP(cspr, EFLAGS_Z) ||
               DRT_TEST_FLAG_UP(cspr, EFLAGS_N) && DRT_TEST_FLAG_DOWN(cspr, EFLAGS_V) ||
               DRT_TEST_FLAG_DOWN(cspr, EFLAGS_N) && DRT_TEST_FLAG_UP(cspr, EFLAGS_V);

    case DR_PRED_AL:
        return true;
    }

    return false;
}

/* ======================================================================================
 * main: event app instruction handler
 * ==================================================================================== */

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    if (instr_is_meta(where))
        return DR_EMIT_DEFAULT;

#ifdef ASM_TAINT
    ds_opnds_insert_clear_info(drcontext, ilist, where);
#endif

    int opcode = instr_get_opcode(where);

    // get opcode of previsous instruction
    // if it changes cpsr then update shadow cpsr
    if (instr_affects_on_flags(ds_get_prev_instr(drcontext)))
    {
        uint flags = instr_get_arith_flags(where, DR_QUERY_INCLUDE_ALL);
        ds_update_cpsr(drcontext, flags);
    }

    // save current opcode
    ds_save_instr(drcontext, opcode);

    // check if instruction is conditionally executed
    // if predication is false we don't need to continue
    if (instr_is_predicated(where))
    {
        uint flags = ds_get_cpsr(drcontext);
        if (!instr_predicate_is_true(where, flags))
            goto dr_emit_default;
    }

    // untaint stack area when allocating a new frame
    if (opcode == OP_sub || opcode == OP_subs)
    {
        if (opnd_get_reg(instr_get_dst(where, 0)) == DR_REG_SP &&
            opnd_get_reg(instr_get_src(where, 0)) == DR_REG_SP &&
            opnd_is_immed(instr_get_src(where, 1)))
        {
            dr_insert_clean_call(drcontext, ilist, where, (void *)untaint_stack, false, 3,
                                 OPND_CREATE_INTPTR(drcontext),
                                 opnd_create_reg(DR_REG_SP),
                                 instr_get_src(where, 1));
        }
    }

    if (propagate_default_isa(drcontext, tag, ilist, where, opcode, user_data))
        goto dr_emit_default;

    if (propagate_simd_isa(drcontext, tag, ilist, where, opcode, user_data))
        goto dr_emit_default;

dr_emit_default:

#ifdef ASM_TAINT
    ds_opnds_insert_callback(drcontext, ilist, where);
#endif
    return DR_EMIT_DEFAULT;
}

/* ======================================================================================
 * system call clearing and handling routines
 * ==================================================================================== */

static bool
drsys_iter_cb(drsys_arg_t *arg, void *drcontext)
/*
    Set syscall output parameters untainted 
*/
{
    if (!arg->valid)
        return true;

    if (arg->pre)
        return true;

#define TEST(mask, var) (((mask) & (var)) != 0)

    if (TEST(arg->mode, DRSYS_PARAM_OUT))
    {
        char *buffer = (char *)arg->start_addr;
        for (int i = 0; i < arg->size; ++i)
        {
            if (!drtaint_set_app_taint(drcontext,
                                       (app_pc)buffer + i, 0))
                DR_ASSERT(false);
        }
    }
#undef TEST
    return true;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (drsys_iterate_memargs(drcontext, drsys_iter_cb, drcontext) !=
        DRMF_SUCCESS)
        DR_ASSERT(false);
    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    dr_syscall_result_info_t info = {
        sizeof(info),
    };
    dr_syscall_get_result_ex(drcontext, &info);

    /* all syscalls untaint rax */
    drtaint_set_reg_taint(drcontext, DR_REG_R0, (byte)0);

    if (!info.succeeded)
    {
        /* We only care about tainting if the syscall
         * succeeded.
         */
        return;
    }

    /* clear taint for system calls with an OUT memarg param */
    if (drsys_iterate_memargs(drcontext, drsys_iter_cb, drcontext) !=
        DRMF_SUCCESS)
        DR_ASSERT(false);
}

/* ======================================================================================
 * default isa taint propagation handling
 * ==================================================================================== */

/*  
    We define a routine to make it easier to call drreg_restore_app_value() in
    the case that we have to swap a register out to make space for the stolen reg.
*/
#define DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, opnd, cb)      \
    do                                                                  \
    {                                                                   \
        reg_id_t swap = DR_REG_NULL;                                    \
        drreg_restore_app_values(drcontext, ilist, where, opnd, &swap); \
        cb;                                                             \
        if (swap != DR_REG_NULL)                                        \
            drreg_unreserve_register(drcontext, ilist, where, swap);    \
    } while (false);

static bool
propagate_default_isa(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      int opcode, void *user_data)
{
    if (instr_handle_constant_func(drcontext, tag, ilist, where))
        return true;

    switch (opcode)
    {
    case OP_ldmia:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_src(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_ldm_cc_template<IA>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_src(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_srcs(where) > 1));
        });
        break;
    case OP_ldmdb:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_src(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_ldm_cc_template<DB>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_src(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_srcs(where) > 1));
        });
        break;
    case OP_ldmib:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_src(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_ldm_cc_template<IB>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_src(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_srcs(where) > 1));
        });
        break;
    case OP_ldmda:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_src(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_ldm_cc_template<DA>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_src(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_srcs(where) > 1));
        });
        break;
    case OP_stmia:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_dst(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_stm_cc_template<IA>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_dst(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_dsts(where) > 1));
        });
        break;
    case OP_stmdb:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_dst(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_stm_cc_template<DB>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_dst(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_dsts(where) > 1));
        });
        break;
    case OP_stmib:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_dst(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_stm_cc_template<IB>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_dst(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_dsts(where) > 1));
        });
        break;
    case OP_stmda:
        DRREG_RESTORE_APP_VALUE(drcontext, ilist, where, instr_get_dst(where, 0), {
            dr_insert_clean_call(drcontext, ilist, where, (void *)propagate_stm_cc_template<DA>,
                                 false, 3, OPND_CREATE_INTPTR(instr_get_app_pc(where)),
                                 opnd_create_reg(opnd_get_base(instr_get_dst(where, 0))),
                                 /* writeback */
                                 OPND_CREATE_INT8(instr_num_dsts(where) > 1));
        });
        break;

    case OP_ldr:
    case OP_ldrex:
    case OP_ldrt:

        propagate_ldr<WORD>(drcontext, tag, ilist, where);
        break;

    case OP_ldrh:
    case OP_ldrsh:
    case OP_ldrexh:
    case OP_ldrht:
    case OP_ldrsht:

        propagate_ldr<HALF>(drcontext, tag, ilist, where);
        break;

    case OP_ldrb:
    case OP_ldrsb:
    case OP_ldrexb:
    case OP_ldrbt:
    case OP_ldrsbt:

        propagate_ldr<BYTE>(drcontext, tag, ilist, where);
        break;

    case OP_ldrd:
    case OP_ldrexd:

        propagate_ldrd(drcontext, tag, ilist, where);
        break;

    case OP_str:
    case OP_strex:
    case OP_strt:

        propagate_str<WORD>(drcontext, tag, ilist, where);
        break;

    case OP_strh:
    case OP_strexh:
    case OP_strht:

        propagate_str<HALF>(drcontext, tag, ilist, where);
        break;

    case OP_strb:
    case OP_strexb:
    case OP_strbt:

        propagate_str<BYTE>(drcontext, tag, ilist, where);
        break;

    case OP_strd:
    case OP_strexd:

        propagate_strd(drcontext, tag, ilist, where);
        break;

    case OP_mov:
    case OP_mvn:
    case OP_mvns:
    case OP_movs:
    case OP_movw:
    case OP_movt:

        if (opnd_is_reg(instr_get_src(where, 0)))
            propagate_mov_reg_src(drcontext, tag, ilist, where);
        else
            propagate_mov_imm_src(drcontext, tag, ilist, where);

        break;

    case OP_rrx:
    case OP_rrxs:
    case OP_sbfx:
    case OP_ubfx:
    case OP_uxtb:
    case OP_uxth:
    case OP_sxtb:
    case OP_sxtb16:
    case OP_sxth:
    case OP_uxtb16:
    case OP_rev:
    case OP_rev16:
    case OP_revsh:
    case OP_rbit:
    case OP_bfi:
    case OP_clz:

        /* These aren't mov's per se, but they only accept 1
         * reg source and 1 reg dest.
         */
        if (instr_num_dsts(where) > 0) // some instructions contain optional Rd
            propagate_mov_reg_src(drcontext, tag, ilist, where);

        break;

    // op rd, r1, op2
    case OP_adc:
    case OP_adcs:
    case OP_add:
    case OP_adds:
    case OP_addw:
    case OP_rsb:
    case OP_rsbs:
    case OP_rsc:
    case OP_rscs:
    case OP_sbc:
    case OP_sbcs:
    case OP_sub:
    case OP_subw:
    case OP_subs:
    case OP_and:
    case OP_ands:
    case OP_bic:
    case OP_bics:
    case OP_eor:
    case OP_eors:
    case OP_orr:
    case OP_orrs:
    case OP_ror:
    case OP_rors:
    case OP_lsl:
    case OP_lsls:
    case OP_lsr:
    case OP_lsrs:
    case OP_asr:
    case OP_asrs:
    case OP_orn:
    case OP_orns:

        if (instr_num_dsts(where) > 0) // some instructions contain optional Rd
        {
            if (opnd_is_reg(instr_get_src(where, 1)))
                propagate_arith_reg_reg(drcontext, tag, ilist, where);
            else
                propagate_arith_reg_imm(drcontext, tag, ilist, where);
        }

        break;

    // op rd, r1, r2
    case OP_mul:
    case OP_muls:

    case OP_shsub16:
    case OP_shsub8:
    case OP_sdiv:
    case OP_sadd16:
    case OP_sadd8:
    case OP_sasx:
    case OP_ssax:
    case OP_ssub16:
    case OP_ssub8:
    case OP_sxtab:
    case OP_sxtab16:
    case OP_sxtah:

    case OP_qadd:
    case OP_qadd16:
    case OP_qadd8:
    case OP_qasx:
    case OP_qdadd:
    case OP_qdsub:
    case OP_qsax:
    case OP_qsub:
    case OP_qsub16:
    case OP_qsub8:

    case OP_udiv:
    case OP_uadd8:
    case OP_uadd16:
    case OP_usax:
    case OP_usub16:
    case OP_usub8:
    case OP_uasx:
    case OP_uqadd16:
    case OP_uqadd8:
    case OP_uqasx:
    case OP_uqsax:
    case OP_uqsub16:
    case OP_usad8:

    case OP_uhadd16:
    case OP_uhadd8:
    case OP_uhasx:
    case OP_uhsax:
    case OP_uhsub16:
    case OP_uhsub8:

    case OP_smmul:
    case OP_smmulr:
    case OP_smuad:
    case OP_smuadx:
    case OP_smulbb:
    case OP_smulbt:
    case OP_smultb:
    case OP_smultt:
    case OP_smulwb:
    case OP_smulwt:
    case OP_smusd:
    case OP_smusdx:

    case OP_uxtab:
    case OP_uxtab16:
    case OP_uxtah:

        if (instr_num_dsts(where) > 0) // some instructions contain optional Rd
            propagate_arith_reg_reg(drcontext, tag, ilist, where);

        break;

    // op rd1, rd2, r1, r2
    case OP_smull:
    case OP_smulls:
    case OP_umull:
    case OP_umulls:

        propagate_mull(drcontext, tag, ilist, where);
        break;

    // op rdlo, rdhi, r1, r2
    case OP_smlal:
    case OP_smlalbb:
    case OP_smlalbt:
    case OP_smlald:
    case OP_smlaldx:
    case OP_smlals:
    case OP_smlaltb:
    case OP_smlaltt:
    case OP_smlsld:
    case OP_smlsldx:
    case OP_umaal:
    case OP_umlal:
    case OP_umlals:

        propagate_smlal(drcontext, tag, ilist, where);
        break;

    // op rd, r1, r2, r3
    case OP_mla:
    case OP_mlas:
    case OP_mls:

    case OP_smlabb:
    case OP_smlabt:
    case OP_smlatb:
    case OP_smlatt:
    case OP_smlad:
    case OP_smladx:
    case OP_smlawb:
    case OP_smlawt:
    case OP_smlsd:
    case OP_smlsdx:
    case OP_smmla:
    case OP_smmlar:
    case OP_smmls:
    case OP_smmlsr:
    case OP_usada8:

        propagate_1rd_3rs(drcontext, tag, ilist, where);
        break;

    case OP_pkhbt:

        propagate_pkhXX(drcontext, tag, ilist, where, true);
        break;

    case OP_pkhtb:

        propagate_pkhXX(drcontext, tag, ilist, where, false);
        break;

        // ===================================

    case OP_swp:
    case OP_swpb:
        break;

    case OP_usat:
    case OP_usat16:
    case OP_ssat:
    case OP_ssat16:

        break;
        // ===================================

    case OP_bl:
    case OP_blx:
    case OP_blx_ind:

        // lr = next_instr(pc)
        // then taint lr
        propagate_mov_regs(drcontext, tag, ilist, where,
                           DR_REG_LR, DR_REG_PC);

        // fallthrough, we could have a register dest

    case OP_bxj:
    case OP_bx:
    case OP_b:
    case OP_b_short:

        // could have register destination
        if (opnd_is_reg(instr_get_src(where, 0)))
        {
            propagate_mov_regs(drcontext, tag, ilist, where,
                               opnd_get_reg(instr_get_src(where, 0)),
                               DR_REG_PC);
        }

        // we don't have to do anything for immediates
        break;

    default:
        return false;
    }

    return true;
}