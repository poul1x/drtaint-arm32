#include "drtaint_helper.h"

drreg_reservation::
    drreg_reservation(instrlist_t *ilist, instr_t *where)
    : drcontext_(dr_get_current_drcontext()),
      ilist_(ilist), where_(where)
{
    DR_ASSERT(drreg_reserve_register(drcontext_, ilist_, where_, NULL, &reg_) == DRREG_SUCCESS);
}

drreg_reservation::
    ~drreg_reservation()
{
    drreg_unreserve_register(drcontext_, ilist_, where_, reg_);
}

void unimplemented_opcode(instr_t *where)
{
    /* N/A */
}

void instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert)
{
    instrlist_meta_preinsert(ilist, where, INSTR_XL8(insert, instr_get_app_pc(where)));
}
