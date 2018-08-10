#ifndef DRTAINT_HELPER_H_
#define DRTAINT_HELPER_H_

#include "dr_api.h"
#include "drreg.h"

#ifdef __cplusplus
extern "C"
{
#endif

  class drreg_reservation
  {
  public:
    drreg_reservation(instrlist_t *ilist, instr_t *where);
    ~drreg_reservation();
    operator reg_id_t() const { return reg_; }

  private:
    instrlist_t *ilist_;
    instr_t *where_;
    reg_id_t reg_;
    void *drcontext_;
  };

  class load_store_helper
  {
    // arm32 mode load and store instructions only

  public:
    load_store_helper(instr_t *where);
    ~load_store_helper();

    bool is_pre_addr();
    bool is_post_addr();
    bool is_pre_or_offs_addr();
    bool is_offs_addr();
    bool is_imm_offs();
    bool is_reg_offs();

  private:
    uint raw_instr_bits;

    // type1 - LDR|STR{<cond>}H|SH|SB|D <Rd>, <addressing_mode>
    // type2 - LDR|STR{<cond>}{B}{T} <Rd>, <addressing_mode>
    bool type1;
  };

  void 
  load_store_info(instr_t * where);

  void
  unimplemented_opcode(instr_t *where);

  void
  instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert);

  void
  what_are_srcs(instr_t *where);

  void
  what_are_dsts(instr_t *where);

#ifdef __cplusplus
}
#endif

#endif
