#ifndef DRTAINT_HELPER_H_
#define DRTAINT_HELPER_H_

#include "dr_api.h"
#include "drreg.h"

#define TEST(mask, var) (((mask) & (var)) != 0)

#define IS_BIT_UP(word, bit) (((word) & (1 << bit)))
#define IS_BIT_DOWN(word, bit) (!((word) & (1 << bit)))

#define DRT_SET_FLAGS_UP(cpsr, flags) ((cpsr) |= (flags))
#define DRT_SET_FLAGS_DOWN(cpsr, flags) ((cpsr) &= ~(flags))
#define DRT_TEST_FLAGS_UP(cpsr, flags) (((cpsr) & (flags)) >= (flags))
#define DRT_TEST_FLAGS_DOWN(cpsr, flags) (!((cpsr) & (flags)))


#ifdef __cplusplus
extern "C" {
#endif

class drreg_reservation
{
public:
  drreg_reservation(void *drcontext, instrlist_t *ilist, instr_t *where);
  ~drreg_reservation();
  operator reg_id_t() const { return reg_; }

private:
  void *drcontext_;
  instrlist_t *ilist_;
  instr_t *where_;
  reg_id_t reg_;
};

bool is_pre_addr(uint raw_instr_bits);

bool is_post_addr(uint raw_instr_bits);

bool is_pre_or_offs_addr(uint raw_instr_bits);

bool is_offs_addr(uint raw_instr_bits);

void unimplemented_opcode(instr_t *where);

void instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert);

void what_are_srcs(instr_t *where);

void what_are_dsts(instr_t *where);

#ifdef __cplusplus
}
#endif

#endif
