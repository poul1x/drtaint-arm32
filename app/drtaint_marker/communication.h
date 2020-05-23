#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "dr_api.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    bool cmn_send_load_request(dr_mcontext_t *mc, ptr_uint_t load_addr, ptr_uint_t libc_addr,
                               ptr_uint_t target_addr, uint32_t tc_length);

    bool cmn_send_solve_request(const char *buf, uint32_t buf_len,
                                uint32_t taint, uint32_t taint_offs, app_pc cmp_addr);

    bool cmn_send_next_tc_request(char *buf, uint32_t buf_sz);

#ifdef __cplusplus
}
#endif

#endif