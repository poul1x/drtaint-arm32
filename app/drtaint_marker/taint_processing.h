#ifndef TAINT_PROCESSING_H_
#define TAINT_PROCESSING_H_

#include "dr_api.h"
#include <string>
#include <vector>

struct u_integer
{
	enum u_sz
	{
		sz1_byte,
		sz2_bytes,
		sz4_bytes,
	} sz;

	union {
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
	};
};

struct tainted_opnd
{
	enum o_type
	{
		addr,
		reg
	} type;

	union {
		reg_id_t reg_num;
		uint32_t address;
	};

	u_integer value;
	u_integer taint;
};


using tainted_opnd_vec = std::vector<tainted_opnd>;

struct tainted_instr
{
	byte* pc;
	u_integer bytes;
	tainted_opnd_vec operands;
};

void tainted_instr_save_bytes_addr(void* drcontext, instr_t *instr, tainted_instr* tnt_instr);

void tainted_instr_save_tainted_opnds(void *drcontext, instr_t *where, tainted_instr* instr);

std::string tainted_opnd_name_str(const tainted_opnd &opnd);

std::string tainted_opnd_type_str(const tainted_opnd &opnd);

std::string tainted_opnd_value_str(const tainted_opnd &opnd);

std::string tainted_opnd_taint_str(const tainted_opnd &opnd);

std::string tainted_instr_bytes_str(const tainted_instr &instr);

std::string tainted_instr_addr_str(const tainted_instr &instr);

std::string u_integer_hex_str(const u_integer &itgr);

#endif