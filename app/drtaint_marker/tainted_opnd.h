#ifndef TAINTED_OPND_H_
#define TAINTED_OPND_H_

#include "dr_api.h"
#include <string>
#include <variant>

enum taint_variant_type_t {
	tainted_register,
	tainted_address,
};

struct tainted_regiter_t
{
	reg_id_t reg_num;
	uint32_t value;
	uint32_t taint;
};

struct tainted_address_t
{
	uint32_t address;
	uint32_t value;
	uint32_t taint;
};

using taint_variant_t = std::variant<tainted_regiter_t, tainted_address_t>;

class tainted_opnd_t
{
	taint_variant_t opnd;

public:

	tainted_opnd_t(taint_variant_t opnd)
		: opnd(opnd) {}

	std::string get_name() const 
	{ 
		return opnd.index() == tainted_register
			? get_register_name(std::get<tainted_regiter_t>(opnd).reg_num)
			: std::to_string(std::get<tainted_address_t>(opnd).address);
	}

	std::string get_type() const 
	{ 
		return opnd.index() == tainted_register
			? "register"
			: "address";
	}

	std::string get_value() const 
	{ 
		return opnd.index() == tainted_register
			? std::to_string(std::get<tainted_regiter_t>(opnd).value)
			: std::to_string(std::get<tainted_address_t>(opnd).value);
	}
	
	std::string get_taint() const
	{ 
		return opnd.index() == tainted_register
			? std::to_string(std::get<tainted_regiter_t>(opnd).taint)
			: std::to_string(std::get<tainted_address_t>(opnd).taint);
	}
};

#endif