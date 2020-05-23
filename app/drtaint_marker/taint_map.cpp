#include "taint_map.h"
#include <algorithm>
#include <vector>
#include <map>

using taint_map = std::map<app_pc, std::vector<uint32_t>>;
taint_map tmap;

bool tmap_has(instr_t *instr, uint32_t taint)
{
    bool res = false;
    app_pc pc = instr_get_app_pc(instr);
    auto it = tmap.find(pc);

    if (it != tmap.end())
    {
        const auto &tvec = it->second;
        auto itv = std::find(tvec.begin(), tvec.end(), taint);
        res = itv != tvec.end();
    }

    return res;
}

void tmap_emplace(instr_t *instr, uint32_t taint)
{
    app_pc pc = instr_get_app_pc(instr);

    auto it = tmap.find(pc);
    if (it != tmap.end())
    {
        auto& tvec = it->second;
        tvec.push_back(taint);
    }
    else
    {
        std::vector<uint32_t> tvec{taint};
        tmap.emplace(pc, tvec);
    }
}

void tmap_print()
{
    for (const auto &elem : tmap)
    {
        app_pc addr = elem.first;
        const auto &tvec = elem.second;

        dr_printf("\nAddress = 0x%p\n", addr);
        dr_printf("Taint:");

        for (const auto &taint : tvec)
            dr_printf(" 0x%08X", taint);
    }
    dr_printf("\n");
}