#include "taint_map.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <algorithm>
#include <vector>
#include <map>

#define FILENAME "tmap.json"

using json = nlohmann::json;
using tvec_t = std::vector<uint32_t>;
using taint_map = std::map<app_pc, tvec_t>;

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
        tvec_t tvec{taint};
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

void tmap_dump()
{
    json j_tmap;
    for (const auto &elem : tmap)
    {
        json j_instr;
        j_instr["address"] = (uint32_t)elem.first;
        j_instr["taint"] = elem.second;
        j_tmap.push_back(j_instr);
    }

    std::ofstream out(FILENAME, std::ios::out | std::ios::trunc);
    out << j_tmap << std::endl;
}

void tmap_load()
{
    json j_tmap;

    std::ifstream in(FILENAME);

    if (!in.is_open())
        return;

    in >> j_tmap;

    for (const auto &j_instr : j_tmap)
    {
        app_pc pc = (app_pc)j_instr["address"].get<uint32_t>();
        tvec_t tvec = j_instr["taint"].get<tvec_t>();

        tmap.emplace(pc, tvec);
    }

    tmap_print();
}