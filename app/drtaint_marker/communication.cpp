#include "communication.h"
#include "taint_processing.h"
#include "http/picohttpclient.hpp"

#define SOLVER_URL "http://192.168.1.34:8080"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>

using namespace std;

static std::string
url_encode(std::string value)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i)
    {
        string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char)c);
        escaped << nouppercase;
    }

    return escaped.str();
}

bool cmn_send_load_request(dr_mcontext_t *mc, ptr_uint_t load_addr, ptr_uint_t libc_addr,
                           ptr_uint_t target_addr, uint32_t tc_length)
{
    std::ostringstream request;
    request << SOLVER_URL << "/load"
            << "?load_addr=" << u32_to_hex_string(load_addr)
            << "&libc_addr=" << u32_to_hex_string(load_addr)
            << "&target_addr=" << u32_to_hex_string(target_addr)
            << "&tc_length=" << u32_to_hex_string(tc_length)
            << "&ctx.r0=" << u32_to_hex_string(mc->r0)
            << "&ctx.r1=" << u32_to_hex_string(mc->r1)
            << "&ctx.r2=" << u32_to_hex_string(mc->r2)
            << "&ctx.r3=" << u32_to_hex_string(mc->r3)
            << "&ctx.r4=" << u32_to_hex_string(mc->r4)
            << "&ctx.r5=" << u32_to_hex_string(mc->r5)
            << "&ctx.r6=" << u32_to_hex_string(mc->r6)
            << "&ctx.r7=" << u32_to_hex_string(mc->r7)
            << "&ctx.r8=" << u32_to_hex_string(mc->r8)
            << "&ctx.r9=" << u32_to_hex_string(mc->r9)
            << "&ctx.r10=" << u32_to_hex_string(mc->r10)
            << "&ctx.r11=" << u32_to_hex_string(mc->r11)
            << "&ctx.r12=" << u32_to_hex_string(mc->r12)
            << "&ctx.sp=" << u32_to_hex_string(mc->sp)
            << "&ctx.lr=" << u32_to_hex_string(mc->lr)
            << "&ctx.flags=" << u32_to_hex_string(mc->xflags);

    HTTPResponse response = HTTPClient::request(HTTPClient::POST, URI(request.str()));
    if (!response.success)
    {
        dr_printf("Failed to send request to solver\n");
        return false;
    }

    int code = atoi(response.response.c_str());
    if (code != 202)
    {
        dr_printf("Get testcase request failed: %d\n", code);
        dr_printf("Response: %s\n", response.body.c_str());
        return false;
    }

    return true;
}

bool cmn_send_solve_request(const char *buf, uint32_t buf_len,
                            uint32_t taint, uint32_t taint_offs, app_pc cmp_addr)
{
    std::ostringstream request;
    request << SOLVER_URL << "/solver"
            << "?buf=" << url_encode(std::string(buf, buf_len))
            << "&buf_addr=" << u32_to_hex_string((uint32_t)buf)
            << "&taint=" << u32_to_hex_string(taint)
            << "&taint_offs=" << u32_to_hex_string(taint_offs)
            << "&cmp_addr=" << u32_to_hex_string((uint32_t)cmp_addr);

    HTTPResponse response = HTTPClient::request(HTTPClient::POST, URI(request.str()));
    if (!response.success)
    {
        dr_printf("Failed to send request to solver\n");
        return -1;
    }

    int code = atoi(response.response.c_str());
    if (code != 202)
    {
        dr_printf("Get testcase request failed: %d\n", code);
        dr_printf("Response: %s\n", response.body.c_str());
        return false;
    }

    return true;
}

bool cmn_send_next_tc_request(char *buf, uint32_t buf_sz)
{
    std::ostringstream request;
    request << SOLVER_URL << "/next";

    HTTPResponse response = HTTPClient::request(HTTPClient::GET, URI(request.str()));
    if (!response.success)
    {
        dr_printf("Failed to send request to solver\n");
        return -1;
    }

    int code = atoi(response.response.c_str());
    if (code != 200)
    {
        if (code != 204)
        {
            dr_printf("Get testcase request failed: %d\n", code);
            dr_printf("Response: %s\n", response.body.c_str());
        }

        return false;
    }

    std::string resp = response.body;
    std::size_t resp_len = resp.length();
    dr_printf("TC response = %s\n", resp.c_str());

    if (resp_len != buf_sz)
    {
        dr_printf("Buf size does not match: %llu\n", resp_len);
        return false;
    }

    memcpy(buf, resp.c_str(), buf_sz);
    return true;
}