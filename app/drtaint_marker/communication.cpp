#include "dr_api.h"
#include "http/picohttpclient.hpp"
#include "taint_processing.h"

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

    for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
        string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char) c);
        escaped << nouppercase;
    }

    return escaped.str();
}

extern "C" int
cmn_send_load_request(dr_mcontext_t *mc, ptr_uint_t target_addr, ptr_uint_t buffer_addr)
{
    std::ostringstream request;
    request << SOLVER_URL << "/load"
            << "?target_addr=" << u32_to_hex_string(target_addr)
            << "&buffer_addr=" << u32_to_hex_string(buffer_addr)
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
            << "&ctx.flags=" << u32_to_hex_string(mc->xflags);

    HTTPResponse response = HTTPClient::request(HTTPClient::POST, URI(request.str()));
    if (!response.success)
    {
        dr_printf("Failed to send request to solver\n");
        return -1;
    }

    int code = atoi(response.response.c_str());
    if (code != 201)
    {
        dr_printf("Load request failed: %d\n", code);
        return -1;
    }

    return 0;
}

extern "C" int
cmn_send_solve_request(app_pc cmp_addr, uint32_t taint, const char *buf_concrete)
{
    std::ostringstream request;
    request << SOLVER_URL << "/solver"
            << "?cmp_addr=" << u32_to_hex_string((uint32_t)cmp_addr)
            << "&taint=" << u32_to_hex_string(taint)
            << "&buf=" << url_encode(buf_concrete);

    HTTPResponse response = HTTPClient::request(HTTPClient::POST, URI(request.str()));
    if (!response.success)
    {
        dr_printf("Failed to send request to solver\n");
        return -1;
    }

    int code = atoi(response.response.c_str());
    if (code != 202)
    {
        dr_printf("Solve request failed: %d\n", code);
        return -1;
    }

    return 0;
}