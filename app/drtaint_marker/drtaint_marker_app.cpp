#include <cstdio>
#include <unistd.h>
#include <string.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

bool own_strcmp(const char *dst, const char *src)
{
    const char* p_dst = dst;
    const char* p_src = src;

    while (*p_dst && *p_src && *p_dst == *p_src)
    {
        p_src++;
        p_dst++;
    }

    return *p_src == '\0' && *p_dst == '\0';
}

bool own_memcmp(const char *dst, const char *src, int len)
{
    for (int i = 0; i < len; i += 4)
    {
        if (*(int *)&dst[i] != *(int *)&src[i])
            return false;
    }

    int cnt_left = len % 4;
    for (int i = 0; i < cnt_left; i++)
    {
        if (dst[i] != src[i])
            return false;
    }

    return true;
}


// isalnum
// isalpha
// isascii
// isctrl
// isdigit
// isgraph
// islower
// isprint
// ispunct
// isspace
// isupper
// isxdigit
// memcmp, memicmp
// strcmp

// stricmp, stricmpi, _fstricmp
// strlen, _fstrlen
// strncmp, strnicmp, strncmpi
// strncpy, _fstrncpy
// strstr, _fstrstr

// strrchr, _fstrrchr
// strchr, _fstrchr

/* repeatme should be re-executed 5 times with arg 1-5 */
extern "C" int
target(const char *buf)
{
    if (!strcmp(buf, "<head>"))
    {
        printf("Target success!\n");
        return *(int *)0;
    }
    else
    {
        printf("Target failed\n");
        return -1;
    }
}

int main(int argc, char **argv)
{
    char buf[] = "AAAAAAA";
    target(buf);
    printf("done\n");
    return 0;
}