#include <cstdio>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

bool own_strcmp(const char *dst, const char *src)
{
    const char *p_dst = dst;
    const char *p_src = src;

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

extern "C" int
target(const char *buf);

// isalnum
// isalpha
// isdigit
// islower
// ispunct
// isspace
// isupper
// isxdigit

// strlen +

// memcmp +

// strncmp +
// strcmp +

// strstr, _fstrstr
// strrchr, _fstrrchr
// strchr, _fstrchr

int main(int argc, char **argv)
{
    char buf[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    target(buf);
    printf("done\n");
    return 0;
}

extern "C" int
target(const char *buf)
{

    if (islower(buf[1]))
    {
        printf("Target success!\n");
        return *(int *)0;
    }

    printf("Target failed\n");
    return -1;

    if (isalnum(buf[0]) && isalpha(buf[0]) && islower(buf[0]))
    {
        if (isdigit(buf[1]) && isspace(buf[2]) && isdigit(buf[3]))
        {
            printf("Target success!\n");
            return *(int *)0;
        }
    }

    printf("Target failed\n");
    return -1;
}

// extern "C" int
// target(const char *buf)
// {
//     size_t len = strlen(buf);
//     if (len > 24 && len < 32)
//     {
//         printf("Target success!\n");
//         return *(int *)0;
//     }
//     else
//     {
//         printf("Target failed\n");
//         return -1;
//     }
// }

// extern "C" int
// target(const char *buf)
// {
//     // "<"
//     // "<he"
//     // "<hea"
//     // "<hea"
//     // "<head>"
//     // "<heade>"
//     // "<header>"
//     // "<head>aaaa</head>"
//     char str[] = "<heade>";
//     if (!strncmp(buf, str, sizeof(str)))
//     {
//         printf("Target success!\n");
//         return *(int *)0;
//     }
//     else
//     {
//         printf("Target failed\n");
//         return -1;
//     }
// }

// extern "C" int
// target(const char *buf)
// {
//     // {0x42}
//     // {0x4243}
//     // {0x424344}
//     // {0x42434445}
//     // {0x42434445}, {0x42}
//     // {0x42434445, 0x4243}
//     // {0x42434445, 0x4243}
//     // {0x42434445, 0x424344}
//     // {0x42434445, 0x42434445}
//     // {0x42434445, 0x42434445, 0x42434445, 0x42434445}
//     int arr[] = {0x42434445, 0x42434445, 0x42434445, 0x42434445};
//     if (!memcmp(buf, arr, sizeof(arr)))
//     {
//         printf("Target success!\n");
//         return *(int *)0;
//     }
//     else
//     {
//         printf("Target failed\n");
//         return -1;
//     }
// }

// extern "C" int
// target(const char *buf)
// {
//     // ""
//     // "<"
//     // "<he"
//     // "<hea"
//     // "<hea"
//     // "<head>"
//     // "<heade>"
//     // "<header>"
//     // "<head>aaaa</head>"
//     if (!strcmp(buf, "<head>aaaa</head>"))
//     {
//         printf("Target success!\n");
//         return *(int *)0;
//     }
//     else
//     {
//         printf("Target failed\n");
//         return -1;
//     }
// }