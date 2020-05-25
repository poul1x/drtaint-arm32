#include <cstdio>
#include <unistd.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

bool somefunc(const int *buf, size_t *pos)
{
    int tag[] = {0x11111111, 0x22222222, 0x3333, 0x4444, 0x55, 0x66, 0};
    bool res = true;

    for (size_t i = 0; i < sizeof(tag) / sizeof(int); i++)
    {
        if (buf[i] != tag[i])
        {
            *pos = i;
            res = false;
            break;
        }
    }

    return res;
}

/* repeatme should be re-executed 5 times with arg 1-5 */
extern "C" int
target(const int *buf)
{
    size_t pos = -1;
    bool res = somefunc(buf, &pos);
    if (res == true)
    {
        printf("Target success!\n");
        return *(int*)0;
    }
    else
    {
        // printf("Target failed: %d\n", pos);
        return -1;
    }
}

int main(int argc, char **argv)
{
    int buf[] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
    target(buf);
    printf("done\n");
    return 0;
}