#include <cstdio>
#include <unistd.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

int somefunc(const char *buf)
{
    char tag[] = "<head>";
    bool res = true;

    for (size_t i = 0; i < sizeof(tag); i++)
    {
        if (buf[i] != tag[i])
        {
            res = false;
            break;
        }
    }

    return res;
}

/* repeatme should be re-executed 5 times with arg 1-5 */
extern "C" int
target(const char *buf, int len)
{
    printf("len = 0x%08X\n", len);
    if (somefunc(buf) == false)
        return -1;
    else
        return 1;
}

int main(int argc, char **argv)
{
    char buf[] = "aaaaaaa";
    int x = sizeof(buf);
    target(buf, x);
    printf("done\n");
    return 0;
}