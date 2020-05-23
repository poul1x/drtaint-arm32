#include <cstdio>
#include <unistd.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

bool somefunc(const char *buf, size_t *pos)
{
    char tag[] = "<head>";
    bool res = true;

    for (size_t i = 0; i < sizeof(tag); i++)
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
target(const char *buf)
{
    size_t pos = -1;
    bool res = somefunc(buf, &pos);
    if (res == true)
    {
        printf("Target success!\n");
        return 1;
    }
    else
    {
        printf("Target failed: %d\n", pos);
        return -1;
    }
}

int main(int argc, char **argv)
{
    char buf[] = "aaaaaaa";
    target(buf);
    printf("done\n");
    return 0;
}