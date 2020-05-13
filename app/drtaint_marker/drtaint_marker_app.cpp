#include <cstdio>
#include <unistd.h>
using namespace std;

#define NUM_THREADS 5

#ifdef WINDOWS
# define EXPORT __declspec(dllexport)
#else
# define EXPORT
#endif

/* repeatme should be re-executed 5 times with arg 1-5 */
extern "C" void
target(const char* buf)
{
    if (buf[0] == 'A')
        printf("Guessed A!\n");
    else if (buf[0] == 'B')
        printf("Guessed B!\n");
    else
        printf("Guess failed!\n");
}

int
main(int argc, char **argv)
{
    char buf[] = "qwerty";
    target(buf);
    printf("done\n");
    return 0;
}