#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>

static int global1;
int global2;
static void foo1() {}
void foo2() {}

void write_assert_fail(void *p)
{
    assert(write(1, p, 4) == -1);
}

int main(int argc, char **argv, char **envp)
{
    int i;
    /* test argv taint status */
    for (i = 0; i < argc; ++i)
        printf("%s\n", argv[i]);
    for (i = 0; envp[i]; ++i)
        printf("%s\n", envp[i]);

    /* test envp taint status */
    for (; *envp; ++envp)
        assert(write(1, &envp, 4) == -1);
    for (i = 0; i < argc; ++i, ++argv)
        assert(write(1, &argv, 4) == -1);
    printf("Argv leaks - ok\n");

    /* leaking the address of a global variable */
    int *j = (int *)&global1;
    assert(fwrite(&j, 4, 1, stdout) == -1);
    j = (int *)&global2;
    assert(fwrite(&j, 4, 1, stdout) == -1);
    j = (int *)&foo1;
    assert(fwrite(&j, 4, 1, stdout) == -1);
    j = (int *)&foo2;
    assert(fwrite(&j, 4, 1, stdout) == -1);
    printf("Global variable leaks - ok\n");

    /* leak fastbin freelist next pointer, which is a heap leak */
    unsigned int *a = malloc(10);
    unsigned int *b = malloc(10);
    unsigned int *c = malloc(10);
    free(a);
    free(c);
    write_assert_fail(c);

    /* leak heap address from the stack */
    write_assert_fail(c);

    /* leak stack address from the stack */
    unsigned int **d = &c;
    write_assert_fail(d);

    /* leak stack address from environ */
    extern char **environ;
    write_assert_fail(environ);

    /* leak a libc address provided by the loader */
    write_assert_fail(&stdout);
    printf("Simple code leaks - ok\n");
    printf("Done\n");
}
