#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[20];
    printf("Enter string: ");
    scanf("%s", buf);
    printf("Echo: %s\n", buf);
}