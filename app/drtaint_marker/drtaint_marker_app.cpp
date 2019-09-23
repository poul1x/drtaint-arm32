#include <unistd.h> 
#include <stdio.h>

int main(int argc, char **argv)
{
    char buf[20] = {0};
    printf("Enter string: ");
    ssize_t n = read(0, buf, sizeof(buf));
    
    for (int i =0; i<n; i++)
        buf[i] ^= 5;

    printf("\nEcho: %s\n", buf);
}