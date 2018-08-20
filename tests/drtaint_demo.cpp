#include <stdio.h>

int main()
{
    // prints xor - string
    char buf[11] = {0};
    printf("Enter string: ");    
	scanf("%10s", buf);

	printf("Your string is: %s\n", buf);
	
    for (unsigned int i = 0; i < sizeof(buf) - 1; i++)
        buf[i] ^= 17;
    
    printf("Your xor string is: %s\n", buf);
}