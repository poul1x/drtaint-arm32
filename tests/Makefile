CFLAGS=-Wall

all:
	gcc $(CFLAGS) simple_argv.c -o simple_argv
	gcc $(CFLAGS) simple_leaks.c -o simple_leaks
	gcc $(CFLAGS) -fPIC -fPIE -pie simple_code_leaks.c -o simple_code_leaks
