CFLAGS= -Wall -Wno-unknown-pragmas

all:

	rm -rf build
	mkdir build
	
	#gcc $(CFLAGS) simple_argv.c -o build/simple_argv
	#gcc $(CFLAGS) simple_leaks.c -o build/simple_leaks
	#gcc $(CFLAGS) -fPIC -fPIE -pie simple_code_leaks.c -o build/simple_code_leaks
	g++ $(CFLAGS) -mthumb -DMTHUMB drtaint_test.cpp -o build/drtaint_test_thumb
	#g++ $(CFLAGS) -marm drtaint_test.cpp -o build/drtaint_test_arm
