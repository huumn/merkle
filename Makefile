test: test.c array.c merkle.h merkle.c md5.c
	gcc -g -ggdb -o test test.c array.c merkle.c md5.c

clean:
	rm -rf test *.dSYM