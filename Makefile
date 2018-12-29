test: test.c array.c merkle.h merkle.c hash.c
	gcc -g -ggdb -o test hash.c array.c merkle.c test.c -lcrypto

clean:
	rm -rf test *.dSYM