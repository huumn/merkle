test: array.c hash.c merkle.h merkle.c test.c
	gcc -g -ggdb -o test array.c hash.c merkle.c test.c -lcrypto

clean:
	rm -rf test *.dSYM