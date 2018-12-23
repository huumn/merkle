test: test.c merkle.h merkle.c md5.c
	gcc -g -ggdb -o test test.c merkle.c md5.c

clean:
	rm test