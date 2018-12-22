test: test.c merkle.c md5.c
	gcc -o test test.c merkle.c md5.c

clean:
	rm test