CC=g++
CFLAGS=-c -Wall

all:runpriv

runpriv: runpriv.o
	$(CC) runpriv.o -o runpriv

clean:
	rm -rf *o runpriv

