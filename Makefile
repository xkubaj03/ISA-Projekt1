CC=g++
CFLAGS=-pedantic -Wall -Wextra -g -lpcap -std=gnu99
NAME=flow

all:
	$(CC) $(GFLAGS) flow.cpp -o $(NAME) -lpcap
Clean:

		-rm -f *.o $(NAME)
