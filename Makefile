CC = gcc
CFLAGS = -std=gnu99 -lpcap -o sniffer

all:
	$(CC) $(CFLAGS) main.c
clean:
	rm *.o sniffer -f
