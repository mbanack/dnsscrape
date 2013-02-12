CFLAGS=-Wall -Wextra -std=gnu99 -pedantic -g
CLIBS=-lpcap

dnsscrape: main.c dns_types.c debug.c dns_types.h debug.h
	gcc $(CFLAGS) -o dnsscrape main.c dns_types.c debug.c $(CLIBS)
