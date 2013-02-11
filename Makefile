CFLAGS=-Wall -Wextra -std=gnu99 -pedantic -g
CLIBS=-lpcap

dnsscrape: main.c dns_types.c debug.c
	gcc $(CFLAGS) -o dnsscrape main.c dns_types.c debug.c $(CLIBS)
