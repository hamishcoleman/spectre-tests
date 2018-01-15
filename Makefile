#
# Simple test for the spectre issue
#

TARGETS := spectre spectre_pthread

CFLAGS := -msse2
CC = gcc $(CFLAGS) -g -Wall

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

test: all
	./spectre
	./spectre_pthread

spectre: spectre.c
	$(CC) -o $@ $<

spectre_pthread: spectre.c
	$(CC) -DPTHREAD -lpthread -o $@ $<

