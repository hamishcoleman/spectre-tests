#
# Simple test for the spectre issue
#

all: spectre spectre_pthread

test: all
	./spectre
	./spectre_pthread

spectre: spectre.c
	$(CC) -g -Wall -o $@ $<

spectre_pthread: spectre.c
	$(CC) -g -Wall -DPTHREAD -lpthread -o $@ $<

