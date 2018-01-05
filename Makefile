#
# Simple test for the spectre issue
#

all: test

test: spectre
	./spectre

spectre: spectre.c
	$(CC) -g -Wall -o $@ $<

