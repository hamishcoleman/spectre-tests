#
# Simple test for the spectre issue
#

TARGETS := spectre spectre_pthread

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

test: all
	./spectre
	./spectre_pthread

spectre: spectre.c
	$(CC) -g -Wall -o $@ $<

spectre_pthread: spectre.c
	$(CC) -g -Wall -DPTHREAD -lpthread -o $@ $<

