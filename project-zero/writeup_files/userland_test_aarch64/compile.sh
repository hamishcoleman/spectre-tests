#!/bin/sh
gcc -c -o test_vulnfunc.o test_vulnfunc.c -Wall -O3
gcc -static -o test test.c test_vulnfunc.o -Wall -ggdb -std=gnu99
