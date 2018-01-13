#!/bin/sh
nasm -felf64 asm_helpers.asm
gcc -c -o test_vulnfunc.o test_vulnfunc.c -Wall -O3
gcc -o test test.c test_vulnfunc.o asm_helpers.o -Wall -ggdb -std=gnu99


nasm -felf64 test_branch_native.asm
gcc -o test_branch test_branch.c test_branch_native.o asm_helpers.o -Wall -ggdb -std=gnu99
