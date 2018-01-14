#
# Provide a makefile to try out the proof-of-concept
#

all:
	false

build-depends:
	apt install nasm

userland_test_x86/test: userland_test_x86/test.c userland_test_x86/test_vulnfunc.c
userland_test_x86/test userland_test_x86/test_branch:
	cd userland_test_x86 && ./compile.sh

userland_test: userland_test_x86/test
	cd userland_test_x86 && ./test
userland_test_branch: userland_test_x86/test_branch
	cd userland_test_x86 && ./test_branch

CLEAN+=userland_test_x86/test userland_test_x86/test_branch \
       userland_test_x86/asm_helpers.o userland_test_x86/test_branch_native.o \
       userland_test_x86/test_vulnfunc.o

kernel_leak_exploit_intel_xeon_e5_1650_v3/bpf_stuff: kernel_leak_exploit_intel_xeon_e5_1650_v3/bpf_stuff.c
	gcc -pthread -o $@ $^ -Wall -ggdb -std=gnu99

kernel_leak_exploit: kernel_leak_exploit_intel_xeon_e5_1650_v3/bpf_stuff
	$^

CLEAN+=kernel_leak_exploit_intel_xeon_e5_1650_v3/bpf_stuff

clean:
	rm -f $(CLEAN)
