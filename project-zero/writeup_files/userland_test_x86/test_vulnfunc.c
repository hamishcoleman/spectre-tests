#include <stdint.h>
#include <stdlib.h>

#define LT_SIZE (128 * 1024 * 1024)
extern unsigned int lookup_table[LT_SIZE];

volatile uint8_t value;

unsigned long j_limit = 0x1000;

unsigned char vuln_func(unsigned long i, uint8_t *timing_leak_array, uint8_t *source_data_array, unsigned int j) {
	asm volatile(
		"mov $0, %%eax\n\t"
		"cpuid\n\t" /* serialize; clobbers eax, ebx, ecx, edx */
	: /* no outputs */
	: /* no inputs */
	: "ax", "bx", "cx", "dx");
	if (__builtin_expect((/*(lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[lookup_table[random()%LT_SIZE]]]]]]]]]]&0x80000000) |*/ (j < j_limit)), 1)) {
		//value = ;
		return timing_leak_array[(source_data_array[i]&1)<<10];
	}
	return 0;
}
