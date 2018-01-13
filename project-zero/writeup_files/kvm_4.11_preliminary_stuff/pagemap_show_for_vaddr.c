#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    puts("usage: ./pagemap_show_for_vaddr <pid> <vaddr>");
    return 1;
  }
  pid_t pid = atoi(argv[1]);
  unsigned long vaddr = strtoul(argv[2], NULL, 0);
  printf("looking up 0x%lx in pid %d\n", vaddr, (int)pid);

  // prefault readable
  unsigned char dummy;
  struct iovec local_iov = {
    .iov_base = &dummy,
    .iov_len = 1
  };
  struct iovec remote_iov = {
    .iov_base = (void*)vaddr,
    .iov_len = 1
  };
  process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

  char path[100];
  sprintf(path, "/proc/%d/pagemap", (int)pid);
  int pagemap_fd = open(path, O_RDONLY);
  if (pagemap_fd == -1)
    err(1, "open pagemap");
  uint64_t pm_val;
  if (pread(pagemap_fd, &pm_val, 8, vaddr / 4096 * 8) != 8)
    err(1, "read pagemap");
  printf("present: %s\n", (pm_val & (1ULL<<63)) ? "yes" : "no");
  printf("swapped: %s\n", (pm_val & (1ULL<<62)) ? "yes" : "no");
  if ((pm_val & (1ULL<<63)) != 0) {
    printf("physical address: 0x%lx\n", (pm_val & 0x7fffffffffffff)*0x1000);
  }
}
