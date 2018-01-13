bits 64
default rel
global flush_addr
global cpuid

; flush+reload approach
flush_addr:
; reload
mfence
rdtscp ; sets edx:eax, ecx
mov r11d, eax
mov esi, [rdi]
mfence
rdtscp ; sets edx:eax, ecx
sub eax, r11d
; flush
clflush [rdi]
mfence
ret
ud2

cpuid:
push rbx
mov rax, 0
cpuid
pop rbx
ret
ud2
