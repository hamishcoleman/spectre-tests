bits 64
default rel

ud2

global indir_branch_target
indir_branch_target:
mov rsi, [rsi]
ret
ud2

global nop_branch_target
nop_branch_target:
ret
ud2

global indir_branch_victim
global indir_branch_victim_end
indir_branch_victim:
mov rax, [rdi]
jmp rax
ud2
indir_branch_victim_end:

global indir_branch_attacker
global indir_branch_attacker_end
indir_branch_attacker:
mov rax, [rdi]
jmp rax
ud2
indir_branch_attacker_end:
