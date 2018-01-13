/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when _do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever _do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ratelimit.h>
#include <linux/mm_types.h>

static int __init spo_init(void)
{
	pr_info("PAGE_OFFSET=0x%lx\n", PAGE_OFFSET);
        pr_info("pgd at 0x%lx\n", (unsigned long)current->mm->pgd);
	return 0;
}

static void __exit spo_exit(void)
{
}

module_init(spo_init)
module_exit(spo_exit)
MODULE_LICENSE("GPL");
