/*
 * Snoop on the reads that a process does.
 *
 * Designed to attach to a sshd and show the user's session traffic
 */

#include <sys/ptrace.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>

#include <stdio.h>
#include <stdlib.h>

#include <asm/unistd.h>

void print_child_buf(int pid, unsigned long int buf, int count) {
	if (count<0) {
		printf("ERROR: negative count!\n");
		return;
	}
	while (count) {
		char ch;
		/* FIXME - this uses unaligned accesses */
		ch = ptrace(PTRACE_PEEKDATA,pid,buf,NULL);
		buf++;
		count--;
		printf("%c",ch);
	}
	fflush(stdout);
}

int get_syscallnr(int pid) {
	/* FIXME - amd64 specific */
	return ptrace(PTRACE_PEEKUSER,pid,8*ORIG_RAX,NULL);
}

int get_args3(int pid, unsigned long int args[3]) {
	/* could use PEEKUSER, but that requires 3 ptrace calls */
	struct user_regs_struct uregs;
	ptrace(PTRACE_GETREGS,pid,NULL, &uregs);

	/* FIXME - the register names are amd64 specific */
	args[0] = uregs.rdi;
	args[1] = uregs.rsi;
	args[2] = uregs.rdx;

	return 0;
}

int get_result(int pid) {
	/* FIXME - amd64 specific */
	return ptrace(PTRACE_PEEKUSER,pid,8*RAX,NULL);
}

void handle_syscall(int pid, int wantfd) {

	/* FIXME - check child personality 32bit or 64bit */
	/* strace uses CS==0x33 to indicate 64bit */
	/* strace uses CS==0x23 to indicate 32bit */

	int syscall = get_syscallnr(pid);
	unsigned long int args[3];
	if (syscall == __NR_read) {
		get_args3(pid,args);
	}

	/* allow the syscall to complete */
	ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
	wait(NULL);
	/* FIXME - we should care about the wait result */

	if (syscall == __NR_read) {
		int total = get_result(pid);
		if (args[0] == wantfd) {
			print_child_buf(pid,args[1],total);
		}

	}
}

int main(int argc, char **argv) {

	/* FIXME - help message */
	/* FIXME - getopt & check args */
	int pid = strtol(argv[1],NULL,0);
	int fd = strtol(argv[2],NULL,0);

	if (ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1) {
		perror("attaching");
		return(1);
	}
	/* FIXME - check if process is in a syscall and allow it to complete */

	while (1) {
		int status = 0;

		ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
		wait(&status);

		if (WIFSTOPPED(status)) {
			int signal = WSTOPSIG(status);
			if (signal == SIGTRAP) {
				/* FIXME - SIGTRAPs that are not syscalls ? */
				handle_syscall(pid,fd);
			} else {
				/* Send the signal to the process */
				ptrace(PTRACE_SYSCALL,pid,NULL,signal);
			}
		} else {
			printf("FIXME: status !WIFSTOPPED (0x%0x)\n",status);
		}

		if (WIFEXITED(status)) {
			return(0);
		}
	}
}

