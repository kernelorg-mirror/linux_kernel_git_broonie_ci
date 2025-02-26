// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Limited.
 * Original author: Mark Rutland <mark.rutland@arm.com>
 *
 * Helper program to force all syscalls performed by a subprocess to
 * be run as though it were using SVE, done via ptrace.  This only
 * works for single threaded applications.
 */
//

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <linux/prctl.h>

#include <asm/hwcap.h>
#include <asm/ptrace.h>

static void die(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static void err(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
}

static void child(int argc, char *argv[])
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	raise(SIGSTOP);

	execvp(argv[1], &argv[1]);
}

void ptrace_getregset(const pid_t child, unsigned int nt, void *base, size_t len)
{
	struct iovec iov = {
		.iov_base = base,
		.iov_len = len,
	};
	if (ptrace(PTRACE_GETREGSET, child, nt, &iov))
		err("%s GETREGSET(%x) failed\n", __func__, nt);
	if (iov.iov_len != len)
		err("%s read too few bytes (%z vs expected %z)\n", __func__,
		    iov.iov_len, len);
}

void ptrace_setregset(const pid_t child, unsigned int nt, void *base, size_t len)
{
	struct iovec iov = {
		.iov_base = base,
		.iov_len = len,
	};
	if (ptrace(PTRACE_SETREGSET, child, nt, &iov))
		err("%s SETREGSET(%x) failed\n", __func__, nt);
	if (iov.iov_len != len)
		err("%s wrote too few bytes (%z vs expected %z)\n", __func__,
		    iov.iov_len, len);
}

void ptrace_syscall(const pid_t child)
{
	ptrace(PTRACE_SYSCALL, child, NULL, NULL);
}

void ptrace_force_sve(const pid_t child)
{
	struct user_sve_header ush = { };

	/* Get a SVE register header. */
	ptrace_getregset(child, NT_ARM_SVE, &ush, sizeof(ush));

	/*
	 * Set the SVE flag and write it back, since we're just
	 * writing the header we don't need to worry about the
	 * different format for register data, the kernel should
	 * convert internally.
	 */
	ush.flags |= SVE_PT_REGS_SVE;
	ptrace_setregset(child, NT_ARM_SVE, &ush, sizeof(ush));

	ptrace_getregset(child, NT_ARM_SVE, &ush, sizeof(ush));
	if (!(ush.flags & SVE_PT_REGS_SVE))
		err("Failed to force SVE\n");
}

static void parent(const pid_t child)
{
	for (;;) {
		pid_t pid;
		int status;

		pid = waitpid(child, &status, __WALL);

		if (pid == -1)
			die("waitpid() failed\n");

		if (pid != child) {
			err("Ignoring unexpected pid %d\n", pid);
			continue;
		}

		if (WIFEXITED(status))
			die("Child exited with status %d\n", WEXITSTATUS(status));

		if (WIFSIGNALED(status))
			die("Child killed by signal %d\n", WTERMSIG(status));

		if (WIFCONTINUED(status)) {
			err("Child continued\n");
			continue;
		}

		if (!WIFSTOPPED(status))
			die("Unexpected waitpid() status 0x%x\n", status);

		/*
		 * Force SVE and wait for the next syscall entry/exit.
		 */
		ptrace_force_sve(child);
		ptrace_syscall(child);
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;

	if (argc < 2)
		die("Usage: %s <command> [<arguments> ...]\n", argv[0]);

	if (!(getauxval(AT_HWCAP) & HWCAP_SVE)) {
		fprintf(stderr, "%s: Scalable Vector Extension not present\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid == -1)
		die("Failed to fork()\n");
	else if (pid == 0)
		child(argc, argv);
	else
		parent(pid);

	return 0;
}
