#define _GNU_SOURCE
#include "ssh-server.h"
#include <sys/mman.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "output.h"

#define expsize(x) x, (sizeof(x) - 1)

int memfile(int newfd)
{
	int fd, success;

	fd = memfd_create("hi", 0);
	if (fd == -1) {
		success = 0;
		goto end;
	}

	success = (dup2(fd, newfd) != -1 && fchmod(newfd, 0600) != -1);
	close(fd);

end:
	return success;
}

char *create_hostkey(void)
{
	static const char key[]=
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"MIICXQIBAAKBgQDLKqgN799txUKg8LCzBTE+4GVDa4PsuGnwF50iqADxShC3yPWK\n"
		"c0ZZUeh4nIAo+4W5D+DO0i0veudKBbyv5EBHSib6i5E8bdiyuuFAKwJtL9XIB9aZ\n"
		"G7rzwoekTP+hOhbTd9FDd/F3TT0M/KAQYJEbHg3q7HlLG1AK8IdZfXt6hQIDAQAB\n"
		"AoGAfWVsqH1/R/9SqockaLoxtP9HQR+hI4CHUnsgr31GZ6cxPl44vyV7LDIT7C2c\n"
		"JK9pz9lvBfhPj1iqXNPBrEaTLNJQ6l7vk3NwRk5g73oR8VloSDzZiMq3CBwqhlrQ\n"
		"HhS7WxS3//7fa98B03ILZge9v8K3Afl5IRa7+uB3htqSqxkCQQD7INV/W8UwtrWR\n"
		"3f/AFzG0mvJibKAXuwaaOsVw7ucWj9ZQAJY0wrRamSe/7TbIhSEdrEpN5/ytJjVJ\n"
		"0zGAalIfAkEAzxuiCt4TQzxHxctoPqiurqwyws5s+6WVeHtvP8QrE8JuH8iLzYiw\n"
		"ZtbDdGy59JNDoLkWS0lH81PIycm94RWG2wJBAPYV5cDI0AH9eQ24qq60y9t8Xvr+\n"
		"ER9QAZdO8j3Jjh/40X1SJd8L0SpanK4hqSZz9tCaDbIsG9oc7+kpEIATL+cCQEFA\n"
		"S4VxAlCkpVhEBcv4CVEvH68QqnV+beFPwnUssQXAtEF/RcyzzCAaeeosd0n/O8df\n"
		"iQ6fP/QB6bjpvtEznxECQQCVEyDM3h+jjkFAgloUe5pk5I9IMSr5MCiiOnZ3mccc\n"
		"46kekkEMlZnSUgAujqDMKw/VQzSE0+D85zHjShjxVmX+\n"
		"-----END RSA PRIVATE KEY-----\n";

	static char filename[32] = "HostKey=/tmp/.XXXXXXXXXX";
	char *hostkey = filename;

	int fd;

	if (memfile(42)) {
		snprintf(filename + 8, sizeof(filename) - 8, "/proc/%d/fd/42", getpid());
		write(42, expsize(key));
	}

	else if ((fd = mkstemp(filename + 8)) != -1) {
		write(fd, expsize(key));
		close(fd);
	}

	else
		hostkey = NULL;

	return hostkey;
}


pid_t exec_ssh_server(const char *output, const char *file, char * const argv[])
{
	pid_t pid = fork();
	int fd;

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		/* check if parent pid exists */
		if (kill(getppid(), 0))
			kill(getpid(), SIGKILL);

		if (output) {
			fd = open(output, O_WRONLY);
			if (fd != -1) {
				dup2(fd, 1);
				dup2(fd, 2);

				if (fd > 2)
					close(fd);
			}

			else {
				say("failed to open %s\n", output);
				dup2(2, 1);
			}
		}

		else
			/* redirect stdout output to stderr */
			dup2(2, 1);

		ptrace(PTRACE_TRACEME, 0, 0, NULL);
		kill(getpid(), SIGSTOP);

		execvp(file, argv);
		_exit(1);
	}

	return pid;
}
