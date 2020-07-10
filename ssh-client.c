#include "ssh-client.h"
#include <pty.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#define expsize(x) x, (sizeof(x) - 1)

void wait_prompt(const char *prompt, int fd)
{
	struct pollfd pfd;
	char buf[1024];

	ssize_t n;
	int i, j = 0;

	pfd.fd = fd;
	pfd.events = POLLIN;


	while (poll(&pfd, 1, 3000) > 0) {
		n = read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;

		for (i = 0; i < n; i++) {
			if (!prompt[j])
				break;

			if (prompt[j] != buf[i] && j)
				i--, j = 0;
			else
				j++;
		}
	}
}

void exec_ssh_client(const char *file, char *const argv[], const char *password)
{
	char buf[1024];

	int master;
	ssize_t n;

	pid_t pid = fork();
	if (pid)
		return;

	pid = forkpty(&master, NULL, NULL, NULL);
	if (pid == -1)
		return;

	else if (pid == 0) {
		execvp(file, argv);
		_exit(1);
	}

	wait_prompt("password:", master);

	write(master, password, strlen(password));

	while ((n = read(master, buf, sizeof(buf))) > 0) {}
	close(master);

	_exit(0);
}
