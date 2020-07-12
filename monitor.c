#include <sys/inotify.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <errno.h>

static const char *fields[]={
	"password",
	"user",
	"ip"
};

int wait_file(const char *filename)
{
	int fd;

	while ((fd = open(filename, O_RDONLY)) == -1) {
		if (errno != ENOENT) {
			printf("can't open %s - %s\n", filename, strerror(errno));
			exit(1);
		}

		sleep(1);
	}

	return fd;
}

void strrev(char *str, int len)
{
	char aux;
	int i;

	for (i = 0; i < len/2; i++) {
		aux = str[i];
		str[i] = str[len - i - 1];
		str[len - i - 1] = aux;
	}
}

void get_creds(char *data, int n)
{
	static int size, type, j;
	static char *buf;

	if (data == NULL && buf) {
		strrev(buf, j);
		j = 0;

		printf("%s=%s\n", fields[type], buf);
		type = (type + 1) % 3;
		return;
	}

	for (int i = 0; i < n; i++) {
		if (data[i] == 0x0 && j) {
			strrev(buf, j);
			j = 0;

			printf("%s=%s\n", fields[type], buf);
			type = (type + 1) % 3;
		}

		if (j >= size) {
			size += 128;
			buf = realloc(buf, size);
		}


		buf[j++] = data[i];
	}

}

int main(int argc, char **argv)
{
	struct inotify_event event;
	struct pollfd pfd;
	char buf[8192];
	ssize_t n;

	int fd, nfd;

	if (argc != 2) {
		printf("monitor [filename]\n");
		return 1;
	}

	fd = wait_file(argv[1]);

	nfd = inotify_init();
    inotify_add_watch(nfd, argv[1], IN_MODIFY);

	pfd.fd = nfd;
	pfd.events = POLLIN;

	goto print_creds;

	while (poll(&pfd, 1, -1) != -1) {
		if (read(nfd, &event, sizeof(event)) != sizeof(event)){
			perror("read()");
			return 1;
		}

		if (!(event.mask & IN_MODIFY)) {
			perror("invalid event ...");
			return 1;
		}

print_creds:
		while ((n = read(fd, buf, sizeof(buf))) > 0) {
			get_creds(buf, n);
		}

		get_creds(NULL, 0);
	}

	return 0;
}
