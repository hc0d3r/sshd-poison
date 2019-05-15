#include <sys/inotify.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *fields[]={
    "PASSWORD=",
    "RHOST=",
    "USER="
};

int main(int argc, char **argv){
    struct inotify_event event;
    struct pollfd pfd;

    ssize_t i, j, k, n;
    int nfd, fd, start;

    char buf[1024];

    if(argc != 2){
        printf("monitor [filename]\n");
        return 1;
    }

    fd = open(argv[1], O_RDONLY|O_APPEND);
    if(fd == -1){
        perror("open()");
        return 1;
    }

    lseek(fd, 0, SEEK_END);

    nfd = inotify_init();
    inotify_add_watch(nfd, argv[1], IN_MODIFY);

    pfd.fd = nfd;
    pfd.events = POLLIN;

    start = 1;
    k = 0;

    while(poll(&pfd, 1, -1) != -1){
        if(read(nfd, &event, sizeof(struct inotify_event)) <= 0){
            perror("read()");
            return 1;
        }

        if(!(event.mask & IN_MODIFY)){
            perror("invalid event ...");
            return 1;
        }

        while(1){
            n = read(fd, buf, sizeof(buf));
            if(n == -1){
                perror("read()");
                return 1;
            } else if(n == 0){
                break;
            }

            i = 0;

            while(i<n){
                if(start){
                    write(1, fields[k], strlen(fields[k]));
                    start = 0;
                    k++;
                }

                j = i;
                for(; i<n; i++){
                    if(buf[i] == 0x0){
                        start = 1;
                        i++;

                        break;
                    }
                }

                write(1, buf+j, i-j);
                if(start){
                    write(1, "\n", 1);
                    if(k == 3){
                        write(1, "\n", 1);
                        k = 0;
                    }
                }

            }
        }
    }

    return 0;
}
