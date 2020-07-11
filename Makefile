CFLAGS += -Wall -Wextra -O2 -Iignotum/src -static

objs =	.bin/elf-parser.o .bin/ptrace-loop.o .bin/breakpoint.o \
		.bin/ssh-server.o .bin/ssh-client.o .bin/caves.o \
		.bin/memutils.o	.bin/authpassword-scan.o .bin/sshd-poison.o

.PHONY: all clean

all: ignotum/lib/libignotum.a sshd-poison monitor

sshd-poison: LDFLAGS+=-lutil
sshd-poison: $(objs) ignotum/lib/libignotum.a
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

# __deps__

.bin/authpassword-scan.o: authpassword-scan.c authpassword-scan.h \
	ssh-definitions.h .bin/memutils.o
.bin/breakpoint.o: breakpoint.c breakpoint.h
.bin/caves.o: caves.c caves.h elf-parser.h
.bin/elf-parser.o: elf-parser.c elf-parser.h
.bin/memutils.o: memutils.c memutils.h .bin/elf-parser.o
.bin/ptrace-loop.o: ptrace-loop.c ptrace-loop.h
.bin/ssh-server.o: ssh-server.c ssh-server.h output.h
.bin/ssh-client.o: ssh-client.c ssh-client.h
.bin/sshd-poison.o: sshd-poison.c .bin/ptrace-loop.o .bin/breakpoint.o \
	.bin/caves.o .bin/ssh-client.o .bin/ssh-server.o .bin/memutils.o \
	.bin/authpassword-scan.o .bin/elf-parser.o sc.h output.h

.bin/ssh-client.o: LDFLAGS+=-ltuil

# __deps__

.bin/%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(LDFLAGS)

sc.h: .bin/sc
	xxd -i $< $@

.bin/sc: sc.asm
	nasm -f bin $< -o $@

monitor: monitor.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

ignotum/lib/libignotum.a:
	$(MAKE) -C ignotum

clean:
	-rm -f $(objs) sshd-poison .bin/sc monitor
	$(MAKE) -C ignotum clean
