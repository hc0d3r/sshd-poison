CFLAGS += -Wall -Wextra -O2

objs =	.bin/elf-parser.o .bin/main.o .bin/breakpoint.o \
		.bin/proc-info.o .bin/ptrace.o .bin/caves.o

.PHONY: all clean

all: sshd-poison monitor

sshd-poison: $(objs) ignotum/lib/libignotum.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.bin/%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

.bin/main.o: main.c sc.h
	$(CC) $(CFLAGS) -c $< -o $@

sc.h: .bin/sc
	xxd -i $< $@

.bin/sc: sc.asm
	nasm -f bin $< -o $@

monitor: monitor.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

ignotum/lib/libignotum.a:
	$(MAKE) -C ignotum

clean:
	-rm -f $(objs) sshd-poison .bin/sc monitor
	$(MAKE) -C ignotum clean
