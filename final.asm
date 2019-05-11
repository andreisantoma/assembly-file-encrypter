.386
.model flat, stdcall
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;including libraries..
includelib msvcrt.lib
extern exit: proc
extern scanf: proc
extern printf: proc
extern gets: proc
extern puts: proc
extern fopen: proc
extern fclose: proc
extern fread: proc
extern fwrite: proc
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


public start
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


.data

max = 50
filePath db max+1 dup (0)
integerFormat db "%d", 0
integerFormat2 db "%lld",  0
encryptedFilePath db "encrypted.bin", 0
decryptedFilePath db "decrypted.bin", 0
mesaj1 db "Introduceti calea completa catre fisierul sursa:", 0
unableToOpenInputFileMsg db 10, "Fisierul sursa nu s-a putut deschide. Reintroduceti calea completa catre acesta:", 0
unableToOpenEncFileMsg db 10, "Fisierul criptat nu s-a putut deschide", 0
unableToOpenDecFileMsg db 10, "Fisierul decriptat nu s-a putut deschide", 0
inputFileSuccessMsg db 10, "Fisierul sursa s-a deschis cu succes", 0
EncFileSuccessMsg db "Fisierul criptat s-a deschis cu succes", 0
DecFileSuccessMsg db "Fisierul decriptat s-a deschis cu succes", 0
algQuery db 10, "Introduceti litera corespunzatoare algoritmului de criptare care se va folosi:", 10, 9, "A - primul algoritm", 10, 9, "B - al doilea algoritm", 0
algSel db 0, 0
unableToReadAlgSelMsg db "Introduceti A sau B", 0
selectedAlgIsA db 10, "S-a selectat algoritmul A", 0
selectedAlgIsB db 10, "S-a selectat algoritmul B", 0
queryKeyA db "Introduceti o cheie de criptare (numar intreg aflat in intervalul 0-7)", 0
queryKeyB db "Introduceti o cheie de criptare (numar intreg stocat pe maxim 64 de biti)", 0
keyAerror db "Valoarea introdusa nu este in intervalul 0-7", 0
A_encSuccess db "Criptarea cu cheia %d s-a realizat cu succes", 10, 0
B_encSuccess db "Criptarea cu cheia %lld s-a realizat cu succes", 10, 0
keyA db 0
keyB dq 0
mode_rb db "rb", 0
mode_wb db "wb", 0
buffer db 0
bufferQ db 0
format1 db "%c ", 0

.code

openInputFile proc
	mov ebp, esp
	push offset mesaj1
	call puts
	add esp, 4
	
	retryRead:
	push offset filePath
	call gets
	add esp, 4
	
	push offset mode_rb
	push offset filePath
	call fopen
	cmp eax, 0
	je unableToOpenInputFile
	;successfully opened file
	mov esi, eax
	add esp,4*2
	push offset inputFileSuccessMsg
	call puts
	add esp, 4
	jmp endInputFileRead
	
	;failed opening input file
	unableToOpenInputFile:
	push offset unableToOpenInputFileMsg
	call puts
	add esp, 4
	jmp retryRead
	
	endInputFileRead:
	mov esp, ebp
	ret
openInputFile endp

openEncFile proc
	mov ebp, esp
	
	;opening the file which will contain the encrypted text
	push offset mode_wb
	push offset encryptedFilePath
	call fopen
	cmp eax, 0
	je unableToOpenEncFile
	mov edi, eax
	add esp, 4*2
	jmp EncFileSuccess
	
	unableToOpenEncFile:
	push offset unableToOpenEncFileMsg
	call puts
	add esp, 4
	
	EncFileSuccess:
	push offset EncFileSuccessMsg
	call puts
	add esp, 4

	mov esp, ebp
	ret
openEncFile endp

openDecFile proc
	mov ebp, esp
	
	;opening the file which will contain the decrypted text
	push offset mode_wb
	push offset decryptedFilePath
	call fopen
	cmp eax, 0
	je unableToOpenDecFile
	mov ebx, eax
	add esp, 4*2
	jmp DecFileSuccess
	
	unableToOpenDecFile:
	push offset unableToOpenDecFileMsg
	call puts
	add esp, 4
	
	DecFileSuccess:
	push offset DecFileSuccessMsg
	call puts
	add esp, 4
	mov esp, ebp
	ret
openDecFile endp

writeByte1 proc
	push ebp
	mov ebp, esp
	
	push edi
	push 1
	push 1
	push offset buffer
	call fwrite
	add esp, 4*4
	
	mov esp, ebp
	pop ebp
	ret
writeByte1 endp

writeByte2 proc
	push ebp
	mov ebp, esp
	
	push ebx
	push 1
	push 1
	push offset buffer
	call fwrite
	add esp, 4*4
	
	mov esp, ebp
	pop ebp
	ret
writeByte2 endp

encA proc
	push ebp
	mov ebp, esp
	
	xor ecx,ecx
	mov cl,buffer
	not ecx
	inc ecx
	
	cmp keyA, 0
	je A_1_0
	cmp keyA, 1
	je A_1_1
	cmp keyA, 2
	je A_1_2
	cmp keyA, 3
	je A_1_3
	cmp keyA, 4
	je A_1_4
	cmp keyA, 5
	je A_1_5
	cmp keyA, 6
	je A_1_6
	cmp keyA, 7
	je A_1_7
	
	A_1_0:
	ror cl, 0
	jmp A_end
	
	A_1_1:
	ror cl, 1
	jmp A_end
	
	A_1_2:
	ror cl, 2
	jmp A_end
	
	A_1_3:
	ror cl, 3
	jmp A_end
	
	A_1_4:
	ror cl, 4
	jmp A_end
	
	A_1_5:
	ror cl, 5
	jmp A_end
	
	A_1_6:
	ror cl, 6
	jmp A_end
	
	A_1_7:
	ror cl, 7
	
	
	A_end:
	mov buffer, cl
	
	mov esp, ebp
	pop ebp
	ret
encA endp

decA proc
	push ebp
	mov ebp, esp
	
	xor ecx, ecx
	mov cl, buffer
	
	cmp keyA, 0
	je A_2_0
	cmp keyA, 1
	je A_2_1
	cmp keyA, 2
	je A_2_2
	cmp keyA, 3
	je A_2_3
	cmp keyA, 4
	je A_2_4
	cmp keyA, 5
	je A_2_5
	cmp keyA, 6
	je A_2_6
	cmp keyA, 7
	je A_2_7
	
	A_2_0:
	rol cl, 0
	jmp A_end2
	
	A_2_1:
	rol cl, 1
	jmp A_end2
	
	A_2_2:
	rol cl, 2
	jmp A_end2
	
	A_2_3:
	rol cl, 3
	jmp A_end2
	
	A_2_4:
	rol cl, 4
	jmp A_end2
	
	A_2_5:
	rol cl, 5
	jmp A_end2
	
	A_2_6:
	rol cl, 6
	jmp A_end2
	
	A_2_7:
	ror cl, 7
	
	A_end2:
	dec ecx
	not ecx
	mov buffer, cl
	
	mov esp, ebp
	pop ebp
	ret
decA endp

operationA proc
	push ebp
	mov ebp, esp
	
	push offset queryKeyA
	call puts
	add esp, 4
	
	readKeyA:
	push offset keyA
	push offset integerFormat
	call scanf
	add esp, 4*2
	
	cmp keyA, 0
	jl retryQueryKeyA
	cmp keyA, 7
	jg retryQueryKeyA
	
	jmp keyAsuccess
	
	retryQueryKeyA:
	push offset keyAerror
	call puts
	add esp,4
	jmp readKeyA
	
	keyAsuccess:
	
	;pushing arguments for file reading onto the stack	
	push esi
	push 1
	push 1
	push offset buffer
	
	read_loop:
	call fread
	test eax,eax
	jz end_read_loop
		;encryption of read character
		call encA
		;writing in the encrypted file
		call writeByte1
		;decryption of written character
		call decA
		;writing in the encrypted file
		call writeByte2
	jmp read_loop
	
	;stopping the reading loop
	end_read_loop:
	add esp, 4*4
	push esi
	call fclose
	add esp, 4
	
	xor edi, edi
	mov edi, DWORD PTR [keyA]
	push edi
	push offset A_encSuccess
	call printf
	add esp, 4*2
	
	mov esp, ebp
	pop ebp
	ret
operationA endp

encB proc
	push ebp
	mov ebp, esp
	
	not DWORD PTR [bufferQ]
	not DWORD PTR [bufferQ+4]
	xor edx, edx
	mov edx, DWORD PTR [keyB]
	xor DWORD PTR [bufferQ], edx
	xor edx, edx
	mov edx, DWORD PTR [keyB+4]
	xor DWORD PTR [bufferQ+4], edx
	
	mov esp, ebp
	pop ebp
	ret
encB endp

decB proc
	push ebp
	mov ebp, esp
	
	xor edx, edx
	mov edx, DWORD PTR [keyB]
	xor DWORD PTR [bufferQ], edx
	xor edx, edx
	mov edx, DWORD PTR [keyB+4]
	xor DWORD PTR [bufferQ+4], edx
	
	not DWORD PTR [bufferQ]
	not DWORD PTR [bufferQ+4]
	
	mov esp, ebp
	pop ebp
	ret
decB endp

writeQuad1 proc
	push ebp
	mov ebp, esp
	
	push edi
	push 8
	push 1
	push offset bufferQ
	
	call fwrite
	add esp, 4*4
	
	mov esp, ebp
	pop ebp
	ret
writeQuad1 endp

writeQuad2 proc
	push ebp
	mov ebp, esp
	
	push ebx
	push 8
	push 1
	push offset bufferQ
	
	call fwrite
	add esp, 4*4
	
	mov esp, ebp
	pop ebp
	ret
writeQuad2 endp

operationB proc
push ebp
	mov ebp, esp
	
	push offset queryKeyB
	call puts
	add esp, 4
	
	push offset keyB
	push offset integerFormat2
	call scanf
	add esp, 4*2
	
	
	push esi
	push 8
	push 1
	push offset bufferQ
	
	read_loop:
	call fread
	
	cmp eax, 8
	jl end_read_loop		
		
		;encryption of read character
		continue_reading:
		call encB		
		;writing in the encrypted file
		call writeQuad1		
		;decryption of written character
		call decB
		;writing in the decrypted file
		call writeQuad2
	jmp read_loop
	
	;stopping the reading loop
	end_read_loop:
	
	cmp eax, 0
	jg padding_loop
	add esp, 4*4
	push esi
	call fclose
	add esp, 4
	
	
	push DWORD PTR[keyB+4]
	push DWORD PTR[keyB]	
	push offset B_encSuccess
	call printf
	add esp, 4*2

	
	mov esp, ebp
	pop ebp
	ret
	
	padding_loop:
	
	mov BYTE PTR [bufferQ+EAX], 0
	inc EAX
	cmp EAX, 8
	jg continue_reading
	
	jmp padding_loop
operationB endp

encryp proc
	push ebp
	mov ebp, esp
	push offset algQuery
	call puts
	add esp, 4
	
	tryRead:
	push offset algSel
	call gets
	add esp, 4
	
	cmp algSel, 41H
	je algoritmA
	cmp algSel, 42H
	je algoritmB
	jmp retryRead2
	
	algoritmA:	
	push offset selectedAlgIsA
	call puts
	add esp, 4
	call operationA
	jmp selReadSuccess
	
	algoritmB:
	push offset selectedAlgIsB
	call puts
	add esp, 4
	call operationB
	jmp selReadSuccess
	
	retryRead2:
	push offset unableToReadAlgSelMsg
	call puts 
	add esp, 4
	jmp tryRead
	
	selReadSuccess:
	
	mov esp, ebp
	pop ebp
	ret
encryp endp
start:
		
	call openInputFile
	call openEncFile
	call openDecFile
	call encryp
	
	;exiting the program
	push 0
	call exit
end start
