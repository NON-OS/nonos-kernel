; Simple boot sector test for N0N-OS
bits 16
org 0x7C00

start:
    ; Clear screen
    mov ah, 0x00
    mov al, 0x03
    int 0x10
    
    ; Print message
    mov si, msg
    call print_string
    
    ; Halt
    cli
    hlt

print_string:
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    ret

msg db 'N0N-OS Kernel Boot Test - SUCCESS!', 0

; Fill rest of sector
times 510-($-$$) db 0
dw 0xAA55  ; Boot signature