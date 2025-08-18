; ==============================
; Fibonacci sequence in VM16
; ==============================
.ORG 0x0000        ; program starts at 0x0000

MAIN:
    MOV A, #0      ; first term
    MOV B, #1      ; second term
    MOV C, #10     ; loop counter (10 numbers)
    MOV D, #0x8000 ; destination pointer

LOOP:
    MOV [D], A     ; store current term in memory
    INC D          ; advance pointer (low byte)
    INC D          ; advance pointer (high byte, since 16-bit word)

    PUSH A         ; save old A on stack
    ADD A, B       ; A = A + B (next Fibonacci number)
    POP B          ; B = old A (shift forward)

    DEC C          ; decrement counter
    JNZ LOOP       ; repeat if not zero

    HLT            ; stop

