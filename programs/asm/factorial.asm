; ==============================
; Factorial program in VM16
; ==============================
.ORG 0x0000        ; program starts at 0x0000

MAIN:
    MOV A, #1       ; accumulator for factorial
    MOV B, #1       ; counter
    MOV C, #5       ; target factorial + 1
    MOV D, #0x8000  ; memory pointer


LOOP:
    MUL A, B
    MOV [D], A   ; optional: store result in memory
    ADD D, #2    ; move pointer by 2 bytes

    INC B
    CMP B, C
    JNZ LOOP     ; keep looping until B <= C

HLT

