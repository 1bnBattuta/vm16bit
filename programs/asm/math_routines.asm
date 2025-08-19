; MUL: A = A * B (16-bit, naive add)
MUL16:
    MOV C, #0
.M1:
    CMP B, #0
    JZ .MEND
    ADD C, A
    DEC B
    JMP .M1
.MEND:
    MOV A, C
    RET

; DIV/MOD by repeated subtraction
; Input: A = dividend, B = divisor (B>0)
; Output: A = quotient, D = remainder
DIVMOD16:
    MOV C, #0            ; quotient
    MOV D, A             ; remainder work
.D1:
    CMP D, B
    JL .DEND
    SUB D, B
    INC C
    JMP .D1
.DEND:
    MOV A, C
    RET

; GCD(A,B) -> A
GCD:
.G1:
    CMP B, #0
    JZ .GDONE
    ; compute A mod B using DIVMOD16
    PUSH A
    PUSH B
    CALL DIVMOD16        ; A=quotient, D=remainder
    POP B                ; restore divisor into B (unchanged)
    POP A                ; restore dividend (ignored)
    MOV A, B
    MOV B, D
    JMP .G1
.GDONE:
    RET
