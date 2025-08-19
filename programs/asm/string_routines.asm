; C = ptr
; Returns length in A
STRLEN:
    MOV A, #0
.L1:
    MOV B, [C]
    CMP B, #0
    JZ .DONE
    INC A
    INC C
    JMP .L1
.DONE:
    RET

; strcpy: C=src, D=dst
STRCPY:
.L2:
    MOV A, [C]
    MOV [D], A
    INC C
    INC D
    CMP A, #0
    JNZ .L2
    RET

; strcmp: C=s1, D=s2 ; A=0 if equal, 1 otherwise
STRCMP:
.L3:
    MOV A, [C]
    MOV B, [D]
    CMP A, B
    JNZ .NE
    CMP A, #0
    JZ .EQ
    INC C
    INC D
    JMP .L3
.EQ:
    MOV A, #0
    RET
.NE:
    MOV A, #1
    RET
