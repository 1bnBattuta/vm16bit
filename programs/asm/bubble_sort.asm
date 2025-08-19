.ORG 0x0000
    LEA C, ARR           ; C = base
    MOV D, #5            ; D = length

SORT_OUTER:
    ; swapped flag in memory (byte)
    MOV A, #0
    MOV [SWAP], A

    LEA C, ARR
    MOV B, D
    DEC B                ; passes compare count = len-1
    JZ SORT_DONE

INNER:
    MOV A, [C]           ; A = x[i]
    MOV D, [C + #2]      ; D = x[i+1]
    CMP A, D
    JLE NOSW
    ; swap
    MOV [C], D
    MOV [C + #2], A
    MOV A, #1
    MOV [SWAP], A
NOSW:
    ADD C, #2
    DEC B
    JNZ INNER

    MOV A, [SWAP]
    CMP A, #0
    JNZ SORT_OUTER

SORT_DONE:
    HLT

ARR:  .DW 5,3,4,1,2
SWAP: .DB 0
