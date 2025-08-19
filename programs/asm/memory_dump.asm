.ORG 0x0000
    LEA C, SRC            ; start address to dump
    MOV D, #16            ; number of 16-bit words

DUMP_LOOP:
    MOV A, [C]            ; A = word
    CALL PRINT_WORD_HEX   ; prints 4 hex chars
    MOV A, #'\n'
    OUT #0
    ADD C, #2             ; next word
    DEC D
    JNZ DUMP_LOOP
    HLT

; ---- print 16-bit word in A as 4 hex chars ----
PRINT_WORD_HEX:
    PUSH B

    MOV B, A
    SHR B, #12            ; nibble 3
    MOV A, B
    CALL NIBBLE_TO_ASCII
    OUT #0

    MOV B, A              ; restore from A (still has nibble char) -> need original word again
    ; reload original from return slot: we saved only B; so re-derive from caller: keep original in D?
    ; Simpler: caller passes word in A; copy to B and keep A as scratch:
    ; We'll reimplement:

    POP B                 ; undo push to keep code simple
    RET

; (compact correct version:)
; Caller convention: word to print is in A.
; Uses B as scratch, but preserves it.

PRINT_WORD_HEX:
    PUSH B
    MOV B, A
    SHR A, #12            ; nibble 3
    CALL N2A
    OUT #0
    MOV A, B
    SHR A, #8             ; nibble 2
    AND A, #0x000F
    CALL N2A
    OUT #0
    MOV A, B
    SHR A, #4             ; nibble 1
    AND A, #0x000F
    CALL N2A
    OUT #0
    MOV A, B
    AND A, #0x000F        ; nibble 0
    CALL N2A
    OUT #0
    POP B
    RET

; A = nibble (0..15) -> A = ASCII
N2A:
    CMP A, #9
    JLE N2A_DIG
    ADD A, #55            ; 'A' - 10
    RET
N2A_DIG:
    ADD A, #48            ; '0'
    RET

SRC: .DW 0x1234,0xABCD,0x0000,0xDEAD,0xBEEF,0x0001,0x0ACE,0xFACE
     .DW 0x1111,0x2222,0x3333,0x4444,0x5555,0x6666,0x7777,0x8888
