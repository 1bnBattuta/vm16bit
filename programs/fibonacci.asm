.ORG 0x0000  
    MOV A, #0        ; F(0)  
    MOV B, #1        ; F(1)  
    MOV C, #10       ; Counter  
    MOV D, #0x8000   ; Output address  

LOOP:  
    MOV [D], A       ; Store current  
    MOV A, B         ; Swap values  
    ADD B, [D]       ; Calculate next  
    INC D            ; Increment address  
    INC D  
    DEC C            ; Decrement counter  
    JNZ LOOP         ; Continue loop  
    HLT  
