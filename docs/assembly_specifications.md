# VM16 Assembly Language Specification  

## Overview  
This document specifies the custom assembly language for the 16-bit virtual machine (VM16). The language is designed to be:  
- **Hardware-aligned**: Directly maps to VM16's architecture  
- **Expressive**: Supports modern programming patterns  
- **Familiar**: Blends concepts from x86, ARM, and RISC-V  
- **Efficient**: Optimized for compiler generation  

## Architecture Overview  
- **16-bit** data/address bus  
- **32KB ROM** (0x0000-0x7FFF) for program code  
- **32KB RAM** (0x8000-0xFEFF) for data/stack  
- **16 I/O ports** (0xFF00-0xFF0F) for device communication  
- **8 registers**:  
  | Register | Purpose          |  
  |----------|------------------|  
  | A, B, C, D | General purpose |  
  | SP       | Stack pointer    |  
  | PC       | Program counter  |  
  | FP       | Frame pointer    |  
  | FLAGS    | Status flags     |  

## Instruction Set  

### 1. Data Movement  
| Mnemonic | Operands          | Description                     |  
|----------|-------------------|---------------------------------|  
| MOV      | Rd, Rs           | Copy register Rs to Rd          |  
| MOV      | Rd, #imm         | Load 16-bit immediate           |  
| MOV      | Rd, [Rs]         | Load from memory address in Rs  |  
| MOV      | [Rd], Rs         | Store to memory address in Rd   |  
| PUSH     | Rs               | Push register to stack          |  
| POP      | Rd               | Pop stack to register           |  
| LEA      | Rd, #imm         | Load absolute address           |  
| LEA      | Rd, LABEL        | Load PC-relative address        |  
| LEA      | Rd, [Rs + #imm]  | Base register + offset address  |  

### 2. Arithmetic Operations  
| Mnemonic | Operands          | Description                     |  
|----------|-------------------|---------------------------------|  
| ADD      | Rd, Rs            | Rd = Rd + Rs                    |  
| ADD      | Rd, #imm          | Rd = Rd + immediate             |  
| SUB      | Rd, Rs            | Rd = Rd - Rs                    |  
| MUL      | Rd, Rs            | Rd = Rd * Rs (16-bit result)    |  
| DIV      | Rd, Rs            | Rd = Rd / Rs (integer division) |  
| INC      | Rd                | Increment register              |  
| DEC      | Rd                | Decrement register              |  
| NEG      | Rd                | Two's complement negation       |  

### 3. Logical Operations  
| Mnemonic | Operands          | Description                     |  
|----------|-------------------|---------------------------------|  
| AND      | Rd, Rs           | Bitwise AND                     |  
| OR       | Rd, Rs           | Bitwise OR                      |  
| XOR      | Rd, Rs           | Bitwise XOR                     |  
| NOT      | Rd               | Bitwise complement              |  
| SHL      | Rd, #count       | Shift left (0-15 bits)          |  
| SHR      | Rd, #count       | Logical shift right             |  
| SAR      | Rd, #count       | Arithmetic shift right          |  

### 4. Control Flow  
| Mnemonic | Operands          | Description                     |  
|----------|-------------------|---------------------------------|  
| JMP      | LABEL            | Unconditional jump              |  
| JZ       | LABEL            | Jump if zero flag set           |  
| JNZ      | LABEL            | Jump if zero flag not set       |  
| JC       | LABEL            | Jump if carry flag set          |  
| JNC      | LABEL            | Jump if carry flag not set      |  
| CALL     | LABEL            | Call subroutine                 |  
| RET      |                   | Return from subroutine          |  
| CMP      | Rd, Rs           | Compare registers (set flags)   |  
| TEST     | Rd, Rs           | Test bitwise AND (set flags)    |  
| HLT      |                   | Halt execution                  |  
| NOP      |                   | No operation                    |  

### 5. I/O Operations  
| Mnemonic | Operands          | Description                     |  
|----------|-------------------|---------------------------------|  
| OUT      | #port             | Output A to I/O port (0-15)     |  
| IN       | #port             | Input from I/O port to A        |  

## Addressing Modes  

| Mode          | Syntax          | Example            | Description                     |  
|---------------|-----------------|--------------------|---------------------------------|  
| Immediate     | #value          | MOV A, #0x1234    | 16-bit literal constant         |  
| Register      | Reg             | ADD A, B           | Direct register access          |  
| Direct        | [address]       | MOV A, [0x8000]    | Absolute memory address         |  
| Register Indirect | [Reg]       | MOV C, [B]         | Address contained in register   |  
| Base+Offset   | [Reg + #offset] | LEA D, [C + #0x10] | Register value + offset         |  
| PC-Relative   | LABEL           | JMP MAIN_LOOP      | Relative to current PC          |  

## Directives  

| Directive    | Arguments        | Description                          |  
|--------------|------------------|--------------------------------------|  
| .ORG         | address          | Set program origin                   |  
| .DB          | byte1, byte2,... | Define byte data                     |  
| .DW          | word1, word2,... | Define 16-bit words                  |  
| .DS          | count            | Reserve bytes                        |  
| .EQU         | NAME = value     | Define constant                      |  
| ;            | text             | Comment (line)                       |  
| /* */        | text             | Comment (block)                      |  

## Status Flags  

| Flag | Bit | Meaning                        |  
|------|-----|--------------------------------|  
| Z    | 0   | Zero (result = 0)              |  
| N    | 1   | Negative (sign bit set)        |  
| C    | 2   | Carry (unsigned overflow)      |  
| O    | 3   | Overflow (signed overflow)     |  

Flags are automatically set by:  
- Arithmetic operations (ADD, SUB, MUL, DIV, INC, DEC, NEG)  
- Logical operations (AND, OR, XOR, NOT)  
- Shift operations (SHL, SHR, SAR)  
- Explicit comparison instructions (CMP, TEST)  

## Programming Guide  

### Basic Structure  
```asm 
.ORG 0x0000       ; Set program start in ROM

MAIN:  
    MOV A, #0      ; Initialize counter  
    MOV B, #1      ; Initialize value  

LOOP:  
    ADD A, B       ; A += B  
    INC B          ; B++  
    CMP B, #10     ; Compare B to 10  
    JNZ LOOP       ; Loop if not zero  
    HLT            ; Stop execution  
```

### Data Definition  
```asm 
.ORG 0x1000  
DATA:  
    .DB 'H','e','l','l','o',0  ; Null-terminated string  
    .DW 0x1234, 0xABCD         ; 16-bit values  
BUFFER:  
    .DS 32                     ; 32-byte buffer  
```

### Subroutine Call  
```asm 
.ORG 0x2000  
START:  
    MOV A, #5  
    CALL DOUBLE    ; Call subroutine  
    HLT  

; Double input value in A  
DOUBLE:  
    ADD A, A       ; A *= 2  
    RET            ; Return  
```

### I/O Operations  
```asm 
.ORG 0x3000  
    MOV A, #'A'   ; Load character  
    OUT #0        ; Output to console  
    IN #1         ; Read input port  
    MOV [0x8000], A ; Store in RAM  
    HLT  
```

## Best Practices  

1. **Memory Organization**:  
   - Place code in ROM (0x0000-0x7FFF)  
   - Use RAM (0x8000+) for variables and stack  
   - Reserve stack space with `.DS` directive  

2. **Subroutine Conventions**:  
   - Use CALL/RET for function calls  
   - Preserve registers with PUSH/POP  
   - Pass arguments in A/B/C/D registers  

3. **Efficient Coding**:  
   - Use LEA for address calculations  
   - Prefer register operations over memory access  
   - Use CMP/TEST before conditional jumps  

4. **I/O Handling**:  
   - Port 0: Console output (character)  
   - Port 1: Console input (character)  
   - Ports 2-15: Available for devices  
 

## Example Programs  

### Fibonacci Sequence  
```asm 
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
```  

### String Copy  
```asm 
.ORG 0x1000  
    LEA C, SRC       ; Source address  
    LEA D, DEST      ; Destination address  

COPY_LOOP:  
    MOV A, [C]       ; Load character  
    CMP A, #0        ; Check null terminator  
    JZ DONE  
    MOV [D], A       ; Store character  
    INC C            ; Next source  
    INC D            ; Next destination  
    JMP COPY_LOOP  

DONE:  
    HLT  

SRC:  
    .DB "Hello VM16!", 0  
DEST:  
    .DS 32           ; Reserve space  
```  

## Appendix: Opcode Quick Reference  

| Mnemonic | Opcode | Mnemonic | Opcode |  
|----------|--------|----------|--------|  
| MOV reg  | 0x01   | ADD imm  | 0x11   |  
| MOV [A]  | 0x02   | SUB reg  | 0x12   |  
| MOV mem  | 0x03   | SUB imm  | 0x13   |  
| MOV imm  | 0x04   | MUL      | 0x14   |  
| LD       | 0x05   | DIV      | 0x15   |  
| ST       | 0x06   | INC      | 0x16   |  
| PUSH     | 0x07   | DEC      | 0x17   |  
| POP      | 0x08   | NEG      | 0x18   |  
| LEA      | 0x09   | AND      | 0x20   |  
| ADD reg  | 0x10   | ...      | ...    |  

> Full opcode mapping available in `instruction_set.md`  

---  
**Revision**: 1.1  
**Date**: 2025-08-16  
**Author**: Omar Merroun
