# Virtual Machine Instruction Set Specification

## Overview
- **Instruction Length**: Variable (1-4 bytes)
- **Operand Types**: Register, Immediate, Memory Address
- **Endianness**: Little-endian
- **Addressing Modes**: Direct, Indirect, Immediate, Stack-Relative

## Instruction Format
┌───────────────┬───────────────┬──────────────────┐
│ Opcode (1B) │ Operand 1 │ Operand 2 │
│ │ (4-bit reg) │ (16-bit imm) │
│ │ (4-bit flags) │ │
└───────────────┴───────────────┴──────────────────┘


### Register Encoding
0000: A (Accumulator)
0001: B (General Purpose)
0010: C (General Purpose)
0011: D (General Purpose)
0100: SP (Stack Pointer)
0101: PC (Program Counter)
0110: FP (Frame Pointer)
0111: FLAGS (Status Register)




# Virtual Machine Instruction Set

## Instruction Reference

| Opcode | Mnemonic | Operands     | Description                          | Flags      | Cycles |
|--------|----------|--------------|--------------------------------------|------------|--------|
| 0x01   | MOV      | Rd, Rs       | Register to register move            | None       | 1      |
| 0x02   | MOV      | Rd, [A]      | Load from memory at A                | None       | 3      |
| 0x03   | MOV      | [A], Rs      | Store to memory at A                 | None       | 3      |
| 0x04   | MOV      | Rd, #imm     | Load 16-bit immediate                | None       | 2      |
| 0x05   | LD       | Rd, [Rs]     | Indirect load                        | None       | 3      |
| 0x06   | ST       | [Rd], Rs     | Indirect store                       | None       | 3      |
| 0x07   | PUSH     | Rs           | Push register to stack               | None       | 2      |
| 0x08   | POP      | Rd           | Pop stack to register                | None       | 2      |
| 0x09   | LEA      | Rd, #imm     | Load effective address               | None       | 2      |
| 0x10   | ADD      | Rd, Rs       | Add registers                        | Z,C,O,N    | 1      |
| 0x11   | ADD      | Rd, #imm     | Add immediate                        | Z,C,O,N    | 2      |
| 0x12   | SUB      | Rd, Rs       | Subtract registers                   | Z,C,O,N    | 1      |
| 0x13   | SUB      | Rd, #imm     | Subtract immediate                   | Z,C,O,N    | 2      |
| 0x14   | MUL      | Rd, Rs       | Unsigned multiply                    | Z,C        | 3      |
| 0x15   | DIV      | Rd, Rs       | Unsigned divide                      | Z (if div0)| 4      |
| 0x16   | INC      | Rd           | Increment register                   | Z,O,N      | 1      |
| 0x17   | DEC      | Rd           | Decrement register                   | Z,O,N      | 1      |
| 0x18   | NEG      | Rd           | Negate (two's complement)            | Z,C,O,N    | 1      |
| 0x20   | AND      | Rd, Rs       | Bitwise AND                          | Z,N        | 1      |
| 0x21   | OR       | Rd, Rs       | Bitwise OR                           | Z,N        | 1      |
| 0x22   | XOR      | Rd, Rs       | Bitwise XOR                          | Z,N        | 1      |
| 0x23   | NOT      | Rd           | Bitwise NOT                          | Z,N        | 1      |
| 0x24   | SHL      | Rd, #imm     | Logical shift left                   | Z,C        | 1      |
| 0x25   | SHR      | Rd, #imm     | Logical shift right                  | Z,C        | 1      |
| 0x26   | SAR      | Rd, #imm     | Arithmetic shift right               | Z,C        | 1      |
| 0x30   | JMP      | addr         | Absolute jump                        | None       | 1      |
| 0x31   | JZ       | addr         | Jump if zero                         | None       | 1/2    |
| 0x32   | JNZ      | addr         | Jump if not zero                     | None       | 1/2    |
| 0x33   | JC       | addr         | Jump if carry                        | None       | 1/2    |
| 0x34   | JNC      | addr         | Jump if no carry                     | None       | 1/2    |
| 0x35   | JO       | addr         | Jump if overflow                     | None       | 1/2    |
| 0x36   | JNO      | addr         | Jump if no overflow                  | None       | 1/2    |
| 0x37   | CALL     | addr         | Call subroutine                      | None       | 4      |
| 0x38   | RET      |              | Return from subroutine               | None       | 3      |
| 0x39   | CMP      | Rd, Rs       | Compare registers                    | Z,C,O,N    | 1      |
| 0x3A   | TEST     | Rd, Rs       | Test bits                            | Z,N        | 1      |
| 0xF0   | HLT      |              | Halt execution                       | None       | -      |
| 0xF1   | NOP      |              | No operation                         | None       | 1      |
| 0xF2   | OUT      | port         | Output to I/O port                   | None       | 2      |
| 0xF3   | IN       | port         | Input from I/O port                  | None       | 2      |

## Flag Behavior
Z=Zero  C=Carry  O=Overflow  N=Negative

## Memory Map
0x0000-0x7FFF: ROM (Program)
0x8000-0xFFFD: RAM (Data)
0xFFFE-0xFFFF: Stack
0xFF00-0xFF0F: I/O Ports
