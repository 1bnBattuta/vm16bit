# 16-bit Educational Virtual Machine Architecture

## Overview
A Harvard architecture VM designed to execute compiled C programs with:

- **16-bit accumulator-based design**
- Separate 32KB ROM (program) and 32KB RAM (data)
- 8 core registers with status flags
- Downward-growing stack (0xFFFE - 0xFFFF)
- Little-endian memory organization

## Registers
| Register | Size  | Purpose                              |
|----------|-------|--------------------------------------|
| A        | 16-bit| Accumulator (primary operations)     |
| B        | 16-bit| General purpose                      |
| C        | 16-bit| General purpose                      |
| D        | 16-bit| General purpose                      |
| SP       | 16-bit| Stack Pointer (points to stack top)   |
| PC       | 16-bit| Program Counter (next instruction)   |
| FP       | 16-bit| Frame Pointer (stack frames)          |
| FLAGS    | 8-bit | Status flags (bitmask)               |

### FLAGS Register Format

7 6 5 4 3 2 1 0
│ │ │ │ │ │ │ └─ Carry (C)
│ │ │ │ │ │ └─── Zero (Z)
│ │ │ │ │ └───── Reserved
│ │ │ │ └─────── Reserved
│ │ │ └───────── Reserved
│ │ └─────────── Overflow (O)
└─────────────── Negative (N)


## Memory Layout (64KB Total)
| Address Range  | Size  | Purpose                         |
|----------------|-------|---------------------------------|
| `0x0000-0x7FFF`| 32KB  | **ROM** (Program Code)          |
| `0x8000-0xFFFD`| 32KB  | **RAM** (Data/Heap)             |
| `0xFFFE-0xFFFF`| 2B    | **Stack** (Top downward)        |

## Key Design Decisions
1. **Harvard Architecture**  
   Strict separation between code (ROM) and data (RAM) prevents accidental program modification and simplifies security.

2. **Accumulator-based Design**  
   Classic architecture that clearly demonstrates fundamental computing concepts:
   ```c
   // C operation implementation example:
   // c = a + b;
   LOAD A, [a_addr]  ; Get a
   ADD A, [b_addr]   ; Add b
   STORE [c_addr], A ; Store result
   ```

3. **C-Compatible Features**
   - Frame Pointer (FP) for stack frames
   - Downward-growing stack (matches x86 convention)
   - Status flags for conditional operations
   - 16-bit data width (supports C `int` type)

## Instruction Set Requirements
To support C compilation, the VM will implement:

| Category       | Mnemonics                          |
|----------------|------------------------------------|
| Data Movement  | `MOV`, `LD`, `ST`, `PUSH`, `POP`   |
| Arithmetic     | `ADD`, `SUB`, `MUL`, `DIV`, `INC`, `DEC` |
| Logic          | `AND`, `OR`, `XOR`, `NOT`, `SHL`, `SHR` |
| Control Flow   | `JMP`, `CALL`, `RET`, `JZ`, `JNZ`, `JC` |
| Comparison     | `CMP`, `TEST`                      |

## Calling Convention
C functions will use:
1. Caller pushes arguments right-to-left
2. `CALL` instruction:
   - Pushes return address to stack
   - Sets FP = SP for new stack frame
3. Callee:
   ```asm
   PUSH FP       ; Save previous frame
   MOV FP, SP    ; New frame
   SUB SP, N     ; Allocate locals
   ```
4. Return:
   ```asm
   MOV SP, FP    ; Deallocate locals
   POP FP        ; Restore previous frame
   RET           ; Pop return address
   ```

## I/O Handling
Memory-mapped I/O regions (future expansion):
```c
#define CONSOLE_OUT 0xFFFF8000  // Write chars here
#define KEYBOARD_IN 0xFFFF8002  // Read input here
```

## Limitations and Trade-offs
1. 32KB program limit (addressable with bank switching later)
2. No hardware floating point
3. Simplified MMU (no virtual memory)
4. Atomic operations not implemented

## Development Roadmap
1. Implement core VM in Python (`vm.py`)
2. Build assembler (`asm.py`)
3. Create C compiler frontend (`compiler/`)
4. Add debugger and disassembler
5. Implement memory-mapped I/O



## Example Memory Layout

+-------------------+ 0x0000
|      ROM          |
| (Program Code)    |
|                   |
+-------------------+ 0x7FFF
|      RAM          |
| (Global Data)     |
|                   |
|                   |
|                   |
|                   |
| Heap (grows up)   |
|                   |
+-------------------+ 
| Stack (grows down)|
|                   |
+-------------------+ 0xFFFE
| Stack Top         |
+-------------------+ 0xFFFF

