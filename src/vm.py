import os
from pathlib import Path
import sys

# Flag bit masks
C_FLAG = 0x01  # Carry
Z_FLAG = 0x02  # Zero
O_FLAG = 0x04  # Overflow
N_FLAG = 0x08  # Negative

# Register encoding
REGISTERS = {
    0x0: 'A', 0x1: 'B', 0x2: 'C', 0x3: 'D',
    0x4: 'SP', 0x5: 'PC', 0x6: 'FP', 0x7: 'FLAGS'
}

class VirtualMachine:
    def __init__(self):
        # 64KB memory (ROM: 0x0000-0x7FFF, RAM: 0x8000-0xFFFF)
        self.memory = [0] * 65536
        
        # Registers (16-bit except FLAGS which is 8-bit)
        self.reg = {
            'A': 0, 'B': 0, 'C': 0, 'D': 0,
            'SP': 0xFFFE,  # Stack Pointer
            'PC': 0,       # Program Counter
            'FP': 0,       # Frame Pointer
            'FLAGS': 0     # Status Flags
        }
        
        self.running = False
        self.cycles = 0
        self.debug = False
        self.breakpoints = set()
        self.io_ports = [0] * 16  # 16 I/O ports (0xFF00-0xFF0F)

    def load_program(self, filename, address=0):
        """Load raw binary program into memory"""
        try:
            with open(filename, 'rb') as f:  # Note 'rb' for binary mode
                binary_data = f.read()
            
            if len(binary_data) > (len(self.memory) - address):
                raise MemoryError("Program exceeds available memory")
            
            for i, byte in enumerate(binary_data):
                self.memory[address + i] = byte
                
            print(f"Loaded {len(binary_data)} bytes from {filename}")
            return True
            
        except FileNotFoundError:
            print(f"Error: File {filename} not found")
            return False

    def fetch_byte(self):
        """Fetch single byte from memory at PC"""
        byte = self.memory[self.reg['PC']]
        self.reg['PC'] += 1
        return byte

    def fetch_word(self):
        """Fetch 16-bit word (little-endian) from memory at PC"""
        low = self.fetch_byte()
        high = self.fetch_byte()
        return (high << 8) | low

    def read_mem(self, address):
        """Read byte from memory"""
        return self.memory[address]

    def write_mem(self, address, value):
        """Write byte to memory (only if in RAM area)"""
        if address >= 0x8000 or address in range(0xFF00, 0xFFFF + 1):
            self.memory[address] = value & 0xFF
        elif self.debug:
            print(f"Warning: Write to ROM at {hex(address)}")

    def read_mem_word(self, address):
        """Read 16-bit word from memory (little-endian)"""
        low = self.read_mem(address)
        high = self.read_mem(address + 1)
        return (high << 8) | low

    def write_mem_word(self, address, value):
        """Write 16-bit word to memory (little-endian)"""
        self.write_mem(address, value & 0xFF)
        self.write_mem(address + 1, (value >> 8) & 0xFF)

    def push(self, value):
        """Push 16-bit value onto stack"""
        sp = self.reg['SP']
        self.write_mem_word(sp, value)
        self.reg['SP'] -= 2

    def pop(self):
        """Pop 16-bit value from stack"""
        self.reg['SP'] += 2
        sp = self.reg['SP']
        return self.read_mem_word(sp)

    def set_flag(self, flag, condition):
        """Set or clear a specific flag"""
        if condition:
            self.reg['FLAGS'] |= flag
        else:
            self.reg['FLAGS'] &= ~flag

    def get_flag(self, flag):
        """Check if a flag is set"""
        return (self.reg['FLAGS'] & flag) != 0

    def update_flags_arith(self, result, width=16):
        """Update arithmetic flags after operation"""
        # Set Zero flag
        self.set_flag(Z_FLAG, result == 0)
        
        # Set Negative flag (sign bit)
        mask = 0x8000 if width == 16 else 0x80
        self.set_flag(N_FLAG, (result & mask) != 0)
        
        # Set Carry flag for unsigned overflow
        self.set_flag(C_FLAG, result > 0xFFFF if width == 16 else result > 0xFF)
        
        # Set Overflow flag for signed overflow
        # Overflow occurs when signs of operands are same but result sign differs
        # This is handled in individual operations

    def update_flags_logic(self, result, width=16):
        """Update flags for logical operations"""
        # Set Zero flag
        self.set_flag(Z_FLAG, result == 0)
        
        # Set Negative flag (sign bit)
        mask = 0x8000 if width == 16 else 0x80
        self.set_flag(N_FLAG, (result & mask) != 0)
        
        # Clear Carry and Overflow for logical operations
        self.set_flag(C_FLAG, False)
        self.set_flag(O_FLAG, False)

    def execute(self):
        """Main execution loop"""
        self.running = True
        while self.running:
            self.cycles += 1
            
            # Check breakpoints
            if self.reg['PC'] in self.breakpoints:
                print(f"Breakpoint hit at {hex(self.reg['PC'])}")
                self.debug = True
            
            # Fetch opcode
            opcode = self.fetch_byte()
            
            if self.debug:
                state = f"PC:{hex(self.reg['PC'])} A:{hex(self.reg['A'])} "
                state += f"B:{hex(self.reg['B'])} C:{hex(self.reg['C'])} "
                state += f"D:{hex(self.reg['D'])} SP:{hex(self.reg['SP'])} "
                state += f"FLAGS:{self.reg['FLAGS']:04b} (NZCO)"
                print(f"Executing {hex(opcode)} | {state}")
            
            # Decode and execute instruction
            try:
                # ========================================
                # Data Movement Instructions (0x01-0x09)
                # ========================================
                if opcode == 0x01:   # MOV Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.reg[rd] = self.reg[rs]
                    
                elif opcode == 0x02: # MOV Rd, [A]
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = self.read_mem_word(self.reg['A'])
                    
                elif opcode == 0x03: # MOV [A], Rs
                    reg_byte = self.fetch_byte()
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.write_mem_word(self.reg['A'], self.reg[rs])
                    
                elif opcode == 0x04: # MOV Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    imm = self.fetch_word()
                    self.reg[rd] = imm
                    
                elif opcode == 0x05: # LD Rd, [Rs]
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    addr = self.reg[rs]
                    self.reg[rd] = self.read_mem_word(addr)
                    
                elif opcode == 0x06: # ST [Rd], Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.write_mem_word(self.reg[rd], self.reg[rs])
                    
                elif opcode == 0x07: # PUSH Rs
                    reg_byte = self.fetch_byte()
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.push(self.reg[rs])
                    
                elif opcode == 0x08: # POP Rd
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = self.pop()
                    
                elif opcode == 0x09: # LEA Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    imm = self.fetch_word()
                    self.reg[rd] = self.reg['PC'] + imm
                    
                # ========================================
                # Arithmetic Instructions (0x10-0x18)
                # ========================================
                elif opcode == 0x10: # ADD Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    a = self.reg[rd]
                    b = self.reg[rs]
                    result = a + b
                    
                    # Set overflow (V) if signs same but result sign different
                    self.set_flag(O_FLAG, ((a ^ b) & 0x8000) == 0 and ((a ^ result) & 0x8000) != 0)
                    
                    self.reg[rd] = result & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x11: # ADD Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    imm = self.fetch_word()
                    a = self.reg[rd]
                    result = a + imm
                    
                    # Set overflow
                    self.set_flag(O_FLAG, ((a ^ imm) & 0x8000) == 0 and ((a ^ result) & 0x8000) != 0)
                    
                    self.reg[rd] = result & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x12: # SUB Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    a = self.reg[rd]
                    b = self.reg[rs]
                    result = a - b
                    
                    # Set overflow (V) if signs different and result sign same as subtrahend
                    self.set_flag(O_FLAG, ((a ^ b) & 0x8000) != 0 and ((b ^ result) & 0x8000) == 0)
                    
                    self.reg[rd] = result & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x13: # SUB Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    imm = self.fetch_word()
                    a = self.reg[rd]
                    result = a - imm
                    
                    # Set overflow
                    self.set_flag(O_FLAG, ((a ^ imm) & 0x8000) != 0 and ((imm ^ result) & 0x8000) == 0)
                    
                    self.reg[rd] = result & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x14: # MUL Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    a = self.reg[rd]
                    b = self.reg[rs]
                    result = a * b
                    
                    # For 16-bit multiplication, we keep the lower 16 bits
                    self.reg[rd] = result & 0xFFFF
                    
                    # Set carry if result exceeds 16 bits
                    self.set_flag(C_FLAG, result > 0xFFFF)
                    self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x15: # DIV Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    dividend = self.reg[rd]
                    divisor = self.reg[rs]
                    
                    if divisor == 0:
                        self.set_flag(Z_FLAG, True)
                        self.reg[rd] = 0xFFFF  # Error value
                    else:
                        self.set_flag(Z_FLAG, False)
                        self.reg[rd] = dividend // divisor
                        self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x16: # INC Rd
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = (self.reg[rd] + 1) & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x17: # DEC Rd
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = (self.reg[rd] - 1) & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                elif opcode == 0x18: # NEG Rd
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = (~self.reg[rd] + 1) & 0xFFFF
                    self.update_flags_arith(self.reg[rd])
                    
                # ========================================
                # Logical & Bitwise Instructions (0x20-0x26)
                # ========================================
                elif opcode == 0x20: # AND Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.reg[rd] &= self.reg[rs]
                    self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x21: # OR Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.reg[rd] |= self.reg[rs]
                    self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x22: # XOR Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    self.reg[rd] ^= self.reg[rs]
                    self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x23: # NOT Rd
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    self.reg[rd] = (~self.reg[rd]) & 0xFFFF
                    self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x24: # SHL Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    shift = self.fetch_byte() & 0x0F  # Only lower 4 bits
                    
                    if shift > 0:
                        # Save the last bit shifted out for carry
                        last_bit = (self.reg[rd] >> (16 - shift)) & 1
                        self.set_flag(C_FLAG, last_bit == 1)
                        
                        self.reg[rd] = (self.reg[rd] << shift) & 0xFFFF
                        self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x25: # SHR Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    shift = self.fetch_byte() & 0x0F
                    
                    if shift > 0:
                        # Save the last bit shifted out for carry
                        last_bit = (self.reg[rd] >> (shift - 1)) & 1
                        self.set_flag(C_FLAG, last_bit == 1)
                        
                        self.reg[rd] = self.reg[rd] >> shift
                        self.update_flags_logic(self.reg[rd])
                    
                elif opcode == 0x26: # SAR Rd, #imm
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    shift = self.fetch_byte() & 0x0F
                    
                    if shift > 0:
                        # Save the last bit shifted out for carry
                        last_bit = (self.reg[rd] >> (shift - 1)) & 1
                        self.set_flag(C_FLAG, last_bit == 1)
                        
                        # Arithmetic shift preserves sign
                        sign = self.reg[rd] & 0x8000
                        self.reg[rd] = (self.reg[rd] >> shift) | sign
                        self.update_flags_logic(self.reg[rd])
                    
                # ========================================
                # Control Flow Instructions (0x30-0x3A)
                # ========================================
                elif opcode == 0x30: # JMP addr
                    addr = self.fetch_word()
                    self.reg['PC'] = addr
                    
                elif opcode == 0x31: # JZ addr
                    addr = self.fetch_word()
                    if self.get_flag(Z_FLAG):
                        self.reg['PC'] = addr
                    
                elif opcode == 0x32: # JNZ addr
                    addr = self.fetch_word()
                    if not self.get_flag(Z_FLAG):
                        self.reg['PC'] = addr
                        
                elif opcode == 0x33: # JC addr
                    addr = self.fetch_word()
                    if self.get_flag(C_FLAG):
                        self.reg['PC'] = addr
                        
                elif opcode == 0x34: # JNC addr
                    addr = self.fetch_word()
                    if not self.get_flag(C_FLAG):
                        self.reg['PC'] = addr
                        
                elif opcode == 0x35: # JO addr
                    addr = self.fetch_word()
                    if self.get_flag(O_FLAG):
                        self.reg['PC'] = addr
                        
                elif opcode == 0x36: # JNO addr
                    addr = self.fetch_word()
                    if not self.get_flag(O_FLAG):
                        self.reg['PC'] = addr
                        
                elif opcode == 0x37: # CALL addr
                    addr = self.fetch_word()
                    self.push(self.reg['PC'])
                    self.reg['PC'] = addr
                    
                elif opcode == 0x38: # RET
                    self.reg['PC'] = self.pop()
                    
                elif opcode == 0x39: # CMP Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    result = self.reg[rd] - self.reg[rs]
                    
                    # Set flags as if subtraction occurred
                    self.set_flag(Z_FLAG, result == 0)
                    self.set_flag(N_FLAG, (result & 0x8000) != 0)
                    self.set_flag(C_FLAG, result < 0)  # Borrow occurred
                    
                    # Set overflow (same as SUB)
                    a = self.reg[rd]
                    b = self.reg[rs]
                    self.set_flag(O_FLAG, ((a ^ b) & 0x8000) != 0 and ((b ^ result) & 0x8000) == 0)
                    
                elif opcode == 0x3A: # TEST Rd, Rs
                    reg_byte = self.fetch_byte()
                    rd = REGISTERS[(reg_byte >> 4) & 0x0F]
                    rs = REGISTERS[reg_byte & 0x0F]
                    result = self.reg[rd] & self.reg[rs]
                    
                    # Set flags as if AND occurred
                    self.set_flag(Z_FLAG, result == 0)
                    self.set_flag(N_FLAG, (result & 0x8000) != 0)
                    self.set_flag(C_FLAG, False)
                    self.set_flag(O_FLAG, False)
                    
                # ========================================
                # System Instructions (0xF0-0xF3)
                # ========================================
                elif opcode == 0xF0: # HLT
                    self.running = False
                    print("Execution halted")
                    
                elif opcode == 0xF1: # NOP
                    pass
                    
                elif opcode == 0xF2: # OUT port
                    port = self.fetch_byte() & 0x0F  # Only 16 ports (0-15)
                    char = self.reg['A'] & 0xFF
                    if port == 0:  # Console output
                        print(chr(char), end='', flush=True)
                    self.io_ports[port] = char
                    
                elif opcode == 0xF3: # IN port
                    port = self.fetch_byte() & 0x0F
                    # For now, just return port value
                    self.reg['A'] = self.io_ports[port]
                    
                # ========================================
                # Invalid Instruction Handling
                # ========================================
                else:
                    print(f"Unknown opcode: {hex(opcode)} at PC={hex(self.reg['PC'])}")
                    self.running = False
                    
            except KeyError as e:
                print(f"Invalid register encoding: {e}")
                self.running = False
            except IndexError as e:
                print(f"Memory access error: {e}")
                self.running = False

    def run(self, program_file, debug=False):
        """Start the virtual machine"""
        self.debug = debug
        self.load_program(program_file)
        print("Starting execution...")
        self.execute()
        print(f"\nExecution completed. Cycles: {self.cycles}")

    def add_breakpoint(self, address):
        """Add a breakpoint at specified address"""
        self.breakpoints.add(address)

def main():
    # =================================================================
    # CONFIGURATION - MODIFY THESE VALUES TO RUN DIFFERENT TESTS
    # =================================================================
    # Use pathlib for cross-platform path handling
    BASE_DIR = Path(__file__).parent.resolve()
    PROGRAMS_DIR = BASE_DIR / ".." / "programs"
    
    # Select which test to run
    TEST_FILE = "mov_test.hex"     # Data movement test

    
    DEBUG_MODE = True             # True = show execution details
    BREAKPOINTS = [0x000A]        # List of breakpoint addresses (hex)
    # =================================================================
    
    # Construct full path to program
    program_path = PROGRAMS_DIR / TEST_FILE
    
    # Normalize the path (resolve .. and .)
    program_path = program_path.resolve()
    
    vm = VirtualMachine()
    
    # Add breakpoints
    for addr in BREAKPOINTS:
        vm.add_breakpoint(addr)
        print(f"Added breakpoint at {hex(addr)}")
    
    # Run the program
    vm.run(program_path, debug=DEBUG_MODE)

if __name__ == "__main__":
    main()

