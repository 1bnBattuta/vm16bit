from pathlib import Path
import sys

# =================================================================
# CONSTANTS
# =================================================================
MEMORY_SIZE = 65536      # 64KB total memory
ROM_START = 0x0000       # ROM area start address
ROM_END = 0x7FFF         # ROM area end address (32KB)
RAM_START = 0x8000       # RAM area start address
RAM_END = 0xFEFF         # RAM area end address
IO_START = 0xFF00        # I/O area start address
IO_END = 0xFF0F          # I/O area end address (16 ports)

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

# =================================================================
# VIRTUAL MACHINE
# =================================================================
class VirtualMachine:
    def __init__(self):
        # Initialize 64KB memory
        self.memory = [0] * MEMORY_SIZE
        
        # Initialize registers
        self.reg = {
            'A': 0, 'B': 0, 'C': 0, 'D': 0,
            'SP': RAM_END,    # Stack Pointer starts at top of RAM
            'PC': ROM_START,  # Program Counter starts at beginning of ROM
            'FP': 0,          # Frame Pointer
            'FLAGS': 0        # Status Flags
        }
        
        # Execution state
        self.running = False
        self.cycles = 0
        self.debug = False
        self.breakpoints = set()
        self.io_ports = [0] * 16  # 16 I/O ports
        
        # Instruction dispatch table
        self.instruction_set = {
            0x01: self.mov_reg,      0x02: self.mov_mem_rd,
            0x03: self.mov_mem_wr,   0x04: self.mov_imm,
            0x05: self.ld,           0x06: self.st,
            0x07: self.inst_push,    0x08: self.inst_pop,
            0x09: self.lea,          0x10: self.add_reg,
            0x11: self.add_imm,      0x12: self.sub_reg,
            0x13: self.sub_imm,      0x14: self.mul,
            0x15: self.div,          0x16: self.inc,
            0x17: self.dec,          0x18: self.neg,
            0x20: self.and_reg,      0x21: self.or_reg,
            0x22: self.xor_reg,      0x23: self.not_reg,
            0x24: self.shl,          0x25: self.shr,
            0x26: self.sar,          0x30: self.jmp,
            0x31: self.jz,           0x32: self.jnz,
            0x33: self.jc,           0x34: self.jnc,
            0x35: self.jo,           0x36: self.jno,
            0x37: self.call,         0x38: self.ret,
            0x39: self.cmp,          0x3A: self.test,
            0xF0: self.hlt,          0xF1: self.nop,
            0xF2: self.out,          0xF3: self.inp
        }
        
        # Instruction cycle counts
        self.cycle_counts = {
            0x01: 1, 0x02: 2, 0x03: 2, 0x04: 2,
            0x05: 3, 0x06: 3, 0x07: 2, 0x08: 2,
            0x09: 2, 0x10: 2, 0x11: 2, 0x12: 2,
            0x13: 2, 0x14: 4, 0x15: 8, 0x16: 1,
            0x17: 1, 0x18: 1, 0x20: 1, 0x21: 1,
            0x22: 1, 0x23: 1, 0x24: 1, 0x25: 1,
            0x26: 1, 0x30: 2, 0x31: 2, 0x32: 2,
            0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2,
            0x37: 4, 0x38: 4, 0x39: 1, 0x3A: 1,
            0xF0: 1, 0xF1: 1, 0xF2: 2, 0xF3: 2
        }

    def reset(self):
        """Reset VM to initial state"""
        self.memory = [0] * MEMORY_SIZE
        self.reg = {
            'A': 0, 'B': 0, 'C': 0, 'D': 0,
            'SP': RAM_END,
            'PC': ROM_START,
            'FP': 0,
            'FLAGS': 0
        }
        self.cycles = 0
        self.running = False
        self.io_ports = [0] * 16
        print("VM reset")

    def load_program(self, filename, address=ROM_START):
        """Load raw binary program into ROM area"""
        try:
            # Validate ROM boundaries
            if address < ROM_START or address > ROM_END:
                raise ValueError(f"Invalid ROM address: {hex(address)}")
            
            with open(filename, 'rb') as f:
                binary_data = f.read()
            
            # Check if program fits in ROM
            if address + len(binary_data) > ROM_END + 1:
                raise MemoryError(f"Program too large for ROM (max {ROM_END - address + 1} bytes)")
            
            # Load into memory
            for i, byte in enumerate(binary_data):
                self.memory[address + i] = byte
                
            print(f"Loaded {len(binary_data)} bytes into ROM [{hex(address)}-{hex(address + len(binary_data) - 1)}]")
            return True
            
        except FileNotFoundError:
            print(f"Error: File {filename} not found")
            return False
        except Exception as e:
            print(f"Load error: {e}")
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

    def fetch_word_signed(self):
        """Fetch 16-bit signed word (two's complement)"""
        value = self.fetch_word()
        return value if value < 0x8000 else value - 0x10000

    def read_mem(self, address):
        """Read byte from memory"""
        return self.memory[address]

    def write_mem(self, address, value):
        """Write byte to memory with protection"""
        # I/O ports
        if IO_START <= address <= IO_END:
            self.handle_io_write(address - IO_START, value)
        # RAM area
        elif RAM_START <= address <= RAM_END:
            self.memory[address] = value & 0xFF
        # ROM area - write attempt
        elif ROM_START <= address <= ROM_END and self.debug:
            print(f"Write to ROM ignored at {hex(address)}")

    def read_mem_word(self, address):
        """Read 16-bit word from memory (little-endian)"""
        low = self.read_mem(address)
        high = self.read_mem(address + 1)
        return (high << 8) | low

    def write_mem_word(self, address, value):
        """Write 16-bit word to memory (little-endian)"""
        self.write_mem(address, value & 0xFF)
        self.write_mem(address + 1, (value >> 8) & 0xFF)

    def stack_push(self, value):
        """Push 16-bit value onto stack with boundary check"""
        sp = self.reg['SP']
        
        # Stack overflow protection
        if sp - 2 < RAM_START:
            raise MemoryError(f"Stack overflow at {hex(sp)}")
        
        self.write_mem_word(sp, value)
        self.reg['SP'] = sp - 2

    def stack_pop(self):
        """Pop 16-bit value from stack with boundary check"""
        sp = self.reg['SP'] + 2
        
        # Stack underflow protection
        if sp > RAM_END:
            raise MemoryError(f"Stack underflow at {hex(sp)}")
        
        value = self.read_mem_word(sp)
        self.reg['SP'] = sp
        return value

    def handle_io_write(self, port, value):
        """Handle I/O port writes"""
        port = port & 0x0F  # Ensure valid port range
        self.io_ports[port] = value
        
        # Special handling for console output (port 0)
        if port == 0:
            char = value & 0xFF
            if char == 10:  # Newline
                print()
            elif 32 <= char <= 126:  # Printable ASCII
                print(chr(char), end='', flush=True)
            elif char == 8:  # Backspace
                print('\b \b', end='', flush=True)

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
        self.set_flag(Z_FLAG, (result & 0xFFFF) == 0)
        
        # Set Negative flag (sign bit)
        mask = 0x8000 if width == 16 else 0x80
        self.set_flag(N_FLAG, (result & mask) != 0)
        
        # Set Carry flag for unsigned overflow
        max_val = 0xFFFF if width == 16 else 0xFF
        self.set_flag(C_FLAG, result > max_val or result < 0)
        
        # Overflow flag must be set by individual operations

    def update_flags_logic(self, result, width=16):
        """Update flags for logical operations"""
        # Set Zero flag
        self.set_flag(Z_FLAG, (result & 0xFFFF) == 0)
        
        # Set Negative flag (sign bit)
        mask = 0x8000 if width == 16 else 0x80
        self.set_flag(N_FLAG, (result & mask) != 0)
        
        # Clear Carry and Overflow for logical operations
        self.set_flag(C_FLAG, False)
        self.set_flag(O_FLAG, False)

    # =================================================================
    # INSTRUCTION IMPLEMENTATIONS
    # =================================================================
    def mov_reg(self):
        """MOV Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        self.reg[rd] = self.reg[rs]

    def mov_mem_rd(self):
        """MOV Rd, [A]"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = self.read_mem_word(self.reg['A'])

    def mov_mem_wr(self):
        """MOV [A], Rs"""
        reg_byte = self.fetch_byte()
        rs = REGISTERS[reg_byte & 0x0F]
        self.write_mem_word(self.reg['A'], self.reg[rs])

    def mov_imm(self):
        """MOV Rd, #imm"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        imm = self.fetch_word()
        self.reg[rd] = imm

    def ld(self):
        """LD Rd, [Rs]"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        addr = self.reg[rs]
        self.reg[rd] = self.read_mem_word(addr)

    def st(self):
        """ST [Rd], Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        self.write_mem_word(self.reg[rd], self.reg[rs])

    def inst_push(self):
        """PUSH Rs"""
        reg_byte = self.fetch_byte()
        rs = REGISTERS[reg_byte & 0x0F]
        self.stack_push(self.reg[rs])

    def inst_pop(self):
        """POP Rd"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = self.stack_pop()

    def lea(self):
        """LEA Rd, addr"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        mode = reg_byte & 0x0F
        
        if mode == 0:  # Absolute address
            self.reg[rd] = self.fetch_word()
        elif mode == 1:  # PC-relative
            offset = self.fetch_word_signed()
            self.reg[rd] = (self.reg['PC'] + offset) & 0xFFFF
        elif mode == 2:  # Register indirect with offset
            base_reg = self.fetch_byte() & 0x07
            base = self.reg[REGISTERS[base_reg]]
            offset = self.fetch_word_signed()
            self.reg[rd] = (base + offset) & 0xFFFF
        else:
            raise ValueError(f"Invalid LEA mode: {mode}")

    def add_reg(self):
        """ADD Rd, Rs"""
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

    def add_imm(self):
        """ADD Rd, #imm"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        imm = self.fetch_word_signed()
        a = self.reg[rd]
        result = a + imm
        
        # Set overflow
        self.set_flag(O_FLAG, ((a ^ imm) & 0x8000) == 0 and ((a ^ result) & 0x8000) != 0)
        
        self.reg[rd] = result & 0xFFFF
        self.update_flags_arith(self.reg[rd])

    def sub_reg(self):
        """SUB Rd, Rs"""
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

    def sub_imm(self):
        """SUB Rd, #imm"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        imm = self.fetch_word_signed()
        a = self.reg[rd]
        result = a - imm
        
        # Set overflow
        self.set_flag(O_FLAG, ((a ^ imm) & 0x8000) != 0 and ((imm ^ result) & 0x8000) == 0)
        
        self.reg[rd] = result & 0xFFFF
        self.update_flags_arith(self.reg[rd])

    def mul(self):
        """MUL Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        a = self.reg[rd]
        b = self.reg[rs]
        result = a * b
        
        # For 16-bit multiplication, keep lower 16 bits
        self.reg[rd] = result & 0xFFFF
        
        # Set carry if result exceeds 16 bits
        self.set_flag(C_FLAG, result > 0xFFFF)
        self.update_flags_logic(self.reg[rd])

    def div(self):
        """DIV Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        dividend = self.reg[rd]
        divisor = self.reg[rs]
        
        if divisor == 0:
            self.set_flag(Z_FLAG, True)
            self.reg[rd] = 0xFFFF  # Division by zero error value
            # Clear other flags
            self.set_flag(C_FLAG, False)
            self.set_flag(O_FLAG, False)
            self.set_flag(N_FLAG, False)
        else:
            self.set_flag(Z_FLAG, False)
            self.reg[rd] = dividend // divisor
            self.update_flags_logic(self.reg[rd])

    def inc(self):
        """INC Rd"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = (self.reg[rd] + 1) & 0xFFFF
        self.update_flags_arith(self.reg[rd])

    def dec(self):
        """DEC Rd"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = (self.reg[rd] - 1) & 0xFFFF
        self.update_flags_arith(self.reg[rd])

    def neg(self):
        """NEG Rd"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = (~self.reg[rd] + 1) & 0xFFFF
        self.update_flags_arith(self.reg[rd])

    def and_reg(self):
        """AND Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        self.reg[rd] &= self.reg[rs]
        self.update_flags_logic(self.reg[rd])

    def or_reg(self):
        """OR Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        self.reg[rd] |= self.reg[rs]
        self.update_flags_logic(self.reg[rd])

    def xor_reg(self):
        """XOR Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        self.reg[rd] ^= self.reg[rs]
        self.update_flags_logic(self.reg[rd])

    def not_reg(self):
        """NOT Rd"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        self.reg[rd] = (~self.reg[rd]) & 0xFFFF
        self.update_flags_logic(self.reg[rd])

    def shl(self):
        """SHL Rd, #imm"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        shift = self.fetch_byte() & 0x0F  # Only lower 4 bits
        
        if shift > 0:
            # Save the last bit shifted out for carry
            last_bit = (self.reg[rd] >> (16 - shift)) & 1
            self.set_flag(C_FLAG, last_bit == 1)
            
            self.reg[rd] = (self.reg[rd] << shift) & 0xFFFF
            self.update_flags_logic(self.reg[rd])

    def shr(self):
        """SHR Rd, #imm"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        shift = self.fetch_byte() & 0x0F
        
        if shift > 0:
            # Save the last bit shifted out for carry
            last_bit = (self.reg[rd] >> (shift - 1)) & 1
            self.set_flag(C_FLAG, last_bit == 1)
            
            self.reg[rd] = self.reg[rd] >> shift
            self.update_flags_logic(self.reg[rd])

    def sar(self):
        """SAR Rd, #imm"""
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

    def jmp(self):
        """JMP addr"""
        addr = self.fetch_word()
        self.reg['PC'] = addr

    def jz(self):
        """JZ addr"""
        addr = self.fetch_word()
        if self.get_flag(Z_FLAG):
            self.reg['PC'] = addr

    def jnz(self):
        """JNZ addr"""
        addr = self.fetch_word()
        if not self.get_flag(Z_FLAG):
            self.reg['PC'] = addr

    def jc(self):
        """JC addr"""
        addr = self.fetch_word()
        if self.get_flag(C_FLAG):
            self.reg['PC'] = addr

    def jnc(self):
        """JNC addr"""
        addr = self.fetch_word()
        if not self.get_flag(C_FLAG):
            self.reg['PC'] = addr

    def jo(self):
        """JO addr"""
        addr = self.fetch_word()
        if self.get_flag(O_FLAG):
            self.reg['PC'] = addr

    def jno(self):
        """JNO addr"""
        addr = self.fetch_word()
        if not self.get_flag(O_FLAG):
            self.reg['PC'] = addr

    def call(self):
        """CALL addr"""
        addr = self.fetch_word()
        self.stack_push(self.reg['PC'])
        self.reg['PC'] = addr

    def ret(self):
        """RET"""
        self.reg['PC'] = self.stack_pop()

    def cmp(self):
        """CMP Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        a = self.reg[rd]
        b = self.reg[rs]
        result = a - b
        
        # Set flags
        self.set_flag(Z_FLAG, (result & 0xFFFF) == 0)
        self.set_flag(N_FLAG, (result & 0x8000) != 0)
        self.set_flag(C_FLAG, result < 0)  # Unsigned borrow
        
        # Set overflow (V) for signed overflow
        self.set_flag(O_FLAG, ((a ^ b) & 0x8000) != 0 and ((a ^ result) & 0x8000) != 0)

    def test(self):
        """TEST Rd, Rs"""
        reg_byte = self.fetch_byte()
        rd = REGISTERS[(reg_byte >> 4) & 0x0F]
        rs = REGISTERS[reg_byte & 0x0F]
        result = self.reg[rd] & self.reg[rs]
        
        # Set flags as if AND occurred
        self.set_flag(Z_FLAG, result == 0)
        self.set_flag(N_FLAG, (result & 0x8000) != 0)
        self.set_flag(C_FLAG, False)
        self.set_flag(O_FLAG, False)

    def hlt(self):
        """HLT"""
        self.running = False
        print("Execution halted")

    def nop(self):
        """NOP"""
        pass

    def out(self):
        """OUT port"""
        port = self.fetch_byte() & 0x0F
        self.handle_io_write(port, self.reg['A'] & 0xFF)

    def inp(self):
        """IN port"""
        port = self.fetch_byte() & 0x0F
        self.reg['A'] = self.io_ports[port]

    # =================================================================
    # EXECUTION CONTROL
    # =================================================================
    def execute(self):
        """Main execution loop"""
        self.running = True
        while self.running:
            # Track cycles
            start_pc = self.reg['PC']
            
            # Check breakpoints
            if start_pc in self.breakpoints:
                print(f"Breakpoint hit at {hex(start_pc)}")
                self.debug = True
            
            # Fetch opcode
            opcode = self.fetch_byte()
            
            # Debug output
            if self.debug:
                state = f"PC:{hex(start_pc)} A:{hex(self.reg['A'])} "
                state += f"B:{hex(self.reg['B'])} C:{hex(self.reg['C'])} "
                state += f"D:{hex(self.reg['D'])} SP:{hex(self.reg['SP'])} "
                state += f"FLAGS:{self.reg['FLAGS']:04b} (NZCO)"
                print(f"Executing {hex(opcode)} | {state}")
            
            # Execute instruction
            try:
                if opcode in self.instruction_set:
                    self.instruction_set[opcode]()
                    self.cycles += self.cycle_counts.get(opcode, 1)
                else:
                    raise RuntimeError(f"Unknown opcode: {hex(opcode)}")
                    
            except Exception as e:
                print(f"Runtime error at PC={hex(start_pc)}: {e}")
                self.running = False

    def run(self, program_file=None, start_address=ROM_START, debug=False):
        """Start the virtual machine"""
        self.debug = debug
        self.reg['PC'] = start_address
        
        if program_file:
            if not self.load_program(program_file):
                print("Failed to load program")
                return
        
        print("Starting execution...")
        self.execute()
        print(f"\nExecution completed. Cycles: {self.cycles}")

    def add_breakpoint(self, address):
        """Add a breakpoint at specified address"""
        self.breakpoints.add(address)

# =================================================================
# COMMAND-LINE INTERFACE
# =================================================================
def main():
    """Entry point for command-line execution"""
    parser = argparse.ArgumentParser(description='16-bit Virtual Machine')
    parser.add_argument('program', nargs='?', help='Binary program file to load')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-a', '--address', type=lambda x: int(x, 0), default=ROM_START,
                        help=f'Start address (hex or decimal), default: {hex(ROM_START)}')
    
    args = parser.parse_args()
    
    vm = VirtualMachine()
    
    if args.program:
        success = vm.run(program_file=args.program, 
                         start_address=args.address,
                         debug=args.debug)
        sys.exit(0 if success else 1)
    else:
        print("No program file specified. Running in interactive mode.")
        vm.run(debug=args.debug)


if __name__ == "__main__":
    main()
