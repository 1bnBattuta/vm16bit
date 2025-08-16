import sys
import re
from collections import defaultdict

# ================================================================
# CONSTANTS AND SETUP
# ================================================================
REGISTERS = {'A', 'B', 'C', 'D', 'SP', 'PC', 'FP', 'FLAGS'}
OPCODES = {
    # Data Movement
    'MOV': {
        ('reg', 'reg'): 0x01,
        ('reg', 'imm'): 0x04,
        ('reg', 'mem_reg'): 0x05,  # LD
        ('mem_reg', 'reg'): 0x06,  # ST
    },
    'PUSH': {('reg',): 0x07},
    'POP': {('reg',): 0x08},
    'LEA': {
        ('reg', 'abs'): 0x09,      # Mode 0
        ('reg', 'label'): 0x09,    # Mode 1 (PC-relative)
        ('reg', 'base_offset'): 0x09,  # Mode 2
    },
    
    # Arithmetic
    'ADD': {
        ('reg', 'reg'): 0x10,
        ('reg', 'imm'): 0x11,
    },
    'SUB': {
        ('reg', 'reg'): 0x12,
        ('reg', 'imm'): 0x13,
    },
    'MUL': {('reg', 'reg'): 0x14},
    'DIV': {('reg', 'reg'): 0x15},
    'INC': {('reg',): 0x16},
    'DEC': {('reg',): 0x17},
    'NEG': {('reg',): 0x18},
    
    # Logical
    'AND': {('reg', 'reg'): 0x20},
    'OR': {('reg', 'reg'): 0x21},
    'XOR': {('reg', 'reg'): 0x22},
    'NOT': {('reg',): 0x23},
    'SHL': {('reg', 'imm'): 0x24},
    'SHR': {('reg', 'imm'): 0x25},
    'SAR': {('reg', 'imm'): 0x26},
    
    # Control Flow
    'JMP': {('label',): 0x30},
    'JZ': {('label',): 0x31},
    'JNZ': {('label',): 0x32},
    'JC': {('label',): 0x33},
    'JNC': {('label',): 0x34},
    'JO': {('label',): 0x35},
    'JNO': {('label',): 0x36},
    'CALL': {('label',): 0x37},
    'RET': {(): 0x38},
    'CMP': {
        ('reg', 'reg'): 0x39,
        ('reg', 'imm'): 0x39,  # Will be handled as reg, reg with temp reg
    },
    'TEST': {('reg', 'reg'): 0x3A},
    'HLT': {(): 0xF0},
    'NOP': {(): 0xF1},
    
    # I/O
    'OUT': {('imm',): 0xF2},
    'IN': {('imm',): 0xF3},
}

# Addressing mode encodings for LEA
LEA_MODES = {
    'abs': 0x0,
    'label': 0x1,
    'base_offset': 0x2,
}

# ================================================================
# ASSEMBLER IMPLEMENTATION
# ================================================================
class Assembler:
    def __init__(self):
        self.symbol_table = {}
        self.definitions = {}
        self.current_address = 0
        self.output = bytearray()
        self.pass_num = 0
        self.listing = []
        self.warnings = []
        self.errors = []
        self.temp_reg = 'D'  # Used for immediate comparisons

    def assemble(self, source, output_file=None):
        """Assemble source code into binary format"""
        self.source_lines = source.splitlines()
        self._reset_assembler()
        
        # First pass: build symbol table and resolve constants
        self.pass_num = 1
        self._first_pass()
        
        if self.errors:
            return False, self.errors, self.warnings
        
        # Second pass: generate machine code
        self.pass_num = 2
        self._reset_assembler()
        self._second_pass()
        
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(self.output)
        
        return True, self.errors, self.warnings, self.output

    def _reset_assembler(self):
        """Reset assembler state between passes"""
        self.current_address = 0
        self.output = bytearray()
        if self.pass_num == 1:
            self.symbol_table = {}
            self.definitions = {}

    def _first_pass(self):
        """First pass: build symbol table and resolve constants"""
        line_num = 0
        for line in self.source_lines:
            line_num += 1
            # Remove comments
            clean_line = re.sub(r';.*$', '', line).strip()
            clean_line = re.sub(r'/\*.*?\*/', '', clean_line).strip()
            if not clean_line:
                continue
            
            # Process directives
            if clean_line.startswith('.'):
                self._process_directive(clean_line, line_num)
                continue
                
            # Process label definition
            if ':' in clean_line:
                label, _, rest = clean_line.partition(':')
                label = label.strip()
                if not self._is_valid_identifier(label):
                    self.errors.append(f"Line {line_num}: Invalid label name '{label}'")
                    continue
                    
                if label in self.symbol_table:
                    self.errors.append(f"Line {line_num}: Duplicate label '{label}'")
                    continue
                    
                self.symbol_table[label] = self.current_address
                clean_line = rest.strip()
                if not clean_line:
                    continue
            
            # Process instruction (just to advance address)
            parts = clean_line.split(maxsplit=1)
            if not parts:
                continue
                
            mnemonic = parts[0].upper()
            operands = parts[1].split(',') if len(parts) > 1 else []
            operands = [op.strip() for op in operands]
            
            # Calculate instruction size
            try:
                size = self._get_instruction_size(mnemonic, operands)
                self.current_address += size
            except ValueError as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

    def _second_pass(self):
        """Second pass: generate machine code"""
        line_num = 0
        for line in self.source_lines:
            line_num += 1
            # Preserve original line for listing
            orig_line = line.rstrip()
            
            # Remove comments
            clean_line = re.sub(r';.*$', '', line).strip()
            clean_line = re.sub(r'/\*.*?\*/', '', clean_line).strip()
            if not clean_line:
                self.listing.append((line_num, orig_line, []))
                continue
            
            # Process directives
            if clean_line.startswith('.'):
                self._process_directive(clean_line, line_num, orig_line)
                continue
                
            # Process label definition
            label_part = ""
            if ':' in clean_line:
                label, _, rest = clean_line.partition(':')
                label = label.strip()
                clean_line = rest.strip()
                label_part = label + ":"
                
                if not clean_line:
                    self.listing.append((line_num, orig_line, []))
                    continue
            
            # Process instruction
            parts = clean_line.split(maxsplit=1)
            if not parts:
                self.listing.append((line_num, orig_line, []))
                continue
                
            mnemonic = parts[0].upper()
            operands = parts[1].split(',') if len(parts) > 1 else []
            operands = [op.strip() for op in operands]
            
            start_address = self.current_address
            try:
                self._encode_instruction(mnemonic, operands, line_num)
            except (ValueError, KeyError) as e:
                self.errors.append(f"Line {line_num}: {str(e)}")
            
            # Capture generated bytes for listing
            generated_bytes = self.output[start_address:self.current_address]
            self.listing.append((line_num, orig_line, list(generated_bytes)))

    def _process_directive(self, line, line_num, orig_line=None):
        """Process assembler directives"""
        parts = line.split()
        directive = parts[0].upper()
        
        # .ORG address
        if directive == '.ORG':
            if len(parts) < 2:
                self.errors.append(f"Line {line_num}: .ORG requires an address")
                return
                
            try:
                address = self._parse_value(parts[1])
                self.current_address = address
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid address for .ORG")
        
        # .DB byte1, byte2, ...
        elif directive == '.DB':
            if len(parts) < 2:
                self.errors.append(f"Line {line_num}: .DB requires at least one value")
                return
                
            for val_str in parts[1:]:
                try:
                    # Handle strings
                    if val_str.startswith("'") and val_str.endswith("'"):
                        if len(val_str) == 3:  # Single character
                            value = ord(val_str[1])
                        else:
                            self.errors.append(f"Line {line_num}: Invalid character literal")
                            continue
                    elif val_str.startswith('"') and val_str.endswith('"'):
                        # String value
                        s = val_str[1:-1]
                        if self.pass_num == 2:
                            for char in s:
                                self.output.append(ord(char))
                                self.current_address += 1
                        else:
                            self.current_address += len(s)
                        continue
                    else:
                        value = self._parse_value(val_str)
                        
                    if self.pass_num == 2:
                        self.output.append(value & 0xFF)
                    self.current_address += 1
                except ValueError:
                    self.errors.append(f"Line {line_num}: Invalid value for .DB")
        
        # .DW word1, word2, ...
        elif directive == '.DW':
            if len(parts) < 2:
                self.errors.append(f"Line {line_num}: .DW requires at least one value")
                return
                
            for val_str in parts[1:]:
                try:
                    value = self._parse_value(val_str)
                    if self.pass_num == 2:
                        # Little-endian
                        self.output.append(value & 0xFF)
                        self.output.append((value >> 8) & 0xFF)
                    self.current_address += 2
                except ValueError:
                    self.errors.append(f"Line {line_num}: Invalid value for .DW")
        
        # .DS count
        elif directive == '.DS':
            if len(parts) < 2:
                self.errors.append(f"Line {line_num}: .DS requires a size")
                return
                
            try:
                size = self._parse_value(parts[1])
                if self.pass_num == 2:
                    self.output.extend(b'\x00' * size)
                self.current_address += size
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid size for .DS")
        
        # .EQU NAME = value
        elif directive == '.EQU':
            if len(parts) < 4 or parts[2] != '=':
                self.errors.append(f"Line {line_num}: Invalid .EQU syntax")
                return
                
            name = parts[1]
            if not self._is_valid_identifier(name):
                self.errors.append(f"Line {line_num}: Invalid constant name '{name}'")
                return
                
            try:
                value = self._parse_value(parts[3])
                if name in self.definitions:
                    self.errors.append(f"Line {line_num}: Duplicate constant '{name}'")
                else:
                    self.definitions[name] = value
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid value for .EQU")
        
        # Add to listing if in second pass
        if self.pass_num == 2 and orig_line:
            self.listing.append((line_num, orig_line, []))

    def _parse_value(self, value_str):
        """Parse numeric value with support for different bases and symbols"""
        # Handle character literals
        if value_str.startswith("'") and value_str.endswith("'") and len(value_str) == 3:
            return ord(value_str[1])
            
        # Handle defined constants
        if value_str in self.definitions:
            return self.definitions[value_str]
            
        # Handle labels (in second pass)
        if self.pass_num == 2 and value_str in self.symbol_table:
            return self.symbol_table[value_str]
            
        # Handle hexadecimal
        if value_str.startswith('0x'):
            return int(value_str[2:], 16)
            
        # Handle binary
        if value_str.startswith('0b'):
            return int(value_str[2:], 2)
            
        # Handle decimal
        if value_str.isdigit() or (value_str[0] == '-' and value_str[1:].isdigit()):
            return int(value_str)
            
        # Handle symbolic expressions
        if '+' in value_str:
            parts = value_str.split('+')
            return sum(self._parse_value(p.strip()) for p in parts)
            
        if '-' in value_str:
            parts = value_str.split('-')
            result = self._parse_value(parts[0].strip())
            for p in parts[1:]:
                result -= self._parse_value(p.strip())
            return result
            
        # Handle PC-relative expressions
        if value_str.startswith('$'):
            # PC-relative calculation will be done during encoding
            return value_str
            
        raise ValueError(f"Invalid value: '{value_str}'")

    def _get_operand_type(self, operand):
        """Determine operand type and its value"""
        # Register operand
        if operand in REGISTERS:
            return 'reg', operand
            
        # Immediate value
        if operand.startswith('#'):
            value = operand[1:]
            return 'imm', value
            
        # Label (for jumps and addresses)
        if operand in self.symbol_table or operand in self.definitions:
            return 'label', operand
            
        # Memory operand: [expression]
        if operand.startswith('[') and operand.endswith(']'):
            expr = operand[1:-1].strip()
            
            # Register indirect
            if expr in REGISTERS:
                return 'mem_reg', expr
                
            # Base + offset
            if '+' in expr:
                base, offset = expr.split('+', 1)
                base = base.strip()
                offset = offset.strip()
                if base in REGISTERS:
                    return 'base_offset', (base, offset)
                
            # Absolute address or label
            return 'abs', expr
            
        # PC-relative expression
        if operand.startswith('$'):
            return 'label', operand[1:]
            
        # Numeric value
        try:
            value = self._parse_value(operand)
            return 'imm', value
        except ValueError:
            pass
            
        return 'unknown', operand

    def _get_instruction_size(self, mnemonic, operands):
        """Determine instruction size for address calculation"""
        # Handle directives separately
        if mnemonic.startswith('.'):
            return 0
            
        # Get operand types
        op_types = []
        op_values = []
        for op in operands:
            op_type, op_value = self._get_operand_type(op)
            op_types.append(op_type)
            op_values.append(op_value)
            
        # Special handling for MOV
        if mnemonic == 'MOV':
            if op_types[0] == 'reg' and op_types[1] == 'mem_reg':
                return 2  # LD
            elif op_types[0] == 'mem_reg' and op_types[1] == 'reg':
                return 2  # ST
            elif op_types[1] == 'imm':
                return 4
            else:
                return 2
                
        # Handle LEA addressing modes
        if mnemonic == 'LEA':
            if op_types[1] == 'abs':
                return 4
            elif op_types[1] == 'label':
                return 4
            elif op_types[1] == 'base_offset':
                return 5
                
        # Handle jumps and calls
        if mnemonic in ['JMP', 'JZ', 'JNZ', 'JC', 'JNC', 'JO', 'JNO', 'CALL']:
            return 3
            
        # Handle I/O instructions
        if mnemonic in ['OUT', 'IN']:
            return 2
            
        # Handle immediate arithmetic
        if mnemonic in ['ADD', 'SUB'] and op_types[1] == 'imm':
            return 4
            
        # Handle shifts
        if mnemonic in ['SHL', 'SHR', 'SAR']:
            return 3
            
        # Handle CMP immediate (needs temporary register)
        if mnemonic == 'CMP' and op_types[1] == 'imm':
            return 6  # MOV + CMP + MOV (to restore temp reg)
            
        # Default sizes
        if len(operands) == 0:
            return 1
        elif len(operands) == 1:
            return 2
        else:
            return 2

    def _encode_instruction(self, mnemonic, operands, line_num):
        """Encode instruction to binary output"""
        # Get operand types and values
        op_types = []
        op_values = []
        for op in operands:
            op_type, op_value = self._get_operand_type(op)
            op_types.append(op_type)
            op_values.append(op_value)
            
        # Special handling for MOV with memory operands
        if mnemonic == 'MOV':
            if op_types[0] == 'reg' and op_types[1] == 'mem_reg':
                self._encode_ld(op_values[0], op_values[1])
                return
            elif op_types[0] == 'mem_reg' and op_types[1] == 'reg':
                self._encode_st(op_values[0], op_values[1])
                return
                
        # Handle CMP immediate using temp register
        if mnemonic == 'CMP' and op_types[1] == 'imm':
            # Save temp register
            self._encode_push([self.temp_reg])
            # Load immediate to temp register
            self._encode_mov(self.temp_reg, f"#{op_values[1]}")
            # Compare
            self._encode_cmp(op_values[0], self.temp_reg)
            # Restore temp register
            self._encode_pop([self.temp_reg])
            return
            
        # Get opcode
        try:
            opcode_info = OPCODES[mnemonic][tuple(op_types)]
            self.output.append(opcode_info)
            self.current_address += 1
        except KeyError:
            raise ValueError(f"Invalid operand combination for {mnemonic}")
            
        # Encode operands based on instruction type
        if mnemonic == 'MOV':
            self._encode_mov_operands(op_values[0], op_values[1])
        elif mnemonic == 'LEA':
            self._encode_lea_operands(op_values[0], op_types[1], op_values[1])
        elif mnemonic in ['ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP', 'TEST']:
            self._encode_reg_reg(op_values[0], op_values[1])
        elif mnemonic in ['SHL', 'SHR', 'SAR']:
            self._encode_shift(op_values[0], op_values[1])
        elif mnemonic in ['PUSH', 'POP', 'INC', 'DEC', 'NEG', 'NOT']:
            self._encode_single_reg(op_values[0])
        elif mnemonic in ['JMP', 'JZ', 'JNZ', 'JC', 'JNC', 'JO', 'JNO', 'CALL']:
            self._encode_jump(op_values[0])
        elif mnemonic in ['OUT', 'IN']:
            self._encode_io(op_values[0])
        elif mnemonic in ['RET', 'HLT', 'NOP']:
            pass  # No operands

    def _encode_mov_operands(self, rd, rs):
        """Encode MOV operands"""
        # Register to register
        self.output.append((self._reg_index(rd) << 4) | self._reg_index(rs))
        self.current_address += 1
        
        # Immediate value
        if isinstance(rs, str) and rs.startswith('#'):
            value = self._parse_value(rs[1:])
            self.output.append(value & 0xFF)
            self.output.append((value >> 8) & 0xFF)
            self.current_address += 2

    def _encode_ld(self, rd, rs):
        """Encode LD (load from memory)"""
        self.output.append(0x05)  # LD opcode
        self.output.append((self._reg_index(rd) << 4) | self._reg_index(rs))
        self.current_address += 2

    def _encode_st(self, rd, rs):
        """Encode ST (store to memory)"""
        self.output.append(0x06)  # ST opcode
        self.output.append((self._reg_index(rd) << 4) | self._reg_index(rs))
        self.current_address += 2

    def _encode_lea_operands(self, rd, mode, value):
        """Encode LEA operands"""
        # Mode encoding: rd in high nibble, mode in low nibble
        mode_byte = (self._reg_index(rd) << 4) | LEA_MODES[mode]
        self.output.append(mode_byte)
        self.current_address += 1
        
        if mode == 'abs':
            # Absolute address
            addr = self._parse_value(value)
            self.output.append(addr & 0xFF)
            self.output.append((addr >> 8) & 0xFF)
            self.current_address += 2
        elif mode == 'label':
            # PC-relative address
            label_addr = self._parse_value(value)
            offset = label_addr - (self.current_address + 2)
            if offset < 0:
                offset = (1 << 16) + offset  # Two's complement
            self.output.append(offset & 0xFF)
            self.output.append((offset >> 8) & 0xFF)
            self.current_address += 2
        elif mode == 'base_offset':
            # Base + offset
            base_reg, offset = value
            self.output.append(self._reg_index(base_reg))
            self.current_address += 1
            offset_val = self._parse_value(offset)
            self.output.append(offset_val & 0xFF)
            self.output.append((offset_val >> 8) & 0xFF)
            self.current_address += 2

    def _encode_reg_reg(self, rd, rs):
        """Encode two register operands"""
        self.output.append((self._reg_index(rd) << 4) | self._reg_index(rs))
        self.current_address += 1

    def _encode_shift(self, rd, count):
        """Encode shift instruction"""
        self.output.append((self._reg_index(rd) << 4))
        self.current_address += 1
        count_val = self._parse_value(count)
        self.output.append(count_val & 0x0F)  # Only 4 bits
        self.current_address += 1

    def _encode_single_reg(self, reg):
        """Encode single register operand"""
        self.output.append((self._reg_index(reg) << 4))
        self.current_address += 1

    def _encode_jump(self, target):
        """Encode jump instruction"""
        target_addr = self._parse_value(target)
        self.output.append(target_addr & 0xFF)
        self.output.append((target_addr >> 8) & 0xFF)
        self.current_address += 2

    def _encode_io(self, port):
        """Encode I/O instruction"""
        port_val = self._parse_value(port)
        self.output.append(port_val & 0x0F)  # Only 4 bits
        self.current_address += 1

    def _encode_push(self, registers):
        for reg in registers:
            self.output.append(0x07)  # PUSH opcode
            self.output.append(self._reg_index(reg))
            self.current_address += 2

    def _encode_pop(self, registers):
        for reg in registers:
            self.output.append(0x08)  # POP opcode
            self.output.append(self._reg_index(reg) << 4)
            self.current_address += 2

    def _reg_index(self, reg_name):
        """Get numeric index for register"""
        reg_map = {
            'A': 0, 'B': 1, 'C': 2, 'D': 3,
            'SP': 4, 'PC': 5, 'FP': 6, 'FLAGS': 7
        }
        return reg_map[reg_name.upper()]

    def _is_valid_identifier(self, name):
        """Check if a label or constant name is valid"""
        return re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name) is not None


# ================================================================
# COMMAND-LINE INTERFACE
# ================================================================
def main():
    if len(sys.argv) < 2:
        print("Usage: python assembler.py <input.asm> [output.bin]")
        return

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.asm', '.bin')

    # Read source file
    with open(input_file, 'r') as f:
        source = f.read()

    # Assemble
    assembler = Assembler()
    success, errors, warnings, binary = assembler.assemble(source, output_file)

    # Print results
    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  {warning}")
            
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  {error}")
        print("\nAssembly failed")
        sys.exit(1)
        
    print(f"\nAssembly successful. Output: {output_file}")
    print(f"Binary size: {len(binary)} bytes")
    
    # Print listing
    print("\nAssembly Listing:")
    print("Line  Address  Bytes   Source")
    for line_num, source_line, bytes_list in assembler.listing:
        addr = assembler.symbol_table.get(source_line.split(':')[0].strip(), '')
        bytes_str = ' '.join(f'{b:02X}' for b in bytes_list) if bytes_list else ''
        print(f"{line_num:<5} {addr:04X}     {bytes_str:<12} {source_line}")

if __name__ == '__main__':
    main()
