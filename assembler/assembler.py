import sys
import re
from collections import defaultdict

# ================================================================
# CONSTANTS AND SETUP
# ================================================================
REGISTERS = {'A', 'B', 'C', 'D', 'SP', 'PC', 'FP', 'FLAGS'}

# Opcode map (aligned with the spec + appendix spirit)
OPCODES = {
    # Data Movement
    'MOV': {
        ('reg', 'reg'): 0x01,        # MOV Rd, Rs
        ('reg', 'imm'): 0x04,        # MOV Rd, #imm16
        ('reg', 'mem_reg'): 0x05,    # LD    Rd, [Rs]
        ('mem_reg', 'reg'): 0x06,    # ST    [Rd], Rs
        ('reg', 'abs'): 0x02,        # LD    Rd, [abs16]
        ('abs', 'reg'): 0x03,        # ST    [abs16], Rs
    },
    'PUSH': {('reg',): 0x07},
    'POP':  {('reg',): 0x08},

    # LEA (single opcode, internal mode byte)
    'LEA': {
        ('reg', 'abs'): 0x09,        # Mode 0
        ('reg', 'label'): 0x09,      # Mode 1 (PC-relative)
        ('reg', 'base_offset'): 0x09 # Mode 2
    },

    # Arithmetic
    'ADD': {('reg', 'reg'): 0x10, ('reg', 'imm'): 0x11},
    'SUB': {('reg', 'reg'): 0x12, ('reg', 'imm'): 0x13},
    'MUL': {('reg', 'reg'): 0x14},
    'DIV': {('reg', 'reg'): 0x15},
    'INC': {('reg',): 0x16},
    'DEC': {('reg',): 0x17},
    'NEG': {('reg',): 0x18},

    # Logical
    'AND': {('reg', 'reg'): 0x20},
    'OR':  {('reg', 'reg'): 0x21},
    'XOR': {('reg', 'reg'): 0x22},
    'NOT': {('reg',): 0x23},
    'SHL': {('reg', 'imm'): 0x24},
    'SHR': {('reg', 'imm'): 0x25},
    'SAR': {('reg', 'imm'): 0x26},

    # Control Flow (PC-relative 16-bit offset encoded by assembler)
    'JMP': {('label',): 0x30},
    'JZ':  {('label',): 0x31},
    'JNZ': {('label',): 0x32},
    'JC':  {('label',): 0x33},
    'JNC': {('label',): 0x34},
    'CALL': {('label',): 0x37},
    'RET': {(): 0x38},
    'CMP': {('reg', 'reg'): 0x39, ('reg', 'imm'): 0x39},
    'TEST': {('reg', 'reg'): 0x3A},
    'HLT': {(): 0xF0},
    'NOP': {(): 0xF1},

    # I/O
    'OUT': {('imm',): 0xF2},
    'IN':  {('imm',): 0xF3},
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
        self.symbol_table = {} # labels -> addresses
        self.definitions = {}  # constants (.EQU)
        self.current_address = 0
        self.output = bytearray()
        self.pass_num = 0
        # listing entries: (line_num, start_address, source_line, [bytes])
        self.listing = []
        self.warnings = []
        self.errors = []

    def assemble(self, source, output_file=None):
        """Assemble source code into binary format"""
        # Strip multi-line block comments globally
        source = re.sub(r'/\*.*?\*/', '', source, flags=re.S)
        self.source_lines = source.splitlines()
        self._reset_assembler()

        # First pass: build symbol table and measure sizes
        self.pass_num = 1
        self._first_pass()
        if self.errors:
            return False, self.errors, self.warnings, b''

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
        self.listing = []
        if self.pass_num == 1:
            self.symbol_table = {}
            self.definitions = {}
            self.warnings = []
            self.errors = []

    # ------------------ First Pass ------------------
    def _first_pass(self):
        line_num = 0
        for raw_line in self.source_lines:
            line_num += 1
            line = self._strip_line_comment(raw_line)
            if not line:
                continue

            # Directives
            if line.startswith('.'):
                self._process_directive(line, line_num)
                continue

            # Label (optional)
            if ':' in line:
                label, _, rest = line.partition(':')
                label = label.strip()
                if not self._is_valid_identifier(label):
                    self.errors.append(f"Line {line_num}: Invalid label name '{label}'")
                    continue
                if label in self.symbol_table:
                    self.errors.append(f"Line {line_num}: Duplicate label '{label}'")
                    continue
                self.symbol_table[label] = self.current_address
                line = rest.strip()
                if not line:
                    continue

            # Instruction sizing
            parts = line.split(maxsplit=1)
            if not parts:
                continue
            mnemonic = parts[0].upper()
            operands = self._split_operands(parts[1]) if len(parts) > 1 else []
            try:
                size = self._get_instruction_size(mnemonic, operands)
                self.current_address += size
            except ValueError as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

    # ------------------ Second Pass ------------------
    def _second_pass(self):
        line_num = 0
        for raw_line in self.source_lines:
            line_num += 1
            orig_line = raw_line.rstrip()

            clean = self._strip_line_comment(raw_line)
            if not clean:
                self.listing.append((line_num, self.current_address, orig_line, []))
                continue

            # Directives
            if clean.startswith('.'):
                start_address = self.current_address
                self._process_directive(clean, line_num, orig_line)
                self.listing.append((line_num, start_address, orig_line, []))
                continue

            # Label
            if ':' in clean:
                _, _, rest = clean.partition(':')
                clean = rest.strip()
                if not clean:
                    self.listing.append((line_num, self.current_address, orig_line, []))
                    continue

            # Instruction encode
            parts = clean.split(maxsplit=1)
            if not parts:
                self.listing.append((line_num, self.current_address, orig_line, []))
                continue

            mnemonic = parts[0].upper()
            operands = self._split_operands(parts[1]) if len(parts) > 1 else []
            start_address = self.current_address
            try:
                self._encode_instruction(mnemonic, operands, line_num)
            except (ValueError, KeyError) as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

            generated = self.output[start_address:self.current_address]
            self.listing.append((line_num, start_address, orig_line, list(generated)))

    # ------------------ Directive Handling ------------------
    def _process_directive(self, line, line_num, orig_line=None):
        parts = line.split(maxsplit=1)
        directive = parts[0].upper()
        argstr = parts[1] if len(parts) > 1 else ""

        if directive == '.ORG':
            if not argstr:
                self.errors.append(f"Line {line_num}: .ORG requires an address")
                return
            try:
                address = self._parse_value(argstr.strip())
                if address < 0 or address > 0xFFFF:
                    raise ValueError
                self.current_address = address
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid address for .ORG")

        elif directive == '.DB':
            # .DB byte1, byte2, ...   can include 'A' or "Hello world"
            items = self._split_args(argstr)
            if not items:
                self.errors.append(f"Line {line_num}: .DB requires at least one value")
                return
            for item in items:
                item = item.strip()
                if self._is_double_quoted(item):
                    s = self._unquote_double(item)
                    if self.pass_num == 2:
                        for ch in s:
                            self.output.append(ord(ch) & 0xFF)
                    self.current_address += len(s)
                elif self._is_single_quoted_char(item):
                    if self.pass_num == 2:
                        self.output.append(ord(item[1]) & 0xFF)
                    self.current_address += 1
                else:
                    try:
                        v = self._parse_value(item)
                        self._require_u16(v, line_num, "byte", maxv=0xFF)
                        if self.pass_num == 2:
                            self.output.append(v & 0xFF)
                        self.current_address += 1
                    except ValueError:
                        self.errors.append(f"Line {line_num}: Invalid value for .DB -> {item}")

        elif directive == '.DW':
            items = self._split_args(argstr)
            if not items:
                self.errors.append(f"Line {line_num}: .DW requires at least one value")
                return
            for item in items:
                item = item.strip()
                try:
                    v = self._parse_value(item)
                    self._require_u16(v, line_num, "word", maxv=0xFFFF)
                    if self.pass_num == 2:
                        # little-endian
                        self.output.append(v & 0xFF)
                        self.output.append((v >> 8) & 0xFF)
                    self.current_address += 2
                except ValueError:
                    self.errors.append(f"Line {line_num}: Invalid value for .DW -> {item}")

        elif directive == '.DS':
            if not argstr:
                self.errors.append(f"Line {line_num}: .DS requires a size")
                return
            try:
                size = self._parse_value(argstr.strip())
                if size < 0:
                    raise ValueError
                if self.pass_num == 2:
                    self.output.extend(b'\x00' * size)
                self.current_address += size
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid size for .DS")

        elif directive == '.EQU':
            # Syntax: .EQU NAME = value
            m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$', argstr)
            if not m:
                self.errors.append(f"Line {line_num}: Invalid .EQU syntax")
                return
            name, val_expr = m.group(1), m.group(2).strip()
            if not self._is_valid_identifier(name):
                self.errors.append(f"Line {line_num}: Invalid constant name '{name}'")
                return
            try:
                value = self._parse_value(val_expr)
                if name in self.definitions:
                    self.errors.append(f"Line {line_num}: Duplicate constant '{name}'")
                else:
                    self.definitions[name] = value
            except ValueError:
                self.errors.append(f"Line {line_num}: Invalid value for .EQU")

    # ------------------ Parsing Helpers ------------------
    def _strip_line_comment(self, line):
        # strip ; comments, trim, collapse internal block comments (already stripped globally)
        line = re.sub(r';.*$', '', line)
        return line.strip()

    def _split_args(self, argstr):
        """Split a directive arg string by commas, preserving quoted strings."""
        items = []
        buf = []
        in_single = False
        in_double = False
        i = 0
        while i < len(argstr):
            c = argstr[i]
            if c == "'" and not in_double:
                in_single = not in_single
                buf.append(c)
            elif c == '"' and not in_single:
                in_double = not in_double
                buf.append(c)
            elif c == ',' and not in_single and not in_double:
                items.append(''.join(buf).strip())
                buf = []
            else:
                buf.append(c)
            i += 1
        if buf:
            items.append(''.join(buf).strip())
        # remove empty entries (e.g., trailing commas)
        return [x for x in items if x != '']

    def _split_operands(self, opstr):
        """Split instruction operands by commas, respecting brackets and quotes."""
        items = []
        buf = []
        depth = 0  # bracket depth for [...]
        in_single = False
        in_double = False
        i = 0
        while i < len(opstr):
            c = opstr[i]
            if c == "'" and not in_double:
                in_single = not in_single
                buf.append(c)
            elif c == '"' and not in_single:
                in_double = not in_double
                buf.append(c)
            elif c == '[' and not in_single and not in_double:
                depth += 1
                buf.append(c)
            elif c == ']' and not in_single and not in_double:
                depth = max(0, depth - 1)
                buf.append(c)
            elif c == ',' and depth == 0 and not in_single and not in_double:
                items.append(''.join(buf).strip())
                buf = []
            else:
                buf.append(c)
            i += 1
        if buf:
            items.append(''.join(buf).strip())
        return items

    def _is_double_quoted(self, s):
        return len(s) >= 2 and s[0] == '"' and s[-1] == '"'

    def _unquote_double(self, s):
        return s[1:-1]

    def _is_single_quoted_char(self, s):
        return len(s) == 3 and s[0] == "'" and s[2] == "'"

    def _parse_value(self, value_str):
        """Parse numeric value with different bases, constants, and labels."""
        value_str = value_str.strip()

        # char literal
        if self._is_single_quoted_char(value_str):
            return ord(value_str[1])

        # constants
        if value_str in self.definitions:
            return self.definitions[value_str]

        # labels (only resolved in pass 2)
        if self.pass_num == 2 and value_str in self.symbol_table:
            return self.symbol_table[value_str]

        # Allow optional leading '#'
        if value_str.startswith('#'):
            value_str = value_str[1:].strip()

        # uppercase hex 0X
        if value_str.startswith('0X'):
            value_str = '0x' + value_str[2:]

        # hex
        if value_str.startswith('0x'):
            return int(value_str[2:], 16)

        # binary
        if value_str.startswith('0b'):
            return int(value_str[2:], 2)

        # decimal (signed allowed)
        if re.fullmatch(r'-?\d+', value_str):
            return int(value_str, 10)

        # simple + / - expressions (left-to-right)
        if '+' in value_str:
            parts = [p.strip() for p in value_str.split('+')]
            return sum(self._parse_value(p) for p in parts)
        if '-' in value_str:
            parts = [p.strip() for p in value_str.split('-')]
            base = self._parse_value(parts[0])
            for p in parts[1:]:
                base -= self._parse_value(p)
            return base

        # if still unresolved and looks like identifier: leave for pass 2
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value_str):
            if self.pass_num == 2:
                raise ValueError(f"Unknown symbol '{value_str}'")
            # in pass 1 we don't need numeric value; caller should not force-evaluate it
            return 0

        raise ValueError(f"Invalid value: '{value_str}'")

    def _get_operand_type(self, operand):
        """Classify operand type."""
        op = operand.strip()

        # Memory operand: [ ... ]
        if op.startswith('[') and op.endswith(']'):
            expr = op[1:-1].strip()
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
            # Absolute address or label expression
            return 'abs', expr

        # Register
        if op in REGISTERS:
            return 'reg', op

        # Immediate
        if op.startswith('#'):
            return 'imm', op[1:].strip()

        # Label or identifier-like (treat as label in pass 1 for sizing)
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', op):
            return 'label', op

        # Numeric literal without '#'
        try:
            _ = self._parse_value(op)  # may return 0 in pass 1 for unresolved labels
            return 'imm', op
        except ValueError:
            return 'unknown', op

    def _get_instruction_size(self, mnemonic, operands):
        """Compute size in bytes."""
        if mnemonic.startswith('.'):
            return 0

        # classify
        op_types = []
        for op in operands:
            t, _ = self._get_operand_type(op)
            op_types.append(t)

        # MOV variants
        if mnemonic == 'MOV':
            if op_types == ['reg', 'mem_reg'] or op_types == ['mem_reg', 'reg']:
                return 2
            if op_types == ['reg', 'abs'] or op_types == ['abs', 'reg']:
                return 4
            if op_types == ['reg', 'imm']:
                return 4
            return 2  # reg,reg

        # LEA
        if mnemonic == 'LEA':
            if len(op_types) != 2 or op_types[0] != 'reg':
                raise ValueError("LEA requires Rd, address")
            if op_types[1] in ('abs', 'label'):
                return 4  # opcode + mode + 16-bit
            if op_types[1] == 'base_offset':
                return 5  # opcode + mode + base + 16-bit
            raise ValueError("Invalid LEA addressing mode")

        # jumps/call: opcode + 16-bit PC-relative offset
        if mnemonic in ['JMP', 'JZ', 'JNZ', 'JC', 'JNC', 'CALL']:
            return 3

        # I/O
        if mnemonic in ['OUT', 'IN']:
            return 2

        # Immediate arithmetic
        if mnemonic in ['ADD', 'SUB'] and len(op_types) == 2 and op_types[1] == 'imm':
            return 4

        # Shifts
        if mnemonic in ['SHL', 'SHR', 'SAR']:
            return 3

        # CMP reg, imm
        if mnemonic == 'CMP' and len(op_types) == 2 and op_types[1] == 'imm':
            return 4

        # Defaults
        if mnemonic in ['RET', 'HLT', 'NOP']:
            return 1
        if len(operands) == 1:
            return 2
        return 2

    # ------------------ Encoding ------------------
    def _encode_instruction(self, mnemonic, operands, line_num):
        # classify with values
        op_types, op_values = [], []
        for op in operands:
            t, v = self._get_operand_type(op)
            op_types.append(t)
            op_values.append(v)

        # fetch opcode
        try:
            opcode = OPCODES[mnemonic][tuple(op_types)]
        except KeyError:
            raise ValueError(f"Invalid operand combination for {mnemonic}: {op_types}")

        # write opcode byte
        self.output.append(opcode)
        self.current_address += 1

        if mnemonic == 'MOV':
            self._encode_MOV(op_types, op_values, line_num)
            return

        if mnemonic == 'LEA':
            self._encode_LEA(op_types, op_values, line_num)
            return

        if mnemonic in ['ADD', 'SUB']:
            if op_types == ['reg', 'reg']:
                self._encode_reg_reg(op_values[0], op_values[1])
                return
            if op_types == ['reg', 'imm']:
                self._encode_reg_imm(op_values[0], op_values[1], line_num)
                return

        if mnemonic in ['AND', 'OR', 'XOR', 'CMP', 'TEST', 'MUL', 'DIV']:
            if op_types == ['reg', 'reg']:
                self._encode_reg_reg(op_values[0], op_values[1])
                return
            if mnemonic == 'CMP' and op_types == ['reg', 'imm']:
                self._encode_reg_imm(op_values[0], op_values[1], line_num)
                return

        if mnemonic in ['SHL', 'SHR', 'SAR']:
            self._encode_shift(op_values[0], op_values[1], line_num)
            return

        if mnemonic in ['PUSH', 'POP', 'INC', 'DEC', 'NEG', 'NOT']:
            self._encode_single_reg(op_values[0])
            return

        if mnemonic in ['JMP', 'JZ', 'JNZ', 'JC', 'JNC', 'CALL']:
            self._encode_jump_pc_relative(op_values[0])
            return

        if mnemonic in ['RET', 'HLT', 'NOP']:
            return

        if mnemonic in ['OUT', 'IN']:
            self._encode_io(op_values[0], line_num)
            return

        raise ValueError(f"Unhandled encoding for {mnemonic} {op_types}")

    # MOV encoding variants
    def _encode_MOV(self, op_types, op_values, line_num):
        if op_types == ['reg', 'reg']:
            self._encode_reg_reg(op_values[0], op_values[1])
        elif op_types == ['reg', 'imm']:
            self._encode_reg_imm(op_values[0], op_values[1], line_num)
        elif op_types == ['reg', 'mem_reg']:
            # LD Rd, [Rs]
            self._encode_reg_reg(op_values[0], op_values[1])
        elif op_types == ['mem_reg', 'reg']:
            # ST [Rd], Rs   (first value is address register)
            self._encode_reg_reg(op_values[0], op_values[1])
        elif op_types == ['reg', 'abs']:
            # LD Rd, [abs16] : reg byte + 16-bit address
            self._encode_reg_abs(op_values[0], op_values[1], line_num)
        elif op_types == ['abs', 'reg']:
            # ST [abs16], Rs : reg byte + 16-bit address
            self._encode_reg_abs(op_values[1], op_values[0], line_num)  # reuse helper (rd, abs)
        else:
            raise ValueError(f"MOV: invalid combination {op_types}")

    def _encode_LEA(self, op_types, op_values, line_num):
        rd = op_values[0]
        mode = op_types[1]
        mode_byte = (self._reg_index(rd) << 4) | LEA_MODES[mode]
        self.output.append(mode_byte)
        self.current_address += 1

        if mode == 'abs':
            addr = self._parse_value(op_values[1])
            self._require_u16(addr, line_num, "address", 0xFFFF)
            self._emit_u16(addr)
        elif mode == 'label':
            label_addr = self._parse_value(op_values[1])
            # offset relative to end of the 2-byte immediate (current + 2)
            offset = (label_addr - (self.current_address + 2)) & 0xFFFF
            self._emit_u16(offset)
        elif mode == 'base_offset':
            base_reg, offset = op_values[1]
            self.output.append(self._reg_index(base_reg) & 0x0F)
            self.current_address += 1
            if isinstance(offset, str) and offset.startswith('#'):
                offset = offset[1:].strip()
            off_val = self._parse_value(offset)
            self._require_u16(off_val, line_num, "offset", 0xFFFF)
            self._emit_u16(off_val)
        else:
            raise ValueError("Invalid LEA mode")

    def _encode_reg_reg(self, rd, rs):
        self.output.append((self._reg_index(rd) << 4) | self._reg_index(rs))
        self.current_address += 1

    def _encode_reg_imm(self, rd, imm_str_or_val, line_num):
        val = self._parse_value(imm_str_or_val)
        self._require_u16(val, line_num, "immediate", 0xFFFF)
        self.output.append(self._reg_index(rd) << 4)
        self.current_address += 1
        self._emit_u16(val)

    def _encode_reg_abs(self, rd, abs_expr, line_num):
        addr = self._parse_value(abs_expr)
        self._require_u16(addr, line_num, "address", 0xFFFF)
        self.output.append(self._reg_index(rd) << 4)
        self.current_address += 1
        self._emit_u16(addr)

    def _encode_shift(self, rd, count_expr, line_num):
        count = self._parse_value(count_expr)
        if count < 0 or count > 15:
            raise ValueError(f"Shift count out of range (0..15): {count}")
        self.output.append(self._reg_index(rd) << 4)
        self.current_address += 1
        self.output.append(count & 0x0F)
        self.current_address += 1

    def _encode_single_reg(self, reg):
        self.output.append(self._reg_index(reg) << 4)
        self.current_address += 1

    def _encode_jump_pc_relative(self, target_label_or_value):
        target_addr = self._parse_value(target_label_or_value)
        # PC-relative offset from end of the 2-byte immediate (current + 2)
        offset = (target_addr - (self.current_address + 2)) & 0xFFFF
        self._emit_u16(offset)

    def _encode_io(self, port_expr, line_num):
        port = self._parse_value(port_expr)
        if port < 0 or port > 15:
            raise ValueError(f"I/O port out of range (0..15): {port}")
        self.output.append(port & 0x0F)
        self.current_address += 1

    # ------------------ Utilities ------------------
    def _emit_u16(self, val):
        self.output.append(val & 0xFF)
        self.output.append((val >> 8) & 0xFF)
        self.current_address += 2

    def _require_u16(self, val, line_num, kind="value", maxv=0xFFFF):
        if not (-(1 << 31) <= val <= (1 << 31) - 1):
            raise ValueError(f"Line {line_num}: {kind} too large: {val}")
        if val < 0 or val > maxv:
            raise ValueError(f"Line {line_num}: {kind} out of range: {val}")

    def _reg_index(self, reg_name):
        reg_map = {
            'A': 0, 'B': 1, 'C': 2, 'D': 3,
            'SP': 4, 'PC': 5, 'FP': 6, 'FLAGS': 7
        }
        name = reg_name.upper()
        if name not in reg_map:
            raise ValueError(f"Unknown register '{reg_name}'")
        return reg_map[name]

    def _is_valid_identifier(self, name):
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

    with open(input_file, 'r', encoding='utf-8') as f:
        source = f.read()

    assembler = Assembler()
    success, errors, warnings, binary = assembler.assemble(source, output_file)

    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  {w}")

    if errors:
        print("\nErrors:")
        for e in errors:
            print(f"  {e}")
        print("\nAssembly failed")
        sys.exit(1)

    print(f"\nAssembly successful. Output: {output_file}")
    print(f"Binary size: {len(binary)} bytes")

    # Listing
    print("\nAssembly Listing:")
    print("Line  Address  Bytes                     Source")
    for line_num, addr, src, bytes_list in assembler.listing:
        addr_str = f"{addr:04X}"
        bytes_str = ' '.join(f'{b:02X}' for b in bytes_list) if bytes_list else ''
        print(f"{line_num:<5} {addr_str}    {bytes_str:<25} {src}")

if __name__ == '__main__':
    main()

