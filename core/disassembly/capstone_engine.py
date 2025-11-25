import capstone
from capstone import *

class CapstoneEngine:
    """Capstone-based disassembly with control flow analysis"""
    
    ARCH_MAP = {
        'x86': (CS_ARCH_X86, CS_MODE_32),
        'x86_64': (CS_ARCH_X86, CS_MODE_64),
        'arm': (CS_ARCH_ARM, CS_MODE_ARM),
        'arm64': (CS_ARCH_ARM64, CS_MODE_ARM),
        'mips': (CS_ARCH_MIPS, CS_MODE_MIPS32),
        'mips64': (CS_ARCH_MIPS, CS_MODE_MIPS64),
    }
    
    def __init__(self, arch='x86_64'):
        """Initialize Capstone engine with specified architecture"""
        if arch not in self.ARCH_MAP:
            raise ValueError(f"Unsupported architecture: {arch}")
        
        arch_const, mode_const = self.ARCH_MAP[arch]
        self.md = Cs(arch_const, mode_const)
        self.md.detail = True  # Enable detailed information
        self.arch = arch
    
    def disassemble(self, data, base_address=0x400000):
        """Disassemble binary data and return instruction list"""
        instructions = []
        
        for insn in self.md.disasm(data, base_address):
            inst_info = {
                'address': hex(insn.address),
                'mnemonic': insn.mnemonic,
                'operands': insn.op_str,
                'bytes': insn.bytes.hex(),
                'size': insn.size,
                'groups': [insn.group_name(g) for g in insn.groups],
                'regs_read': [insn.reg_name(r) for r in insn.regs_read],
                'regs_write': [insn.reg_name(r) for r in insn.regs_write],
            }
            instructions.append(inst_info)
        
        return instructions
    
    def identify_functions(self, instructions):
        """Identify function boundaries from disassembly"""
        functions = []
        current_function = None
        
        for i, insn in enumerate(instructions):
            # Function start heuristics
            if self._is_function_start(insn, i, instructions):
                if current_function:
                    functions.append(current_function)
                
                current_function = {
                    'address': insn['address'],
                    'name': f"sub_{insn['address'][2:]}",  # Remove '0x' prefix
                    'instructions': [insn],
                    'size': insn['size']
                }
            elif current_function:
                current_function['instructions'].append(insn)
                current_function['size'] += insn['size']
                
                # Function end heuristics
                if self._is_function_end(insn):
                    functions.append(current_function)
                    current_function = None
        
        # Add last function if exists
        if current_function:
            functions.append(current_function)
        
        return functions
    
    def _is_function_start(self, insn, index, instructions):
        """Heuristic to detect function start"""
        # First instruction is always a function start
        if index == 0:
            return True
        
        # Check if previous instruction was a return
        if index > 0:
            prev = instructions[index - 1]
            if 'ret' in prev['groups'] or prev['mnemonic'] == 'ret':
                return True
        
        # Check for common function prologue patterns
        if insn['mnemonic'] in ['push', 'mov', 'sub'] and 'ebp' in insn['operands']:
            return True
        
        # Check if this is a call target (would need xref analysis)
        # For now, use address alignment as heuristic
        addr = int(insn['address'], 16)
        if addr % 16 == 0:  # Aligned to 16 bytes
            return True
        
        return False
    
    def _is_function_end(self, insn):
        """Heuristic to detect function end"""
        return 'ret' in insn['groups'] or insn['mnemonic'] in ['ret', 'retn']
    
    def build_basic_blocks(self, instructions):
        """Identify basic blocks in instruction list"""
        basic_blocks = []
        current_block = []
        
        for i, insn in enumerate(instructions):
            current_block.append(insn)
            
            # End block on control flow instructions
            if any(g in insn['groups'] for g in ['jump', 'call', 'ret']):
                basic_blocks.append({
                    'start_address': current_block[0]['address'],
                    'end_address': insn['address'],
                    'instructions': current_block,
                    'type': self._get_block_type(insn)
                })
                current_block = []
            # Also end block if next instruction is a jump target
            elif i + 1 < len(instructions):
                next_insn = instructions[i + 1]
                # Simple heuristic: aligned addresses are likely jump targets
                next_addr = int(next_insn['address'], 16)
                if next_addr % 16 == 0:
                    basic_blocks.append({
                        'start_address': current_block[0]['address'],
                        'end_address': insn['address'],
                        'instructions': current_block,
                        'type': 'sequential'
                    })
                    current_block = []
        
        # Add last block if exists
        if current_block:
            basic_blocks.append({
                'start_address': current_block[0]['address'],
                'end_address': current_block[-1]['address'],
                'instructions': current_block,
                'type': 'sequential'
            })
        
        return basic_blocks
    
    def _get_block_type(self, insn):
        """Determine basic block terminator type"""
        if 'ret' in insn['groups']:
            return 'return'
        elif 'call' in insn['groups']:
            return 'call'
        elif 'jump' in insn['groups']:
            if insn['mnemonic'].startswith('j') and insn['mnemonic'] != 'jmp':
                return 'conditional_jump'
            else:
                return 'unconditional_jump'
        return 'sequential'
    
    def analyze_control_flow(self, instructions):
        """Analyze control flow and build CFG edges"""
        edges = []
        
        for i, insn in enumerate(instructions):
            current_addr = insn['address']
            
            # Handle calls
            if 'call' in insn['groups']:
                # Extract target address from operands
                target = self._extract_target_address(insn['operands'])
                if target:
                    edges.append({
                        'from': current_addr,
                        'to': target,
                        'type': 'call'
                    })
                # Fall-through edge to next instruction
                if i + 1 < len(instructions):
                    edges.append({
                        'from': current_addr,
                        'to': instructions[i + 1]['address'],
                        'type': 'fallthrough'
                    })
            
            # Handle jumps
            elif 'jump' in insn['groups']:
                target = self._extract_target_address(insn['operands'])
                if target:
                    jump_type = 'conditional' if insn['mnemonic'] != 'jmp' else 'unconditional'
                    edges.append({
                        'from': current_addr,
                        'to': target,
                        'type': jump_type
                    })
                    
                    # Conditional jumps have fall-through edge
                    if jump_type == 'conditional' and i + 1 < len(instructions):
                        edges.append({
                            'from': current_addr,
                            'to': instructions[i + 1]['address'],
                            'type': 'fallthrough'
                        })
            
            # Handle returns (no outgoing edges)
            elif 'ret' not in insn['groups']:
                # Sequential flow to next instruction
                if i + 1 < len(instructions):
                    edges.append({
                        'from': current_addr,
                        'to': instructions[i + 1]['address'],
                        'type': 'sequential'
                    })
        
        return edges
    
    def _extract_target_address(self, operands):
        """Extract target address from operand string"""
        # Simple heuristic: look for hex addresses
        import re
        match = re.search(r'0x[0-9a-fA-F]+', operands)
        if match:
            return match.group(0)
        return None
    
    def build_xrefs(self, instructions):
        """Build cross-reference table"""
        xrefs = []
        
        for insn in instructions:
            current_addr = insn['address']
            
            # Code references (calls and jumps)
            if any(g in insn['groups'] for g in ['call', 'jump']):
                target = self._extract_target_address(insn['operands'])
                if target:
                    xref_type = 'call' if 'call' in insn['groups'] else 'jump'
                    xrefs.append({
                        'from_address': current_addr,
                        'to_address': target,
                        'xref_type': xref_type
                    })
            
            # Data references (mov, lea, etc.)
            elif insn['mnemonic'] in ['mov', 'lea', 'push']:
                target = self._extract_target_address(insn['operands'])
                if target:
                    xrefs.append({
                        'from_address': current_addr,
                        'to_address': target,
                        'xref_type': 'data'
                    })
        
        return xrefs
    
    def get_function_calls(self, function_instructions):
        """Extract all function calls from a function"""
        calls = []
        
        for insn in function_instructions:
            if 'call' in insn['groups']:
                target = self._extract_target_address(insn['operands'])
                if target:
                    calls.append({
                        'address': insn['address'],
                        'target': target,
                        'mnemonic': insn['mnemonic'],
                        'operands': insn['operands']
                    })
        
        return calls
