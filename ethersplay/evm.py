#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from builtins import range
except ImportError:
    pass

from dataclasses import dataclass
from sha3 import keccak_256
from interval3 import Interval, IntervalSet

from binaryninja import (LLIL_TEMP, Architecture, BinaryDataNotification,
                         BinaryView, BranchType, Endianness, InstructionInfo,
                         InstructionTextToken, InstructionTextTokenType, Function,
                         LowLevelILLabel, LowLevelILOperation, RegisterInfo, log_info,
                         SegmentFlag, Symbol, SymbolType, log_debug, Settings, SettingsScope)
from binaryninja.function import _FunctionAssociatedDataStore
from .pyevmasm.pyevmasm import assemble, disassemble_one

from .analysis import VsaNotification
from .common import ADDR_SIZE
from evm_cfg_builder.cfg import CFG
from . import evmhelper as h

# Good reference for behavior: https://www.ethervm.io/
insn_il = {
    'STOP': lambda il, addr, instr: il.no_ret(),
    'ADD': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.add(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'MUL': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.mult(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SUB': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.sub(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'DIV': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.div_unsigned(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SDIV': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.div_signed(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'MOD': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.mod_unsigned(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SMOD': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.mod_signed(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'ADDMOD': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.mod_unsigned(
            ADDR_SIZE, 
            il.add(
                ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
            ),
            il.pop(ADDR_SIZE)
        )
    ),
    'MULMOD': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.mod_unsigned(
            ADDR_SIZE, 
            il.mul(
                ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
            ),
            il.pop(ADDR_SIZE)
        )
    ),
    'EXP': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'SIGNEXTEND': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.sign_extend(
            ADDR_SIZE, il.pop(ADDR_SIZE)
        )
    ),
    'LT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_unsigned_less_than(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'GT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_unsigned_greater_than(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SLT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_signed_less_than(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SGT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_signed_greater_than(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'EQ': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_equal(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'ISZERO': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.compare_equal(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.const(ADDR_SIZE, 0)
        )
    ),
    'AND': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.and_expr(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'OR': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.or_expr(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'XOR': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.xor_expr(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'NOT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.not_expr(
            ADDR_SIZE, il.pop(ADDR_SIZE)
        )
    ),
    'BYTE': h.byte,
    'SHL': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.shift_left(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SHR': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.logical_shift_right(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'SAR': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.arith_shift_right(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    # SHA3 and KECCAK256 are the same opcode
    'SHA3': h.keccak256,
    'KECCAK256': h.keccak256,
    'ADDRESS': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'BALANCE': h.balance,
    'ORIGIN': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CALLER': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CALLVALUE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CALLDATALOAD': h.calldataload,
    'CALLDATASIZE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CALLDATACOPY': h.calldatacopy,
    'CODESIZE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CODECOPY': h.codecopy,
    'GASPRICE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'EXTCODESIZE': h.extcodesize,
    'EXTCODECOPY': h.extcodecopy,
    'RETURNDATASIZE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'RETURNDATACOPY': h.returndatacopy,
    'EXTCODEHASH': h.extcodehash,
    'BLOCKHASH': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'COINBASE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'TIMESTAMP': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'NUMBER': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'DIFFICULTY': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'GASLIMIT': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'CHAINID': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'BASEFEE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'POP': lambda il, addr, instr: il.pop(ADDR_SIZE),
    'MLOAD': h.mload,
    'MSTORE': h.mstore,
    'MSTORE8': h.mstore8,
    'SLOAD': h.sload,
    'SSTORE': h.sstore,
    'JUMP': h.jump,
    'JUMPI': h.jumpi,
    # GETPC and PC are the same opcode
    'GETPC': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'PC': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'MSIZE': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'GAS': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'JUMPDEST': lambda il, addr, instr: [],
    # PUSH is not a real opcode, pyevmasm returns it instead of PUSH* with parameters parsed
    'PUSH': h.push,
    'PUSH1':  h.push,
    'PUSH2':  h.push,
    'PUSH3':  h.push,
    'PUSH4':  h.push,
    'PUSH5':  h.push,
    'PUSH6':  h.push,
    'PUSH7':  h.push,
    'PUSH8':  h.push,
    'PUSH9':  h.push,
    'PUSH10': h.push,
    'PUSH11': h.push,
    'PUSH12': h.push,
    'PUSH13': h.push,
    'PUSH14': h.push,
    'PUSH15': h.push,
    'PUSH16': h.push,
    'PUSH17': h.push,
    'PUSH18': h.push,
    'PUSH19': h.push,
    'PUSH20': h.push,
    'PUSH21': h.push,
    'PUSH22': h.push,
    'PUSH23': h.push,
    'PUSH24': h.push,
    'PUSH25': h.push,
    'PUSH26': h.push,
    'PUSH27': h.push,
    'PUSH28': h.push,
    'PUSH29': h.push,
    'PUSH30': h.push,
    'PUSH31': h.push,
    'PUSH32': h.push,
    # DUP is not a real opcode, pyevmasm returns it in place of any DUP* with parameters parsed
    'DUP': lambda il, addr, instr: h.dup(il, addr, instr.pops),
    'DUP1': lambda il, addr, instr: h.dup(il, addr, 1),
    'DUP2': lambda il, addr, instr: h.dup(il, addr, 2),
    'DUP3': lambda il, addr, instr: h.dup(il, addr, 3),
    'DUP4': lambda il, addr, instr: h.dup(il, addr, 4),
    'DUP5': lambda il, addr, instr: h.dup(il, addr, 5),
    'DUP6': lambda il, addr, instr: h.dup(il, addr, 6),
    'DUP7': lambda il, addr, instr: h.dup(il, addr, 7),
    'DUP8': lambda il, addr, instr: h.dup(il, addr, 8),
    'DUP9': lambda il, addr, instr: h.dup(il, addr, 9),
    'DUP10': lambda il, addr, instr: h.dup(il, addr, 10),
    'DUP11': lambda il, addr, instr: h.dup(il, addr, 11),
    'DUP12': lambda il, addr, instr: h.dup(il, addr, 12),
    'DUP13': lambda il, addr, instr: h.dup(il, addr, 13),
    'DUP14': lambda il, addr, instr: h.dup(il, addr, 14),
    'DUP15': lambda il, addr, instr: h.dup(il, addr, 15),
    'DUP16': lambda il, addr, instr: h.dup(il, addr, 16),
    # SWAP is not a real opcode, pyevmasm returns it in place of any SWAP* with parameters parsed
    'SWAP': lambda il, addr, instr: h.swap(il, addr, instr.pops),
    'SWAP1': lambda il, addr, instr: h.swap(il, addr, 1),
    'SWAP2': lambda il, addr, instr: h.swap(il, addr, 2),
    'SWAP3': lambda il, addr, instr: h.swap(il, addr, 3),
    'SWAP4': lambda il, addr, instr: h.swap(il, addr, 4),
    'SWAP5': lambda il, addr, instr: h.swap(il, addr, 5),
    'SWAP6': lambda il, addr, instr: h.swap(il, addr, 6),
    'SWAP7': lambda il, addr, instr: h.swap(il, addr, 7),
    'SWAP8': lambda il, addr, instr: h.swap(il, addr, 8),
    'SWAP9': lambda il, addr, instr: h.swap(il, addr, 9),
    'SWAP10': lambda il, addr, instr: h.swap(il, addr, 10),
    'SWAP11': lambda il, addr, instr: h.swap(il, addr, 11),
    'SWAP12': lambda il, addr, instr: h.swap(il, addr, 12),
    'SWAP13': lambda il, addr, instr: h.swap(il, addr, 13),
    'SWAP14': lambda il, addr, instr: h.swap(il, addr, 14),
    'SWAP15': lambda il, addr, instr: h.swap(il, addr, 15),
    'SWAP16': lambda il, addr, instr: h.swap(il, addr, 16),
    'LOG0': lambda il, addr, instr: h.log(il, addr, instr, 0),
    'LOG1': lambda il, addr, instr: h.log(il, addr, instr, 1),
    'LOG2': lambda il, addr, instr: h.log(il, addr, instr, 2),
    'LOG3': lambda il, addr, instr: h.log(il, addr, instr, 3),
    'LOG4': lambda il, addr, instr: h.log(il, addr, instr, 4),
    'CREATE': h.create,
    'CALL': h.call,
    'CALLCODE': h.callcode,
    'RETURN': h.return_op,
    'DELEGATECALL': h.delegatecall,
    'CREATE2': h.create2,
    'STATICCALL': h.staticcall,
    'TXEXECGAS': lambda il, addr, instr: il.push(
        ADDR_SIZE, il.unimplemented()
    ),
    'REVERT': h.revert,
    'INVALID': lambda il, addr, instr: il.no_ret(),
    # SUICIDE and SELFDESTRUCT are the same opcode, renamed at some point
    'SUICIDE': h.selfdestruct,
    'SELFDESTRUCT': h.selfdestruct,
}

class EVM(Architecture):
    name = "EVM"

    # Actual size is 32 but we're going to truncate everything
    address_size = ADDR_SIZE

    # should be 32
    default_int_size = ADDR_SIZE

    instr_alignment = 1

    max_instr_length = 33

    endianness = Endianness.BigEndian

    regs = {
        "sp": RegisterInfo("sp", ADDR_SIZE),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):
        instruction = disassemble_one(data, addr)

        result = InstructionInfo()
        result.length = instruction.size
        if instruction.name == "JUMP":
            result.add_branch(BranchType.UnresolvedBranch)
        elif instruction.name == "JUMPI":
            result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + 1)
        elif instruction.name in ('RETURN', 'REVERT', 'SUICIDE', 'INVALID',
                                  'STOP', 'SELFDESTRUCT'):
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_text(self, data, addr):
        instruction = disassemble_one(data, addr)

        tokens = []
        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                "{:7} ".format(
                    instruction.name
                )
            )
        )

        if instruction.name.startswith('PUSH'):
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    '#{:0{i.operand_size}x}'.format(
                        instruction.operand, i=instruction
                    ),
                    instruction.operand
                )
            )

        return tokens, instruction.size

    def get_instruction_low_level_il(self, data, addr, il):
        instruction = disassemble_one(data, addr)

        ill = insn_il.get(instruction.name, None)
        if ill is None:

            '''
            for i in range(instruction.pops):
                il.append(
                    il.set_reg(ADDR_SIZE, LLIL_TEMP(i), il.pop(ADDR_SIZE))
                )

            for i in range(instruction.pushes):
                il.append(il.push(ADDR_SIZE, instruction.operand))
            '''

            il.append(il.unimplemented())

            return instruction.size

        ils = ill(il, addr, instruction)
        if isinstance(ils, list):
            for i in ils:
                il.append(il)
        else:
            il.append(ils)

        return instruction.size

    def assemble(self, code, addr=0):
        try:
            return assemble(code, addr), ''
        except Exception as e:
            return None, str(e)


class EVMView(BinaryView):
    name = "EVM"
    long_name = "Ethereum Bytecode"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def find_swarm_hashes(self, data):
        rv = []
        offset = data.find(b'\xa1ebzzr0')
        while offset != -1:
            log_debug("Adding r-- segment at: {:#x}".format(offset))
            rv.append((offset, 43))
            offset = data[offset+1:].find(b'\xa1ebzzr0')

        return rv

    def init(self):
        self.arch = Architecture['EVM']
        self.platform = Architecture['EVM'].standalone_platform
        self.max_function_size_for_analysis = 0

        file_size = len(self.raw)

        # Find swarm hashes and make them data
        evm_bytes = self.raw.read(0, file_size)

        # code is everything that isn't a swarm hash
        code = IntervalSet([Interval(0, file_size)])

        swarm_hashes = self.find_swarm_hashes(evm_bytes)
        for start, sz in swarm_hashes:
            self.add_auto_segment(
                start, sz,
                start, sz,
                (
                    SegmentFlag.SegmentContainsData |
                    SegmentFlag.SegmentDenyExecute |
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentDenyWrite
                )
            )

            code -= IntervalSet([Interval(start, start + sz)])

        for interval in code:
            if isinstance(interval, int):
                continue
            self.add_auto_segment(
                interval.lower_bound, interval.upper_bound,
                interval.lower_bound, interval.upper_bound,
                (
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable
                )
            )

        cfg = CFG(evm_bytes)
        Function.set_default_session_data('cfg', cfg)

        self.register_notification(VsaNotification())

        self.add_entry_point(0)

        for function in cfg.functions:
            function_start = (function._start_addr + 1
                              if function._start_addr != 0 else 0)

            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    function_start,
                    function.name
                )
            )

            self.add_function(function_start)

        # disable linear sweep
        Settings().set_bool(
            'analysis.linearSweep.autorun',
            False,
            view=self,
            scope=SettingsScope.SettingsResourceScope
        )

        return True

    @staticmethod
    def is_valid_for_data(data):
        return data.file.original_filename.endswith('.evm')

    def is_executable(self):
        return True

    def get_entry_point(self):
        return 0
