try:
    from builtins import range
except ImportError:
    pass

from binaryninja import (LLIL_TEMP, Architecture, BinaryDataNotification,
                         BinaryView, BranchType, Endianness, InstructionInfo,
                         InstructionTextToken, InstructionTextTokenType, Function,
                         LowLevelILFunction, LowLevelILLabel, LowLevelILOperation, RegisterInfo, 
                         log_info, SegmentFlag, Symbol, SymbolType, log_debug, Settings, SettingsScope)
from .pyevmasm.pyevmasm import Instruction

from .common import ADDR_SIZE

def byte(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load i and x
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))

    # Placeholder pushed value
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def keccak256(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load offset and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    # Load length bytes from [offset]
    il.append(
        il.set_reg(
            #il.reg(ADDR_SIZE, LLIL_TEMP(1)), # TODO: placeholder
            ADDR_SIZE,
            LLIL_TEMP(2),
            il.load(
                #il.get_reg_value(LLIL_TEMP(1)).value, # TODO: investigate
                ADDR_SIZE,
                il.reg(ADDR_SIZE, LLIL_TEMP(0))
            )
        )
    )
    # TODO: put result of LLIL_TEMP(2) into keccak256 function and put result on top of stack

    # TODO: placeholder, put junk on stack to emulate result
    il.append(il.push(ADDR_SIZE, il.unimplemented()))
    return []

def balance(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load addr
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Push some data to the stack because we can't actually look up balance
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def calldataload(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load i
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Push placeholder data, should be msg.data[i:i+32]
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def calldatacopy(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load destOffset, offset, and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))

    return []

def codecopy(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load destOffset, offset, and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))

    return []

def extcodesize(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load addr
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Push placeholder data, should be address(addr).code.size
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def extcodecopy(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load addr, destOffset, offset, and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))

    return []

def returndatacopy(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load destOffset, offset, and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))

    return []

def extcodehash(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load addr
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Push placeholder data, should be hash
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def blockhash(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load blockNumber
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Push placeholder data, should be hash
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def mload(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load offset
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    # Load ADDR_SIZE bytes from offset and push to stack
    il.append(
        il.push(ADDR_SIZE, 
            il.load(ADDR_SIZE, il.reg(ADDR_SIZE, LLIL_TEMP(0)))
        )
    )
    return []

def mstore(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load offset and value
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    # Store value at offset
    il.append(
        il.store(
            ADDR_SIZE,
            il.reg(ADDR_SIZE, LLIL_TEMP(0)),
            il.reg(ADDR_SIZE, LLIL_TEMP(1))
        )
    )
    return []

def mstore8(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load offset and value
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    # AND value down to 1 byte, write byte to offset
    il.append(
        il.store(
            1,
            il.reg(ADDR_SIZE, LLIL_TEMP(0)),
            il.and_expr(ADDR_SIZE, il.reg(ADDR_SIZE, LLIL_TEMP(1)), il.const(ADDR_SIZE, 0xff))
        )
    )
    return []

def sload(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load uint256 key
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))

    # Push placeholder value as if we pulled from storage
    il.append(il.push(ADDR_SIZE, il.unimplemented()))
    return []

def sstore(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load uint256 key and value
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))

    # Pretend we put something in storage here
    return []

def jump(il: LowLevelILFunction, addr: int, instr: Instruction):
    dest = il.pop(ADDR_SIZE)

    if len(il) > 0:
        push = il[len(il)-1]
    else:
        push = None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.jump(il.reg(ADDR_SIZE, LLIL_TEMP(addr))))

    return []

def jumpi(il: LowLevelILFunction, addr: int, instr: Instruction):
    dest = il.pop(ADDR_SIZE)

    if len(il) > 0:
        push = il[len(il)-1]
    else:
        push = None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    else:
        il.append(dest)

    t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['EVM'], addr+1)
    must_mark = False

    if f is None:
        f = LowLevelILLabel()
        must_mark = True

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    #il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.if_expr(il.reg(ADDR_SIZE, LLIL_TEMP(0)), t, f))

    il.mark_label(t)
    il.append(il.jump(il.unimplemented()))  # il.reg(ADDR_SIZE, LLIL_TEMP(1))))

    if must_mark:
        il.mark_label(f)
        # false is the fall through case
        il.append(il.jump(il.const(ADDR_SIZE, addr + 1)))

    return []

def push(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Push the operand to stack, variable length but extended to ADDR_SIZE
    return il.push(ADDR_SIZE, il.const(ADDR_SIZE, instr.operand))

def dup(il: LowLevelILFunction, addr: int, distance: int):
    il.append(
        il.set_reg(
            ADDR_SIZE, LLIL_TEMP(0), il.load(
                ADDR_SIZE, il.add(
                    ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
                    il.const(ADDR_SIZE, (distance - 1) * ADDR_SIZE)
                )
            )
        )
    )

    il.append(il.push(ADDR_SIZE, il.reg(ADDR_SIZE, LLIL_TEMP(0))))

    return []

def swap(il: LowLevelILFunction, addr: int, distance: int):
    stack_offset = distance * ADDR_SIZE

    load = il.load(
        ADDR_SIZE, il.add(
            ADDR_SIZE,
            il.reg(ADDR_SIZE, 'sp'),
            il.const(ADDR_SIZE, stack_offset)
        )
    )

    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), load))

    il.append(
        il.set_reg(
            ADDR_SIZE, LLIL_TEMP(1),
            il.load(ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'))
        )
    )

    il.append(
        il.store(
            ADDR_SIZE, il.add(
                ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
                il.const(ADDR_SIZE, stack_offset)
            ),
            il.reg(ADDR_SIZE, LLIL_TEMP(1))
        )
    )
    il.append(
        il.store(
            ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
            il.reg(ADDR_SIZE, LLIL_TEMP(0))
        )
    )

    return []

def log(il: LowLevelILFunction, addr: int, instr: Instruction, topics: int):
    # load offset and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))

    # For now just loop the number of topics and pop them off the stack
    for i in range(topics):
        il.append(il.pop(ADDR_SIZE))

    return []

def create(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load value, offset, and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))

    # Push placeholder value on stack (actual: addr)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def call(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load gas, addr, value, argsOffset, argsLength, retOffset, retLength
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(4), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(5), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(6), il.pop(ADDR_SIZE)))

    # TODO: Add placeholder memory writes for call results
    # il.append(il.store(etc))

    # Push placeholder value on stack (actual: success)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def callcode(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load gas, addr, value, argsOffset, argsLength, retOffset, retLength
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(4), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(5), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(6), il.pop(ADDR_SIZE)))

    # TODO: Add placeholder memory writes for call results
    # il.append(il.store(etc))

    # Push placeholder value on stack (actual: success)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def return_op(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load offset, length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))

    # Load length bytes from offset and return to it
    il.append(
        il.ret(
            il.load(
                #il.get_reg_value(LLIL_TEMP(1)).value, # TODO: investigate
                ADDR_SIZE,
                il.reg(ADDR_SIZE, LLIL_TEMP(0)))
        )
    )

    return []

def delegatecall(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load gas, addr, argsOffset, argsLength, retOffset, retLength
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(4), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(5), il.pop(ADDR_SIZE)))

    # TODO: Add placeholder memory writes for call results
    # il.append(il.store(etc))

    # Push placeholder value on stack (actual: success)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def create2(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load value, offset, length, and salt
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))

    # Push placeholder value on stack (actual: addr)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def staticcall(il: LowLevelILFunction, addr: int, instr: Instruction):
    # load gas, addr, argsOffset, argsLength, retOffset, retLength
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(2), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(3), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(4), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(5), il.pop(ADDR_SIZE)))

    # TODO: Add placeholder memory writes for call results
    # il.append(il.store(etc))

    # Push placeholder value on stack (actual: success)
    il.append(il.push(ADDR_SIZE, il.unimplemented()))

    return []

def revert(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load offset and length
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))

    # Non-returning opcode
    il.append(il.no_ret())

    return []

def selfdestruct(il: LowLevelILFunction, addr: int, instr: Instruction):
    # Load addr
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))

    # Non-returning opcode
    il.append(il.no_ret())

    return []