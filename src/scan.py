import angr
import sys

from capstone.x86_const import X86_OP_IMM, X86_OP_REG

program = sys.argv[1]
proj = angr.Project(program, load_options={"auto_load_libs": False})
main = proj.loader.find_symbol("main")
log = proj.loader.find_symbol("__afl_maybe_log")
start = main.rebased_addr
end = 0x41184C

def isIdinsn(insn):
    if insn.mnemonic != 'mov':
        return False
    if len(insn.operands) != 2:
        return False
    if insn.operands[0].type != X86_OP_REG:
        return False
    if insn.reg_name(insn.operands[0].value.reg) != 'rcx':
        return False
    if insn.operands[1].type != X86_OP_IMM:
        return False
    return True

def isLog(insn):
    if insn.mnemonic != "call":
        return False
    if len(insn.operands) != 1:
        return False
    if insn.operands[0].type != X86_OP_IMM:
        return False
    if insn.operands[0].value.imm != log.rebased_addr:
        return False
    return True

def isCmp(insn):
    if insn.mnemonic != "cmp":
        return False
    if len(insn.operands) != 2:
        return False
    if insn.operands[0].type != X86_OP_REG:
        return False
    if insn.reg_name(insn.operands[0].value.reg) != "rcx":
        return False
    if insn.operands[1].type != X86_OP_IMM:
        return False
    return True

cur = start
cur_rcx = 0
while cur < end:
    block = proj.factory.block(cur)
    cur += block.size
    for insn in block.capstone.insns:
        if isIdinsn(insn):
            cur_rcx = insn.operands[1].value.imm
        if isCmp(insn):
            print("Cmp rcx %c" % chr(insn.operands[1].value.imm))
        if isLog(insn):
            print("0x%x: %x" % (insn.address, cur_rcx))
			
