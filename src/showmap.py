import angr
import sys

from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from capstone.x86_const import X86_OP_REG, X86_OP_IMM

program = sys.argv[1]
proj = angr.Project(program, load_options={"auto_load_libs": False})
main = proj.loader.find_symbol("main")
cfg = proj.analyses.CFGEmulated(context_sensitivity_level=0, starts=[main.rebased_addr], call_depth=0, normalize=True)
func = cfg.functions[main.rebased_address]
graph = func.transition_graph

def get_node(nodes, addr):
    for node in nodes:
        if node.addr == addr:
            return node
    return None

def getsuccessors(graph, node):
    return list(graph.successors(node))

def haslog(succs):
    for succ in succs:
        if isinstance(succ, Function):
            if succ.name == '__afl_maybe_log':
                return True
    return False

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

def getId(block):
    for insn in reversed(block(node.addr.capstone.insns):
        if isIdinsn(insn):
            return insn.operands[1].value.imm
    return 0

start = get_node(graph, main.rebased_addr)
succs = getsuccessors(graph, start)
if haslog(succs):
    block = proj.factory.block(start.addr)
    cur_id = getId(block)


