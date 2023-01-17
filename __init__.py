from binaryninja import (
    Architecture,
    BinaryView,
    BranchType,
    Endianness,
    RegisterInfo,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    SegmentFlag,
    SectionSemantics,
    LowLevelILLabel
)
import struct

class LuckyVMInstr():
    def __init__(self,data):
        data = data+b"\x00"
        self.opcode = data[0]

        self.ops = []
        for i in range(3):
            op = data[i+i+1] + (data[i+i+2]<<8)
            self.ops.append(op)
        self.operand1 = self.ops[0]
        self.operand2 = self.ops[1]
        self.operand3 = self.ops[2]

class LuckyVMDisasm():
    def __init__(self):
        self.BASE = 0
        self.instruction_list = [
            "mov",
            "add",
            "add",
            "sub",
            "sub",
            "mul",
            "mul",
            "div",
            "div",
            "and",
            "and",
            "or",
            "or",
            "xor",
            "xor",
            "cmp0",
            "not",
            "store",
            "store",
            "load",
            "load",
            "print",
            "read",
            "jump",
            "jeq",
            "jne",
            "exit"
        ]
        self.instructions = {
            0:self.default2reg, #mov
            1:self.default3reg, #add
            2:self.default3imm, #add
            3:self.default3reg, #sub
            4:self.default3imm, #sub
            5:self.default3reg, #mul
            6:self.default3imm, #mul
            7:self.default3reg, #div
            8:self.default3imm, #div
            9:self.default3reg, #and
            10:self.default3imm,#and
            11:self.default3reg,#or
            12:self.default3imm,#or
            13:self.default3reg,#xor
            14:self.default3imm,#xor
            15:self.default2reg,#cmp0
            16:self.default2imm,#not
            17:self.default2reg,#store
            18:self.default2imm,#store
            19:self.default2reg,#load
            20:self.load_imm,#load
            21:self.default1reg,#print
            22:self.default1imm,#read
            23:self.jump,
            24:self.jeq,
            25:self.jne,
            26:self.exit
        }

    def disasm(self,data,addr):
        instr = LuckyVMInstr(data)
        return self.instructions[instr.opcode](instr,addr)

    def default1reg(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        return tokens, []

    def default1imm(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(instr.operand1),instr.operand1))
        return tokens, []

    def default2reg(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg2 = f"r{instr.operand2}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
        return tokens, []

    def default3reg(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg2 = f"r{instr.operand2}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg3 = f"r{instr.operand3}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg3))
        return tokens, []

    def default2imm(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(instr.operand2),instr.operand3))
        return tokens, []

    def load_imm(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken,hex(instr.operand2),instr.operand3))
        return tokens, []

    def default3imm(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        reg1 = f"r{instr.operand1}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg1))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg2 = f"r{instr.operand2}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(instr.operand3),instr.operand3))
        return tokens, []

    def jump(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        target = self.BASE + instr.operand1
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(target),target))
        return tokens,[(BranchType.TrueBranch,target)]

    def jeq(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        target = self.BASE + instr.operand1
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(target),target))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))

        reg2 = f"r{instr.operand2}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg3 = f"r{instr.operand3}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg3))
        
        return tokens,[(BranchType.TrueBranch,target),(BranchType.FalseBranch,addr+7)]

    def jne(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        target = self.BASE + instr.operand1
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(target),target))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))

        reg2 = f"r{instr.operand2}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg2))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        reg3 = f"r{instr.operand3}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,reg3))
        
        return tokens,[(BranchType.FalseBranch,target),(BranchType.TrueBranch,addr+7)]

    def exit(self, instr, addr):
        nmem = self.instruction_list[instr.opcode]+" "
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken,nmem)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(instr.operand1),instr.operand1))
        return tokens, [(BranchType.FunctionReturn,None)]

class LuckyVMLifter():
    def __init__(self):
        self.instruction_list = [
            "mov",
            "add",
            "add",
            "sub",
            "sub",
            "mul",
            "mul",
            "div",
            "div",
            "and",
            "and",
            "or",
            "or",
            "xor",
            "xor",
            "cmp0",
            "not",
            "store",
            "store",
            "load",
            "load",
            "print",
            "read",
            "jump",
            "jeq",
            "jne",
            "exit"
        ]
        self.instructions = {
            0:self.unimplimented, #mov
            1:self.add_reg, #add
            2:self.add_imm, #add
            3:self.sub_reg, #sub
            4:self.sub_imm, #sub
            5:self.mul_reg, #mul
            6:self.mul_imm, #mul
            7:self.unimplimented, #div
            8:self.unimplimented, #div
            9:self.and_reg, #and
            10:self.and_imm,#and
            11:self.or_reg,#or
            12:self.or_imm,#or
            13:self.xor_reg,#xor
            14:self.xor_imm,#xor
            15:self.unimplimented,#cmp0
            16:self.unimplimented,#not
            17:self.store_reg,#store
            18:self.store_imm,#store
            19:self.load_reg,#load
            20:self.load_imm,#load
            21:self.unimplimented,#print
            22:self.unimplimented,#read
            23:self.unimplimented,
            24:self.jeq,
            25:self.jne,
            26:self.unimplimented
        }

    def lift(self,data,addr, il):
        instr = LuckyVMInstr(data)
        return self.instructions[instr.opcode](instr,addr,il)

    def unimplimented(self,instr, addr,il):
       il.append(il.unimplemented())
       return 7

    def sub_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.sub(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def add_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.add(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def add_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.add(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7
    
    def sub_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.sub(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7

    def mul_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.mult(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7

    def xor_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.xor_expr(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7

    def or_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.or_expr(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7

    def and_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        src2_reg = f"r{instr.operand3}"
        expr = il.set_reg(2,dest_reg,il.and_expr(2, il.reg(2,src_reg),il.reg(2,src2_reg)))
        il.append(expr)
        return 7

    def mul_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.mult(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def xor_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.xor_expr(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def or_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.or_expr(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def and_imm(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.and_expr(2, il.reg(2,src_reg),il.const(2,instr.operand3)))
        il.append(expr)
        return 7

    def load_imm(self,instr,addr,il):
        reg = f"r{instr.operand1}"
        expr = il.set_reg(2,reg,il.load(2, il.const_pointer(2,instr.operand2)))
        il.append(expr)
        return 7

    def load_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.set_reg(2,dest_reg,il.load(2, il.reg(2,src_reg)))
        il.append(expr)
        return 7

    def store_imm(self,instr,addr,il):
        reg = f"r{instr.operand1}"
        expr = il.store(2,il.reg(2,reg), il.const_pointer(2,instr.operand2))
        il.append(expr)
        return 7

    def store_reg(self,instr,addr,il):
        dest_reg = f"r{instr.operand1}"
        src_reg = f"r{instr.operand2}"
        expr = il.store(2,il.reg(2,dest_reg), il.reg(2,src_reg))
        il.append(expr)
        return 7

    def jne(self,instr,addr,il):
        target = instr.operand1
        reg1 = il.reg(2,f"r{instr.operand2}")
        reg2 = il.reg(2,f"r{instr.operand3}")
        cond = il.compare_not_equal(2,reg1,reg2)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(cond,t,f))
        il.mark_label(t)
        il.append(il.jump(il.const_pointer(2,target)))
        il.mark_label(f)
        return 7

    def jeq(self,instr,addr,il):
        target = instr.operand1
        reg1 = il.reg(2,f"r{instr.operand2}")
        reg2 = il.reg(2,f"r{instr.operand3}")
        cond = il.compare_equal(2,reg1,reg2)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(cond,t,f))
        il.mark_label(t)
        il.append(il.jump(il.const_pointer(2,target)))
        il.mark_label(f)
        return 7



class LuckyVMArch(Architecture):
    name = "luckyvm"
    default_int_size = 2
    address_size = 2
    max_instr_length = 7

    endianness = Endianness.BigEndian
    stack_pointer = "sp"
    regs = {
        "r0" : RegisterInfo("r0",2),
        "r1" : RegisterInfo("r1",2),
        "r2" : RegisterInfo("r2",2),
        "r3" : RegisterInfo("r3",2),
        "r4" : RegisterInfo("r4",2),
        "r5" : RegisterInfo("r5",2),
        "sp" : RegisterInfo("sp",2),
        "pc" : RegisterInfo("pc",2),
    }

    def __init__(self):
        super().__init__()
        self.disassembler = LuckyVMDisasm()
        self.lifter = LuckyVMLifter()

    def get_instruction_info(self,data,addr):
        result = InstructionInfo(7)
        _, branch_info = self.disassembler.disasm(data,addr)
        for b_info in branch_info:
            if b_info[1] is not None:
                result.add_branch(b_info[0],b_info[1])
            else:
                result.add_branch(b_info[0])
        return result

    def get_instruction_text(self,data,addr):
        tokens,_ = self.disassembler.disasm(data,addr)
        return tokens,7
    
    def get_instruction_low_level_il(self,data,addr,il):
        return self.lifter.lift(data,addr,il)

class LuckyVMLoader(BinaryView):
    name = "luckyvm"
    long_name = "luckyvm loader"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls,data):
        return data.file.filename.endswith(".lvm")

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def init(self):
        self.platform = Architecture['luckyvm'].standalone_platform
        self.arch = Architecture['luckyvm']

        self.add_auto_segment(0,len(self.raw),0,len(self.raw),SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable|SegmentFlag.SegmentExecutable)
        self.add_auto_section(".code",0,len(self.raw),SectionSemantics.DefaultSectionSemantics)

        self.entry_addr = 0

        return True

LuckyVMArch.register()
LuckyVMLoader.register()