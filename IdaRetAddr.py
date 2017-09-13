import idaapi
import idc

# each item described as:
# [ delta, [ opcode(s) ] ]
#FF10             call        d,[eax]
#FF5000           call        d,[eax][0]
#FF9044332211     call        d,[eax][011223344]
#FF1500000100     call        d,[000010000]
#FF9300000000     call        d,[ebx][0]
#FF10             call        d,[eax]
CallPattern = \
[
    [-2, [0xFF] ],
    [-3, [0xFF] ],
    [-5, [0xE8] ],               
    [-6, [0xFF] ],
]

def IsPrevInsnCall(ea):
    """
    Given a return address, this function tries to check if previous instruction
    is a CALL instruction
    """
    global CallPattern
    for p in CallPattern:
        # assume caller's ea
        caller = ea + p[0]
        # get the bytes
        bytes = [x for x in GetDataList(caller, len(p[1]), 1)]
        # do we have a match? is it a call instruction?
        if bytes == p[1] and idaapi.is_call_insn(caller):
            return caller
    return False


def CreateCommentString(caller, sp):
    func = idaapi.get_func(caller)
    st = "return address from %08x: " % caller
    if func:
        st += idc.GetFunctionName(caller)
    t = caller - func.startEA
    if t > 0:
        st += "+" + hex(t)
    else:
        st += hex(caller)
        st += " [" + hex(sp) + "]"
    return st


def RetAddrStackWalk(nn, long_size):
    # get stack pointer
    if long_size == 8:
        sp = cpu.Rsp
    else:
        sp = cpu.Esp
    seg = idaapi.getseg(sp)
    if not seg:
        return (False, "Could not locate stack segment!")
    
    stack_seg_end = seg.endEA
    
    for sp in range(cpu.Esp, stack_seg_end + long_size, long_size):
        if long_size == 8:
            ptr = idc.Qword(sp)
        else:
            ptr = idc.Dword(sp)
        seg = idaapi.getseg(ptr)
        # only accept executable segments
        if (not seg) or ((seg.perm & idaapi.SEGPERM_EXEC) == 0):
            continue
        # try to find caller
        caller = IsPrevInsnCall(ptr)
        # we have no recognized caller, skip!
        if not caller:
            continue

        # do we have a debug name that is near?
        if nn:
            near = nn.find(caller)
            if near:
                # function exists?
                f = idaapi.get_func(near[0])
                if not f:
                    # create function
                    idc.MakeFunction(near[0], idaapi.BADADDR)

        # get the flags
        f = idc.GetFlags(caller)
        # no code there?
        if not isCode(f):
            MakeCode(caller)

        idc.SetColor(sp, idc.CIC_ITEM, 0xc7c7ff)
        idc.MakeRptCmt(sp, CreateCommentString(caller, sp))


def main():
    if not idaapi.is_debugger_on():
        idc.Warning("Please run the process first!")
        return
    if idaapi.get_process_state() != -1:
        idc.Warning("Please suspend the debugger first!")
        return
    
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        long_size = 8
    elif info.is_32bit():
        long_size = 4
    else:
        idc.Warning("Only 32 or 64 bit is supported!")
        return
    
    # only avail from IdaPython r232
    if hasattr(idaapi, "NearestName"):
        # get all debug names
        dn = idaapi.get_debug_names(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA)
        # initiate a nearest name search (using debug names)
        nn = idaapi.NearestName(dn)
    else:
        nn = None

    RetAddrStackWalk(nn, long_size)

main()
