# -*- coding: utf-8 -*-

# Keypatch IDA Plugin, powered by Keystone Engine (http://www.keystone-engine.org).
# By Nguyen Anh Quynh & Thanh Nguyen, 2018.

# Keypatch is released under the GPL v2. See COPYING for more information.
# Find docs & latest version at http://keystone-engine.org/keypatch

# This IDA plugin includes 3 tools inside: Patcher, Fill Range & Search.
# Access to these tools via menu "Edit | Keypatch", or via right-click popup menu "Keypatch".

# Hotkey Ctrl-Alt-K opens either Patcher or "Fill Range" window, depending on context.
#  - If there is no code selection, hotkey opens Patcher dialog
#  - If a range of code is selected, hotkey opens "Fill Range" dialog

# To revert (undo) the last patching, choose menu "Edit | Keypatch | Undo last patching".
# To check for update version, choose menu "Edit | Keypatch | Check for update".

'''
    Do not use shortcut(Ctrk + Alt + K) for debugging, otherwise debugging features will not be available.
'''
#########################################################################################################
is_debug = False
if is_debug:
    ''' 
        Install pydevd:

        1. sudo pip install pydevd

        or

        2. Install pycharm-debug.egg, Ensure to use pycharm pro
        https://www.jetbrains.com/help/pycharm/remote-debugging-with-product.html

        # import site
        # site.addsitedir("/usr/local/lib/python2.7/site-packages")
    '''
    try:
        import pydevd

        pydevd.settrace(host='localhost',
                        port=51234,
                        stdoutToServer=True,
                        stderrToServer=True
                        )
    except Exception as e:
        print(e)
#########################################################################################################

import os
import re
import json
from keystone import *
import idc
import idaapi
from idc import GetOpType, GetOpnd, ItemEnd

# bleeding-edge version
# on a new release, this should be sync with VERSION_STABLE file
VERSION = "2.2"


MAX_INSTRUCTION_STRLEN = 256
MAX_ENCODING_LEN = 40
MAX_ADDRESS_LEN = 40
ENCODING_ERR_OUTPUT = "..."
KP_GITHUB_VERSION = "https://raw.githubusercontent.com/keystone-engine/keypatch/master/VERSION_STABLE"
KP_HOMEPAGE = "http://keystone-engine.org/keypatch"

X86_NOP = "\x90"

# Configuration file
KP_CFGFILE = os.path.join(idaapi.get_user_idadir(), "keypatch.cfg")

# save all the info on patching
patch_info = []


def to_hexstr(buf, sep=' '):
    return sep.join("{0:02x}".format(ord(c)) for c in buf).upper()


# return a normalized code, or None if input is invalid
def convert_hexstr(code):
    # normalize code
    code = code.lower()
    code = code.replace(' ', '')    # remove space
    code = code.replace('h', '')    # remove trailing 'h' in 90h
    code = code.replace('0x', '')   # remove 0x
    code = code.replace('\\x', '')  # remove \x
    code = code.replace(',', '')    # remove ,
    code = code.replace(';', '')    # remove ;
    code = code.replace('"', '')    # remove "
    code = code.replace("'", '')    # remove '
    code = code.replace("+", '')    # remove +

    # single-digit hexcode?
    if len(code) == 1 and ((code >= '0' and code <= '9') or (code >= 'a' and code <= 'f')):
        # stick 0 in front (so 'a' --> '0a')
        code = '0' + code

    # odd-length is invalid
    if len(code) % 2 != 0:
        return None

    try:
        hex_data = code.decode('hex')
        # we want a list of int
        return [ord(i) for i in hex_data]
    except:
        # invalid hex
        return None


# download a file from @url, then return (result, file-content)
# return (0, content) on success, or ({1|2}, None) on download failure
def url_download(url):
    from urllib2 import Request, urlopen, URLError, HTTPError

    # create the url and the request
    req = Request(url)

    # Open the url
    try:
        # download this URL
        f = urlopen(req)
        content = f.read()
        return (0, content)

    # handle errors
    except HTTPError, e:
        # print "HTTP Error:", e.code , url
        # fail to download this file
        return (1, None)
    except URLError, e:
        # print "URL Error:", e.reason , url
        # fail to download this file
        return (1, None)
    except Exception as e:
        # fail to save the downloaded file
        # print("Error:", e)
        return (2, None)


def get_name_value(_from, name):
    """
    Fixed: the return value truncated(32 bit) of get_name_value function that analyzed 64 bit binary file about ida64 for win.

    eg:
    type == idaapi.NT_BYTE
    (type, value) = idaapi.get_name_value(idc.BADADDR, "wcschr") # ida64 for win

    value = 0x14003d3f0L is correct  ida64 > 7.x for macOS
    value = 0x4003d3f0L is truncated ida64 >= 6.x for win, ida64 == 6.x for macOS

    :param _from: ea
    :param name: name string
    :return: tuple
    """
    (type, value) = idaapi.get_name_value(_from, name)
    if type == idaapi.NT_BYTE:  # type is byte name (regular name)
        value = idaapi.get_name_ea(_from, name)
    return (type, value)


## Main Keypatch class
class Keypatch_Asm:
    # supported architectures
    arch_lists = {
        "X86 16-bit": (KS_ARCH_X86, KS_MODE_16),                # X86 16-bit
        "X86 32-bit": (KS_ARCH_X86, KS_MODE_32),                # X86 32-bit
        "X86 64-bit": (KS_ARCH_X86, KS_MODE_64),                # X86 64-bit
        "ARM": (KS_ARCH_ARM, KS_MODE_ARM),                      # ARM
        "ARM Thumb": (KS_ARCH_ARM, KS_MODE_THUMB),              # ARM Thumb
        "ARM64 (ARMV8)": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),# ARM64
        "Hexagon": (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),       # Hexagon
        "Mips32": (KS_ARCH_MIPS, KS_MODE_MIPS32),               # Mips32
        "Mips64": (KS_ARCH_MIPS, KS_MODE_MIPS64),               # Mips64
        "PowerPC 32": (KS_ARCH_PPC, KS_MODE_PPC32),             # PPC32
        "PowerPC 64": (KS_ARCH_PPC, KS_MODE_PPC64),             # PPC64
        "Sparc 32": (KS_ARCH_SPARC, KS_MODE_SPARC32),           # Sparc32
        "Sparc 64": (KS_ARCH_SPARC, KS_MODE_SPARC64),           # Sparc64
        "SystemZ": (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN),       # SystemZ
    }

    endian_lists = {
        "Little Endian": KS_MODE_LITTLE_ENDIAN,                 # little endian
        "Big Endian": KS_MODE_BIG_ENDIAN,                       # big endian
    }

    syntax_lists = {
        "Intel": KS_OPT_SYNTAX_INTEL,
        "Nasm": KS_OPT_SYNTAX_NASM,
        "AT&T": KS_OPT_SYNTAX_ATT
    }

    def __init__(self, arch=None, mode=None):
        # update current arch and mode
        self.update_hardware_mode()

        # override arch & mode if provided
        if arch is not None:
            self.arch = arch
        if mode is not None:
            self.mode = mode

        # IDA uses Intel syntax by default
        self.syntax = KS_OPT_SYNTAX_INTEL

    # return Keystone arch & mode (with endianess included)
    @staticmethod
    def get_hardware_mode():
        (arch, mode) = (None, None)

        # heuristically detect hardware setup
        info = idaapi.get_inf_structure()
        
        try:
            cpuname = info.procname.lower()
        except:
            cpuname = info.procName.lower()

        try:
            # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
            is_be = idaapi.cvar.inf.is_be()
        except:
            # older IDA versions
            is_be = idaapi.cvar.inf.mf
        # print("Keypatch BIG_ENDIAN = %s" %is_be)
        
        if cpuname == "metapc":
            arch = KS_ARCH_X86
            if info.is_64bit():
                mode = KS_MODE_64
            elif info.is_32bit():
                mode = KS_MODE_32
            else:
                mode = KS_MODE_16
        elif cpuname.startswith("arm"):
            # ARM or ARM64
            if info.is_64bit():
                arch = KS_ARCH_ARM64
                if is_be:
                    mode = KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_LITTLE_ENDIAN
            else:
                arch = KS_ARCH_ARM
                # either big-endian or little-endian
                if is_be:
                    mode = KS_MODE_ARM | KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("sparc"):
            arch = KS_ARCH_SPARC
            if info.is_64bit():
                mode = KS_MODE_SPARC64
            else:
                mode = KS_MODE_SPARC32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("ppc"):
            arch = KS_ARCH_PPC
            if info.is_64bit():
                mode = KS_MODE_PPC64
            else:
                mode = KS_MODE_PPC32
            if cpuname == "ppc":
                # do not support Little Endian mode for PPC
                mode += KS_MODE_BIG_ENDIAN
        elif cpuname.startswith("mips"):
            arch = KS_ARCH_MIPS
            if info.is_64bit():
                mode = KS_MODE_MIPS64
            else:
                mode = KS_MODE_MIPS32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("systemz") or cpuname.startswith("s390x"):
            arch = KS_ARCH_SYSTEMZ
            mode = KS_MODE_BIG_ENDIAN

        return (arch, mode)

    def update_hardware_mode(self):
        (self.arch, self.mode) = self.get_hardware_mode()

    # normalize assembly code
    # remove comment at the end of assembly code
    @staticmethod
    def asm_normalize(text):
        text = ' '.join(text.split())
        if text.rfind(';') != -1:
            return text[:text.rfind(';')].strip()

        return text.strip()

    @staticmethod
    # check if input address is valid
    # return
    #       -1  invalid address at target binary
    #        0  type mismatch of input address
    #        1  valid address at target binary
    def check_address(address):
        try:
            if idaapi.isEnabled(address):
                return 1
            else:
                return -1
        except:
            # invalid type
            return 0

    ### resolve IDA names from input asm code
    # todo: a better syntax parser for all archs
    def ida_resolve(self, assembly, address=idc.BADADDR):
        def _resolve(_op, ignore_kw=True):
            names = re.findall(r"[\$a-z0-9_:\.]+", _op, re.I)

            # try to resolve all names
            for name in names:
                # ignore known keywords
                if ignore_kw and name in ('byte', 'near', 'short', 'word', 'dword', 'ptr', 'offset'):
                    continue

                sym = name

                # split segment reg
                parts = name.partition(':')
                if parts[2] != '':
                    sym = parts[2]

                (type, value) = get_name_value(address, sym)

                # skip if name doesn't exist or segment / segment registers
                if type in (idaapi.NT_SEG, idaapi.NT_NONE):
                    continue

                _op = _op.replace(sym, '0x{0:X}'.format(value))

            return _op

        if self.check_address(address) == 0:
            print("Keypatch: WARNING: invalid input address {0}".format(address))
            return assembly

        # for now, we only support IDA name resolve for X86, ARM, ARM64, MIPS, PPC, SPARC
        if not (self.arch in (KS_ARCH_X86, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_PPC, KS_ARCH_SPARC)):
            return assembly

        _asm = assembly.partition(' ')
        mnem = _asm[0]
        opers = _asm[2].split(',')

        for idx, op in enumerate(opers):
            _op = list(op.partition('['))
            ignore_kw = True
            if _op[1] == '':
                _op[2] = _op[0]
                _op[0] = ''
            else:
                _op[0] = _resolve(_op[0], ignore_kw=True)
                ignore_kw = False

            _op[2] = _resolve(_op[2], ignore_kw=ignore_kw)

            opers[idx] = ''.join(_op)

        asm = "{0} {1}".format(mnem, ','.join(opers))
        return asm

    # return bytes of instruction or data
    # return None on failure
    def ida_get_item(self, address, hex_output=False):
        if self.check_address(address) != 1:
            # not a valid address
            return (None, 0)

        # return None if address is in the middle of instruction / data
        if address != idc.ItemHead(address):
            return (None, 0)

        len = idc.ItemSize(address)
        item = idaapi.get_many_bytes(address, len)

        if item is None:
            return (None, 0)

        if hex_output:
            item = to_hexstr(item)

        return (item, len)

    @staticmethod
    def get_op_dtype_name(op_idx):
        dtyp_lists = {
            idaapi.dt_byte: 'byte',     #  8 bit
            idaapi.dt_word: 'word',     #  16 bit
            idaapi.dt_dword: 'dword',   #  32 bit
            idaapi.dt_float: 'dword',   #  4 byte
            idaapi.dt_double: 'dword',  #  8 byte
            #idaapi.dt_tbyte = 5        #  variable size (ph.tbyte_size)
            #idaapi.dt_packreal = 6         #  packed real format for mc68040
            idaapi.dt_qword: 'qword',   #  64 bit
            idaapi.dt_byte16: 'xmmword',#  128 bit
            #idaapi.dt_code = 9         #  ptr to code (not used?)
            #idaapi.dt_void = 10        #  none
            #idaapi.dt_fword = 11       #  48 bit
            #idaapi.dt_bitfild = 12     #  bit field (mc680x0)
            #idaapi.dt_string = 13      #  pointer to asciiz string
            #idaapi.dt_unicode = 14     #  pointer to unicode string
            #idaapi.dt_3byte = 15       #  3-byte data
            #idaapi.dt_ldbl = 16        #  long double (which may be different from tbyte)
            idaapi.dt_byte32: 'ymmword',# 256 bit
        }

        dtype = idaapi.cmd.Operands[op_idx].dtyp
        dtyp_size = idaapi.get_dtyp_size(dtype)
        if dtype == idaapi.dt_tbyte:
            if dtyp_size == 10:
                return 'xword'

        dtyp_name = dtyp_lists.get(idaapi.cmd.Operands[op_idx].dtyp, None)

        return dtyp_name

    # return asm instructions from start to end
    def ida_get_disasm_range(self, start, end):
        codes = []
        while start < end:
            asm = self.asm_normalize(idc.GetDisasm(start))
            if asm == None:
                asm = ''
            codes.append(asm)
            start = start + idc.ItemSize(start)

        return codes

    # get disasm from IDA
    # return '' on invalid address
    def ida_get_disasm(self, address, fixup=False):

        def GetMnem(asm):
            sp = asm.find(' ')
            if sp == -1:
                return asm
            return asm[:sp]

        if self.check_address(address) != 1:
            # not a valid address
            return ''

        # return if address is in the middle of instruction / data
        if address != idc.ItemHead(address):
            return ''

        asm = self.asm_normalize(idc.GetDisasm(address))
        # for now, only support IDA syntax fixup for Intel CPU
        if not fixup or self.arch != KS_ARCH_X86:
            return asm

        # KS_ARCH_X86 mode
        # rebuild disasm code from IDA
        i = 0
        mnem = GetMnem(asm)
        if mnem == '' or mnem in ('rep', 'repne', 'repe'):
            return asm

        opers = []
        while GetOpType(address, i) > 0 and i < 6:
            t = GetOpType(address, i)
            o = GetOpnd(address, i)

            if t in (idc.o_mem, idc.o_displ):
                parts = list(o.partition(':'))
                if parts[2] == '':
                    parts[2] = parts[0]
                    parts[0] = ''

                if '[' not in parts[2]:
                    parts[2] = '[{0}]'.format(parts[2])

                o = ''.join(parts)

                if 'ptr ' not in o:
                    dtyp_name = self.get_op_dtype_name(i)
                    if dtyp_name != None:
                        o = "{0} ptr {1}".format(dtyp_name, o)

            opers.append(o)
            i += 1

        asm = mnem
        for o in opers:
            if o != '':
                asm = "{0} {1},".format(asm, o)

        asm = asm.strip(',')
        return asm

    # assemble code with Keystone
    # return (encoding, count), or (None, 0) on failure
    def assemble(self, assembly, address, arch=None, mode=None, syntax=None):

        # return assembly with arithmetic equation evaluated
        def eval_operand(assembly, start, stop, prefix=''):
            imm = assembly[start+1:stop]
            try:
                eval_imm = eval(imm)
                if eval_imm > 0x80000000:
                    eval_imm = 0xffffffff - eval_imm
                    eval_imm += 1
                    eval_imm = -eval_imm
                return assembly.replace(prefix + imm, prefix + hex(eval_imm))
            except:
                return assembly

        # IDA uses different syntax from Keystone
        # sometimes, we can convert code to be consumable by Keystone
        def fix_ida_syntax(assembly):

            # return True if this insn needs to be fixed
            def check_arm_arm64_insn(arch, mnem):
                if arch == KS_ARCH_ARM:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return False
                elif arch == KS_ARCH_ARM64:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return mnem in ("stp")
                return False

            # return True if this insn needs to be fixed
            def check_ppc_insn(mnem):
                return mnem in ("stw")

            # replace the right most string occurred
            def rreplace(s, old, new):
                li = s.rsplit(old, 1)
                return new.join(li)

            # convert some ARM pre-UAL assembly to UAL, so Keystone can handle it
            # example: streqb --> strbeq
            def fix_arm_ual(mnem, assembly):
                # TODO: this is not an exhaustive list yet
                if len(mnem) != 6:
                    return assembly

                if (mnem[-1] in ('s', 'b', 'h', 'd')):
                    #print(">> 222", mnem[3:5])
                    if mnem[3:5] in ("cc", "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"):
                        return assembly.replace(mnem, mnem[:3] + mnem[-1] + mnem[3:5], 1)

                return assembly

            if self.arch != KS_ARCH_X86:
                assembly = assembly.lower()
            else:
                # Keystone does not support immediate 0bh, but only 0Bh
                assembly = assembly.upper()

            # however, 0X must be converted to 0x
            # Keystone should fix this limitation in the future
            assembly = assembly.replace("0X", " 0x")

            _asm = assembly.partition(' ')
            mnem = _asm[0]
            if mnem == '':
                return assembly

            # for PPC, Keystone does not accept registers with 'r' prefix,
            # but only the number behind. lets try to fix that here by
            # removing the prefix 'r'.
            if self.arch == KS_ARCH_PPC:
                for n in range(32):
                    r = " r%u," %n
                    if r in assembly:
                        assembly = assembly.replace(r, " %u," %n)
                for n in range(32):
                    r = "(r%u)" %n
                    if r in assembly:
                        assembly = assembly.replace(r, "(%u)" %n)
                for n in range(32):
                    r = ", r%u" %n
                    if assembly.endswith(r):
                        assembly = rreplace(assembly, r, ", %u" %n)

            if self.arch == KS_ARCH_X86:
                if mnem == "RETN":
                    # replace retn with ret
                    return assembly.replace('RETN', 'RET', 1)
                if 'OFFSET ' in assembly:
                    return assembly.replace('OFFSET ', ' ')
                if mnem in ('CALL', 'JMP') or mnem.startswith('LOOP'):
                    # remove 'NEAR PTR'
                    if ' NEAR PTR ' in assembly:
                        return assembly.replace(' NEAR PTR ', ' ')
                elif mnem[0] == 'J':
                    # JMP instruction
                    if ' SHORT ' in assembly:
                        # remove ' short '
                        return assembly.replace(' SHORT ', ' ')
            elif self.arch in (KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_PPC):
                # *** ARM
                # LDR     R1, [SP+rtld_fini],#4
                # STR     R2, [SP,#-4+rtld_fini]!
                # STR     R0, [SP,#fini]!
                # STR     R12, [SP,#4+var_8]!

                # *** ARM64
                # STP     X29, X30, [SP,#-0x10+var_150]!
                # STR     W0, [X29,#0x150+var_8]
                # LDR     X0, [X0,#(qword_4D6678 - 0x4D6660)]
                # TODO:
                # ADRP    X19, #interactive@PAGE

                # *** PPC
                # stw     r5, 0x120+var_108(r1)
                
                if self.arch == KS_ARCH_ARM and mode == KS_MODE_THUMB:
                    assembly = assembly.replace('movt.w', 'movt')

                if self.arch == KS_ARCH_ARM:
                    #print(">> before UAL fix: ", assembly)
                    assembly = fix_arm_ual(mnem, assembly)
                    #print(">> after UAL fix: ", assembly)

                if check_arm_arm64_insn(self.arch, mnem) or (("[" in assembly) and ("]" in assembly)):
                    bang = assembly.find('#')
                    bracket = assembly.find(']')
                    if bang != -1 and bracket != -1 and bang < bracket:
                        return eval_operand(assembly, bang, bracket, '#')
                    elif '+0x0]' in assembly:
                        return assembly.replace('+0x0]', ']')
                elif check_ppc_insn(mnem):
                    start = assembly.find(', ')
                    stop = assembly.find('(')
                    if start != -1 and stop != -1 and start < stop:
                        return eval_operand(assembly, start, stop)
            return assembly

        def is_thumb(address):
            return idc.GetReg(address, 'T') == 1

        if self.check_address(address) == 0:
            return (None, 0)

        # use default syntax, arch and mode if not provided
        if syntax is None:
            syntax = self.syntax
        if arch is None:
            arch = self.arch
        if mode is None:
            mode = self.mode

        if arch == KS_ARCH_ARM and is_thumb(address):
            mode = KS_MODE_THUMB

        try:
            ks = Ks(arch, mode)
            if arch == KS_ARCH_X86:
                ks.syntax = syntax
            encoding, count = ks.asm(fix_ida_syntax(assembly), address)
        except KsError as e:
            # keep the below code for debugging
            #print("Keypatch Error: {0}".format(e))
            #print("Original asm: {0}".format(assembly))
            #print("Fixed up asm: {0}".format(fix_ida_syntax(assembly)))
            encoding, count = None, 0

        return (encoding, count)


    # patch at address, return the number of written bytes & original data
    # this process can fail in some cases
    @staticmethod
    def patch_raw(address, patch_data, len):
        ea = address
        orig_data = ''

        while ea < (address + len):

            if not idc.hasValue(idc.GetFlags(ea)):
                print("Keypatch: FAILED to read data at 0x{0:X}".format(ea))
                break

            orig_byte = idc.Byte(ea)
            orig_data += chr(orig_byte)
            patch_byte = ord(patch_data[ea - address])

            if patch_byte != orig_byte:
                # patch one byte
                if idaapi.patch_byte(ea, patch_byte) != 1:
                    print("Keypatch: FAILED to patch byte at 0x{0:X} [0x{1:X}]".format(ea, patch_byte))
                    break
            ea += 1
        return (ea - address, orig_data)

    # patch at address, return the number of written bytes & original data
    # on patch failure, we revert to the original code, then return (None, None)
    def patch(self, address, patch_data, len):
        # save original function end to fix IDA re-analyze issue after patching
        orig_func_end = idc.GetFunctionAttr(address, idc.FUNCATTR_END)

        (patched_len, orig_data) = self.patch_raw(address, patch_data, len)

        if len != patched_len:
            # patch failure
            if patched_len > 0:
                # revert the changes
                (rlen, _) = self.patch_raw(address, orig_data, patched_len)
                if rlen == patched_len:
                    print("Keypatch: successfully reverted changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                                        patched_len, address, to_hexstr(orig_data)))
                else:
                    print("Keypatch: FAILED to revert changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                                        patched_len, address, to_hexstr(orig_data)))

            return (None, None)

        # ask IDA to re-analyze the patched area
        if orig_func_end == idc.BADADDR:
            # only analyze patched bytes, otherwise it would take a lot of time to re-analyze the whole binary
            idaapi.analyze_area(address, address + patched_len + 1)
        else:
            idaapi.analyze_area(address, orig_func_end)

            # try to fix IDA function re-analyze issue after patching
            idaapi.func_setend(address, orig_func_end)

        return (patched_len, orig_data)

    # return number of bytes patched
    # return
    #    0  Invalid assembly
    #   -1  PatchByte failure
    #   -2  Can't read original data
    #   -3  Invalid address
    def patch_code(self, address, assembly, syntax, padding, save_origcode, orig_asm=None, patch_data=None, patch_comment=None, undo=False):
        global patch_info

        if self.check_address(address) != 1:
            # not a valid address
            return -3

        orig_comment = idc.Comment(address)
        if orig_comment is None:
            orig_comment = ''

        nop_comment = ""
        padding_len = 0
        if not undo:
            # we are patching via Patcher
            (orig_encoding, orig_len) = self.ida_get_item(address)
            if (orig_encoding, orig_len) == (None, 0):
                return -2

            (encoding, count) = self.assemble(assembly, address, syntax=syntax)
            if encoding is None:
                return 0

            patch_len = len(encoding)
            patch_data = ''.join(chr(c) for c in encoding)

            if patch_data == orig_encoding:
                #print("Keypatch: no need to patch, same encoding data [{0}] at 0x{1:X}".format(to_hexstr(orig_encoding), address))
                return orig_len

            # for now, only support NOP padding on Intel CPU
            if padding and self.arch == KS_ARCH_X86:
                if patch_len < orig_len:
                    padding_len = orig_len - patch_len
                    patch_len = orig_len
                    patch_data = patch_data.ljust(patch_len, X86_NOP)
                elif patch_len > orig_len:
                    patch_end = address + patch_len - 1
                    ins_end = ItemEnd(patch_end)
                    padding_len = ins_end - patch_end - 1

                    if padding_len > 0:
                        patch_len = ins_end - address
                        patch_data = patch_data.ljust(patch_len, X86_NOP)

                if padding_len > 0:
                    nop_comment = "\nKeypatch padded NOP to next boundary: {0} bytes".format(padding_len)

            orig_asm = self.ida_get_disasm_range(address, address + patch_len)
        else:
            # we are reverting the change via "Undo" menu
            patch_len = len(patch_data)

        (plen, p_orig_data) = self.patch(address, patch_data, patch_len)
        if plen is None:
            # failed to patch
            return -1

        if not undo: # we are patching
            new_patch_comment = None
            if save_origcode is True:
                # append original instruction to comments
                if orig_comment == '':
                    new_patch_comment = "Keypatch modified this from:\n  {0}{1}".format('\n  '.join(orig_asm), nop_comment)
                else:
                    new_patch_comment = "\nKeypatch modified this from:\n  {0}{1}".format('\n  '.join(orig_asm), nop_comment)

                new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
                idc.MakeComm(address, new_comment)

            if padding_len == 0:
                print("Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))
            else:
                print("Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}], with {4} byte(s) NOP padded".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data), padding_len))
            # save this patching for future "undo"
            patch_info.append((address, assembly, p_orig_data, new_patch_comment))
        else:   # we are reverting
            if patch_comment:
                # clean previous IDA comment by replacing it with ''
                new_comment = orig_comment.replace(patch_comment, '')
                idc.MakeComm(address, new_comment)

            print("Keypatch: successfully reverted {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))

        return plen

    # fill a range of code [addr_begin, addr_end].
    # return the length of patched area
    # on failure, return 0 = wrong input, -1 = failed to patch
    def fill_code(self, addr_begin, addr_end, assembly, syntax, padding, save_origcode, orig_asm=None):
        # treat input as assembly code first
        (encoding, _) =  self.assemble(assembly, addr_begin, syntax=syntax)

        if encoding is None:
            # input might be a hexcode string. try to convert it to raw bytes
            encoding = convert_hexstr(assembly)

        if encoding is None:
            # invalid input: this is neither assembly nor hexcode string
            return 0

        # save original assembly code before overwritting them
        orig_asm = self.ida_get_disasm_range(addr_begin, addr_end)

        # save original comment at addr_begin
        # TODO: save comments in this range, but how to interleave them?
        orig_comment = idc.Comment(addr_begin)
        if orig_comment is None:
            orig_comment = ''

        patch_data = ""
        assembly_new = []
        size = addr_end - addr_begin
        # calculate filling data
        encode_chr = ''.join(chr(c) for c in encoding)
        while True:
            if len(patch_data) + len(encode_chr) <= size:
                patch_data = patch_data + encode_chr
                assembly_new += [assembly.strip()]
            else:
                break

        # for now, only support NOP padding on Intel CPU
        if padding and self.arch == KS_ARCH_X86:
            for i in range(size -len(patch_data)):
                assembly_new += ["nop"]
            patch_data = patch_data.ljust(size, X86_NOP)

        (plen, p_orig_data) = self.patch(addr_begin, patch_data, len(patch_data))
        if plen is None:
            # failed to patch
            return -1

        new_patch_comment = ''
        # append original instruction to comments
        if save_origcode is True:
            if orig_comment == '':
                new_patch_comment = "Keypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(addr_begin, addr_end - 1, addr_end - addr_begin, '\n  '.join(orig_asm))
            else:
                new_patch_comment = "\nKeypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(addr_begin, addr_end - 1, addr_end - addr_begin, '\n  '.join(orig_asm))

            new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
            idc.MakeComm(addr_begin, new_comment)

        print("Keypatch: successfully filled range [0x{0:X}:0x{1:X}] ({2} bytes) with \"{3}\", replaced \"{4}\"".format(
                    addr_begin, addr_end - 1, addr_end - addr_begin, assembly, '; '.join(orig_asm)))

        # save this modification for future "undo"
        patch_info.append((addr_begin, '\n  '.join(assembly_new), p_orig_data, new_patch_comment))

        return plen


    ### Form helper functions
    @staticmethod
    def dict_to_ordered_list(dictionary):
        list = sorted(dictionary.items(), key=lambda t: t[0], reverse=False)
        keys = [i[0] for i in list]
        values = [i[1] for i in list]

        return (keys, values)

    def get_value_by_idx(self, dictionary, idx, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            val = values[idx]
        except IndexError:
            val = default

        return val

    def find_idx_by_value(self, dictionary, value, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            idx = values.index(value)
        except:
            idx = default

        return idx

    def get_arch_by_idx(self, idx):
        return self.get_value_by_idx(self.arch_lists, idx)

    def find_arch_idx(self, arch, mode):
        return self.find_idx_by_value(self.arch_lists, (arch, mode))

    def get_syntax_by_idx(self, idx):
        return self.get_value_by_idx(self.syntax_lists, idx, self.syntax)

    def find_syntax_idx(self, syntax):
        return self.find_idx_by_value(self.syntax_lists, syntax)
    ### /Form helper functions


# Common ancestor form to be derived by Patcher, FillRange & Search
class Keypatch_Form(idaapi.Form):
    # prepare for form initializing
    def setup(self, kp_asm, address, assembly=None):
        self.kp_asm = kp_asm
        self.address = address

        # update ordered list of arch and syntax
        self.syntax_keys = self.kp_asm.dict_to_ordered_list(self.kp_asm.syntax_lists)[0]
        self.arch_keys = self.kp_asm.dict_to_ordered_list(self.kp_asm.arch_lists)[0]

        # update current arch & mode
        self.kp_asm.update_hardware_mode()

        # find right value for c_arch & c_endian controls
        mode = self.kp_asm.mode
        self.endian_id = 0   # little endian
        if self.kp_asm.mode & KS_MODE_BIG_ENDIAN:
            self.endian_id = 1   # big endian
            mode = self.kp_asm.mode - KS_MODE_BIG_ENDIAN

        self.arch_id = self.kp_asm.find_arch_idx(self.kp_asm.arch, mode)

        self.syntax_id = 0  # to make non-X86 arch happy
        if self.kp_asm.arch == KS_ARCH_X86:
            self.syntax_id = self.kp_asm.find_syntax_idx(self.kp_asm.syntax)

        # get original instruction and bytes
        self.orig_asm = kp_asm.ida_get_disasm(address)
        (self.orig_encoding, self.orig_len) = kp_asm.ida_get_item(address, hex_output=True)
        if self.orig_encoding is None:
            self.orig_encoding = ''

        if assembly is None:
            self.asm = self.kp_asm.ida_get_disasm(self.address, fixup=True)
        else:
            self.asm = assembly

    # update Encoding control
    # return True on success, False on failure
    def _update_encoding(self, arch, mode):
        try:
            syntax = None
            if arch == KS_ARCH_X86:
                syntax_id = self.GetControlValue(self.c_syntax)
                syntax = self.kp_asm.get_syntax_by_idx(syntax_id)

            address = self.GetControlValue(self.c_addr)
            try:
                idaapi.isEnabled(address)
            except:
                # invalid address value
                address = 0

            assembly = self.GetControlValue(self.c_assembly)
            raw_assembly = self.kp_asm.ida_resolve(assembly, address)
            self.SetControlValue(self.c_raw_assembly, raw_assembly)

            (encoding, count) =  self.kp_asm.assemble(raw_assembly, address, arch=arch,
                                                    mode=mode, syntax=syntax)

            if encoding is None:
                self.SetControlValue(self.c_encoding, ENCODING_ERR_OUTPUT)
                self.SetControlValue(self.c_encoding_len, 0)
                return False
            else:
                text = ""
                for byte in encoding:
                    text += "%02X " % byte
                text.strip()
                if text == "":
                    # error?
                    self.SetControlValue(self.c_encoding, ENCODING_ERR_OUTPUT)
                    return False
                else:
                    self.SetControlValue(self.c_encoding, text.strip())
                    self.SetControlValue(self.c_encoding_len, len(encoding))
                    return True
        except Exception,e:
            print (str(e))
            import traceback
            traceback.print_exc()
            self.SetControlValue(self.c_encoding, ENCODING_ERR_OUTPUT)
            return False

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        return 1

    # update Patcher & Fillrange controls
    def update_patchform(self, fid):
        self.EnableField(self.c_endian, False)
        self.EnableField(self.c_addr, False)

        (arch, mode) = (self.kp_asm.arch, self.kp_asm.mode)
        # assembly is focused
        self.SetFocusedField(self.c_assembly)

        if arch == KS_ARCH_X86:
            # do not show Endian control
            self.ShowField(self.c_endian, False)
            # allow to choose Syntax
            self.ShowField(self.c_syntax, True)
            self.ShowField(self.c_opt_padding, True)
        else:   # do not show Syntax control for non-X86 mode
            self.ShowField(self.c_syntax, False)
            # for now, we do not support padding for non-X86 archs
            self.ShowField(self.c_opt_padding, False)
            #self.EnableField(self.c_opt_padding, False)

        # update other controls & Encoding with live assembling
        self.update_controls(arch, mode)

        return 1

    # update some controls - including Encoding control
    def update_controls(self, arch, mode):
        # Fixup & Encoding-len are read-only controls
        self.EnableField(self.c_raw_assembly, False)
        self.EnableField(self.c_encoding_len, False)

        # Encoding is enable to allow user to select & copy
        self.EnableField(self.c_encoding, True)

        if self.GetControlValue(self.c_endian) == 1:
            endian = KS_MODE_BIG_ENDIAN
        else:
            endian = KS_MODE_LITTLE_ENDIAN

        # update encoding with live assembling
        self._update_encoding(arch, mode | endian)

        return 1

    # get Patcher/FillRange options
    def get_opts(self, name=None):
        names = self.c_opt_chk.children_names
        val = self.c_opt_chk.value
        opts = {}
        for i in range(len(names)):
            opts[names[i]] = val & (2**i)

        if name != None:
            opts[name] = val

        return opts


# Fill Range form
class Keypatch_FillRange(Keypatch_Form):
    def __init__(self, kp_asm, addr_begin, addr_end, assembly=None, opts=None):
        self.setup(kp_asm, addr_begin, assembly)
        self.addr_end = addr_end

        # create FillRange form
        super(Keypatch_FillRange, self).__init__(
            r"""STARTITEM {id:c_assembly}
BUTTON YES* Patch
KEYPATCH:: Fill Range

            {FormChangeCb}
            <Endian     :{c_endian}>
            <~S~yntax     :{c_syntax}>
            <Start      :{c_addr}>
            <End        :{c_addr_end}>
            <Size       :{c_size}>
            <~A~ssembly   :{c_assembly}>
             <##-   Fixup :{c_raw_assembly}>
             <##-   Encode:{c_encoding}>
             <##-   Size  :{c_encoding_len}>
            <~N~OPs padding until next instruction boundary:{c_opt_padding}>
            <Save ~o~riginal instructions in IDA comment:{c_opt_comment}>{c_opt_chk}>
            """, {
            'c_endian': self.DropdownListControl(
                          items = self.kp_asm.endian_lists.keys(),
                          readonly = True,
                          selval = self.endian_id),
            'c_addr': self.NumericInput(value=addr_begin, swidth=MAX_ADDRESS_LEN, tp=self.FT_ADDR),
            'c_addr_end': self.NumericInput(value=addr_end - 1, swidth=MAX_ADDRESS_LEN, tp=self.FT_ADDR),
            'c_assembly': self.StringInput(value=self.asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_size': self.NumericInput(value=addr_end - addr_begin, swidth=8, tp=self.FT_DEC),
            'c_raw_assembly': self.StringInput(value='', width=MAX_INSTRUCTION_STRLEN),
            'c_encoding': self.StringInput(value='', width=MAX_ENCODING_LEN),
            'c_encoding_len': self.NumericInput(value=0, swidth=8, tp=self.FT_DEC),
            'c_syntax': self.DropdownListControl(
                          items = self.syntax_keys,
                          readonly = True,
                          selval = self.syntax_id),
            'c_opt_chk':idaapi.Form.ChkGroupControl(('c_opt_padding', 'c_opt_comment', ''), value=opts['c_opt_chk']),
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        # make some controls read-only in FillRange mode
        self.EnableField(self.c_size, False)
        self.EnableField(self.c_addr_end, False)

        return self.update_patchform(fid)


# Patcher form
class Keypatch_Patcher(Keypatch_Form):
    def __init__(self, kp_asm, address, assembly=None, opts=None):
        self.setup(kp_asm, address, assembly)

        # create Patcher form
        super(Keypatch_Patcher, self).__init__(
            r"""STARTITEM {id:c_assembly}
BUTTON YES* Patch
KEYPATCH:: Patcher

            {FormChangeCb}
            <Endian     :{c_endian}>
            <~S~yntax     :{c_syntax}>
            <Address    :{c_addr}>
            <Original   :{c_orig_assembly}>
             <##-   Encode:{c_orig_encoding}>
             <##-   Size  :{c_orig_len}>
            <~A~ssembly   :{c_assembly}>
             <##-   Fixup :{c_raw_assembly}>
             <##-   Encode:{c_encoding}>
             <##-   Size  :{c_encoding_len}>
            <~N~OPs padding until next instruction boundary:{c_opt_padding}>
            <Save ~o~riginal instructions in IDA comment:{c_opt_comment}>{c_opt_chk}>
            """, {
            'c_endian': self.DropdownListControl(
                          items = self.kp_asm.endian_lists.keys(),
                          readonly = True,
                          selval = self.endian_id),
            'c_addr': self.NumericInput(value=address, swidth=MAX_ADDRESS_LEN, tp=self.FT_ADDR),
            'c_assembly': self.StringInput(value=self.asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_orig_assembly': self.StringInput(value=self.orig_asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_orig_encoding': self.StringInput(value=self.orig_encoding[:MAX_ENCODING_LEN], width=MAX_ENCODING_LEN),
            'c_orig_len': self.NumericInput(value=self.orig_len, swidth=8, tp=self.FT_DEC),
            'c_raw_assembly': self.StringInput(value='', width=MAX_INSTRUCTION_STRLEN),
            'c_encoding': self.StringInput(value='', width=MAX_ENCODING_LEN),
            'c_encoding_len': self.NumericInput(value=0, swidth=8, tp=self.FT_DEC),
            'c_syntax': self.DropdownListControl(
                          items = self.syntax_keys,
                          readonly = True,
                          selval = self.syntax_id),
            'c_opt_chk':self.ChkGroupControl(('c_opt_padding', 'c_opt_comment', ''), value=opts['c_opt_chk']),
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        # make some fields read-only in Patch mode
        self.EnableField(self.c_orig_assembly, False)
        self.EnableField(self.c_orig_encoding, False)
        self.EnableField(self.c_orig_len, False)

        return self.update_patchform(fid)


# Search position chooser
class SearchResultChooser(idaapi.Choose2):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        super(SearchResultChooser, self).__init__(
            title,
            [["Address", idaapi.Choose2.CHCOL_HEX|40]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = items
        self.selcount = 0
        self.modal = modal

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.Jump(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0])]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(self.modal) >= 0


# Search form
class Keypatch_Search(Keypatch_Form):
    def __init__(self, kp_asm, address, assembly=None):
        self.setup(kp_asm, address, assembly)

        # create Search form
        super(Keypatch_Search, self).__init__(
            r"""STARTITEM {id:c_assembly}
BUTTON YES* Search
KEYPATCH:: Search

            {FormChangeCb}
            <A~r~ch       :{c_arch}>
            <E~n~dian     :{c_endian}>
            <~S~yntax     :{c_syntax}>
            <A~d~dress    :{c_addr}>
            <~A~ssembly   :{c_assembly}>
             <##-   Fixup :{c_raw_assembly}>
             <##-   Encode:{c_encoding}>
             <##-   Size  :{c_encoding_len}>
            """, {
            'c_addr': self.NumericInput(value=address, swidth=MAX_ADDRESS_LEN, tp=self.FT_ADDR),
            'c_assembly': self.StringInput(value=self.asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_raw_assembly': self.StringInput(value='', width=MAX_INSTRUCTION_STRLEN),
            'c_encoding': self.StringInput(value='', width=MAX_ENCODING_LEN),
            'c_encoding_len': self.NumericInput(value=0, swidth=8, tp=self.FT_DEC),
            'c_arch': self.DropdownListControl(
                          items = self.arch_keys,
                          readonly = True,
                          selval = self.arch_id,
                          width = 32),
            'c_endian': self.DropdownListControl(
                          items = self.kp_asm.endian_lists.keys(),
                          readonly = True,
                          selval = self.endian_id),
            'c_syntax': self.DropdownListControl(
                          items = self.syntax_keys,
                          readonly = True,
                          selval = self.syntax_id),
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        # handle the search button
        if fid == -2:
            address = 0
            addresses = []
            while address != idc.BADADDR:
                address = idc.FindBinary(address, idc.SEARCH_DOWN, self.GetControlValue(self.c_encoding))
                if address == idc.BADADDR:
                    break
                addresses.append([address])
                address = address + 1
            c = SearchResultChooser("Searching for [{0}]".format(self.GetControlValue(self.c_raw_assembly)), addresses)
            c.show()
            return 1

        # only Search mode allows to select arch+mode
        arch_id = self.GetControlValue(self.c_arch)
        (arch, mode) = self.kp_asm.get_arch_by_idx(arch_id)

        # assembly is focused
        self.SetFocusedField(self.c_assembly)

        if arch == KS_ARCH_X86:
            # enable Syntax and disable Endian for x86
            self.ShowField(self.c_syntax, True)
            self.EnableField(self.c_syntax, True)
            self.syntax_id = self.GetControlValue(self.c_syntax)
            self.EnableField(self.c_endian, False)
            # set Endian index properly
            self.SetControlValue(self.c_endian, 0)
        elif arch in (KS_ARCH_ARM64, KS_ARCH_HEXAGON, KS_ARCH_SYSTEMZ):
            # no Syntax & Endian option for these archs
            self.ShowField(self.c_syntax, False)
            self.EnableField(self.c_syntax, False)
            self.EnableField(self.c_endian, False)
            # set Endian index properly
            self.SetControlValue(self.c_endian, (mode & KS_MODE_BIG_ENDIAN != 0))
        elif (arch == KS_ARCH_PPC) and (mode & KS_MODE_PPC32 != 0):
            # no Syntax & Endian option for these archs
            self.ShowField(self.c_syntax, False)
            self.EnableField(self.c_syntax, False)
            self.EnableField(self.c_endian, False)
            # set Endian index properly
            self.SetControlValue(self.c_endian, (mode & KS_MODE_BIG_ENDIAN != 0))
        else:
            # no Syntax & Endian option
            self.ShowField(self.c_syntax, False)
            self.EnableField(self.c_syntax, False)
            self.EnableField(self.c_endian, True)

        if self.GetControlValue(self.c_endian) == 1:
            endian = KS_MODE_BIG_ENDIAN
        else:
            endian = KS_MODE_LITTLE_ENDIAN

        # update other controls & Encoding with live assembling
        self.update_controls(arch, mode)

        return 1


# About form
class About_Form(idaapi.Form):
    def __init__(self, version):
        # create About form
        super(About_Form, self).__init__(
            r"""STARTITEM 0
BUTTON YES* Open Keypatch Website
KEYPATCH:: About

            {FormChangeCb}
            Keypatch IDA plugin v%s, using Keystone Engine v%s.
            (c) Nguyen Anh Quynh + Thanh Nguyen, 2018.

            Keypatch is released under the GPL v2.
            Find more info at http://www.keystone-engine.org/keypatch
            """ %(version, keystone.__version__), {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open Keypatch homepage in a new tab, if possible
            webbrowser.open(KP_HOMEPAGE, new = 2)

        return 1


# Check-for-update form
class Update_Form(idaapi.Form):
    def __init__(self, version, message):
        # create Update form
        super(Update_Form, self).__init__(
            r"""STARTITEM 0
BUTTON YES* Open Keypatch Website
KEYPATCH:: Check for update

            {FormChangeCb}
            Your Keypatch is v%s
            %s
            """ %(version, message), {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })
        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open Keypatch homepage in a new tab, if possible
            webbrowser.open(KP_HOMEPAGE, new = 2)

        return 1


try:
    # adapted from pull request #7 by @quangnh89
    class Kp_Menu_Context(idaapi.action_handler_t):

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            try:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            except:
                # Add exception for main menu on >= IDA 7.0
                return idaapi.AST_ENABLE_ALWAYS
            
    # context menu for Patcher
    class Kp_MC_Patcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.patcher()
            return 1

    # context menu for Fill Range
    class Kp_MC_Fill_Range(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.fill_range()
            return 1

    # context menu for Undo
    class Kp_MC_Undo(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.undo()
            return 1

    # context menu for Search
    class Kp_MC_Search(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

    # context menu for Check Update
    class Kp_MC_Updater(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.updater()
            return 1

    # context menu for About
    class Kp_MC_About(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.about()
            return 1
except:
    pass


# hooks for popup menu
class Hooks(idaapi.UI_Hooks):
    if idaapi.IDA_SDK_VERSION >= 700:
        # IDA >= 700 right click widget popup
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Patcher.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Fill_Range.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Undo.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Search.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Updater.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_About.get_name(), 'Keypatch/')
                except:
                    pass
    else:
        # IDA < 700 right click popup
        def finish_populating_tform_popup(self, form, popup):
            # We'll add our action to all "IDA View-*"s.
            # If we wanted to add it only to "IDA View-A", we could
            # also discriminate on the widget's title:
            #
            #  if idaapi.get_tform_title(form) == "IDA View-A":
            #      ...
            #
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Patcher.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Fill_Range.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Undo.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Search.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_Updater.get_name(), 'Keypatch/')
                    idaapi.attach_action_to_popup(form, popup, Kp_MC_About.get_name(), 'Keypatch/')
                except:
                    pass


# check if we already initialized Keypatch
kp_initialized = False

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Keypatch_Plugin_t(idaapi.plugin_t):
    comment = "Keypatch plugin for IDA Pro (using Keystone framework)"
    help = "Find more information on Keypatch at http://keystone-engine.org/keypatch"
    wanted_name = "Keypatch Patcher"
    wanted_hotkey = "Ctrl-Alt-K"
    flags = idaapi.PLUGIN_KEEP

    def load_configuration(self):
        # default
        self.opts = {}

        # load configuration from file
        try:
            f = open(KP_CFGFILE, "rt")
            self.opts = json.load(f)
            f.close()
        except IOError:
            print("Keypatch: FAILED to load config file. Use default setup now.")
        except Exception as e:
            print("Keypatch: FAILED to load config file, with exception: {0}".format(str(e)))

        # use default values if not defined in config file
        if 'c_opt_padding' not in self.opts:
            self.opts['c_opt_padding'] = 1

        if 'c_opt_comment' not in self.opts:
            self.opts['c_opt_comment'] = 2

        self.opts['c_opt_chk'] = self.opts['c_opt_padding'] | self.opts['c_opt_comment']

    def init(self):
        global kp_initialized

        # register popup menu handlers
        try:
            Kp_MC_Patcher.register(self, "Patcher    (Ctrl-Alt-K)")
            Kp_MC_Fill_Range.register(self, "Fill Range")
            Kp_MC_Undo.register(self, "Undo last patching")
            Kp_MC_Search.register(self, "Search")
            Kp_MC_Updater.register(self, "Check for update")
            Kp_MC_About.register(self, "About")
        except:
            pass

        # setup popup menu
        self.hooks = Hooks()
        self.hooks.hook()

        self.opts = None
        if kp_initialized == False:
            kp_initialized = True

            if idaapi.IDA_SDK_VERSION >= 700:
                # Add menu IDA >= 7.0
                idaapi.attach_action_to_menu("Edit/Keypatch/Patcher", Kp_MC_Patcher.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Keypatch/About", Kp_MC_About.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Keypatch/Check for update", Kp_MC_Updater.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Keypatch/Search", Kp_MC_Search.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Keypatch/Undo last patching", Kp_MC_Undo.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Keypatch/Fill Range", Kp_MC_Fill_Range.get_name(), idaapi.SETMENU_APP)
            else:
                # add Keypatch menu
                menu = idaapi.add_menu_item("Edit/Keypatch/", "Patcher     (Ctrl-Alt-K)", "", 1, self.patcher, None)
                if menu is not None:
                    idaapi.add_menu_item("Edit/Keypatch/", "About", "", 1, self.about, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "Check for update", "", 1, self.updater, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "-", "", 1, self.menu_null, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "Search", "", 1, self.search, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "-", "", 1, self.menu_null, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "Undo last patching", "", 1, self.undo, None)
                    idaapi.add_menu_item("Edit/Keypatch/", "Fill Range", "", 1, self.fill_range, None)
                elif idaapi.IDA_SDK_VERSION < 680:
                    # older IDAPython (such as in IDAPro 6.6) does add new submenu.
                    # in this case, put Keypatch menu in menu Edit \ Patch program
                    # not sure about v6.7, so to be safe we just check against v6.8
                    idaapi.add_menu_item("Edit/Patch program/", "-", "", 0, self.menu_null, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: About", "", 0, self.about, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: Check for update", "", 0, self.updater, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: Search", "", 0, self.search, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: Undo last patching", "", 0, self.undo, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: Fill Range", "", 0, self.fill_range, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Keypatch:: Patcher     (Ctrl-Alt-K)", "", 0, self.patcher, None)

            print("=" * 80)
            print("Keypatch v{0} (c) Nguyen Anh Quynh & Thanh Nguyen, 2018".format(VERSION))
            print("Keypatch is using Keystone v{0}".format(keystone.__version__))
            print("Keypatch Patcher's shortcut key is Ctrl-Alt-K")
            print("Use the same hotkey Ctrl-Alt-K to open 'Fill Range' window on a selected range of code")
            print("To revert (undo) the last patching, choose menu Edit | Keypatch | Undo last patching")
            print("Keypatch Search is available from menu Edit | Keypatch | Search")
            print("Find more information about Keypatch at http://keystone-engine.org/keypatch")

            self.load_configuration()

            print("=" * 80)
            self.kp_asm = Keypatch_Asm()

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None

        if self.opts is None:
            return
        #save configuration to file
        try:
            json.dump(self.opts, open(KP_CFGFILE, "wt"))
        except Exception as e:
            print("Keypatch: FAILED to save config file, with exception: {0}".format(str(e)))
        else:
            print("Keypatch: configuration is saved to {0}".format(KP_CFGFILE))

    # null handler
    def menu_null(self):
        pass

    # handler for About menu
    def about(self):
        f = About_Form(VERSION)
        f.Execute()
        f.Free()

    # handler for Check-for-Update menu
    def updater(self):
        (r, content) = url_download(KP_GITHUB_VERSION)
        if r == 0:
            # find stable version
            sig = 'VERSION_STABLE = "'
            tmp = content[content.find(sig)+len(sig):]
            version_stable = tmp[:tmp.find('"')]

            # compare with the current version
            if version_stable == VERSION:
                f = Update_Form(VERSION, "Good, you are already on the latest stable version!")
                f.Execute()
                # free this form
                f.Free()
            else:
                f = Update_Form(VERSION, "Download latest stable version {0} from http://keystone-engine.org/keypatch".format(version_stable))
                f.Execute()
                # free this form
                f.Free()
        else:
            # fail to download
            idc.Warning("ERROR: Keypatch failed to connect to internet (Github). Try again later.")
            print("Keypatch: FAILED to connect to Github to check for latest update. Try again later.")

    # handler for Undo menu
    def undo(self):
        global patch_info
        if len(patch_info) == 0:
            # TODO: disable Undo menu?
            idc.Warning("ERROR: Keypatch already got to the last undo patching!")
        else:
            (address, assembly, p_orig_data, patch_comment) = patch_info[-1]

            # undo the patch
            self.kp_asm.patch_code(address, None, None, None, None, orig_asm=[assembly], patch_data=p_orig_data, patch_comment=patch_comment, undo=True)
            del(patch_info[-1])

    # handler for Search menu
    def search(self):
        address = idc.ScreenEA()
        f = Keypatch_Search(self.kp_asm, address)
        f.Execute()
        f.Free()

    # handler for Patcher menu
    def patcher(self):
        # be sure that this arch is supported by Keystone
        if self.kp_asm.arch is None:
            idc.Warning("ERROR: Keypatch cannot handle this architecture (unsupported by Keystone), quit!")
            return

        selection, addr_begin, addr_end = idaapi.read_selection()
        if selection:
            # call Fill Range function on this selected code
            return self.fill_range()

        address = idc.ScreenEA()

        if self.opts is None:
            self.load_configuration()

        init_assembly = None
        while True:
            f = Keypatch_Patcher(self.kp_asm, address, assembly=init_assembly, opts=self.opts)
            ok = f.Execute()
            if ok == 1:
                try:
                    syntax = None
                    if f.kp_asm.arch == KS_ARCH_X86:
                        syntax_id = f.c_syntax.value
                        syntax = self.kp_asm.get_syntax_by_idx(syntax_id)

                    assembly = f.c_assembly.value
                    self.opts = f.get_opts('c_opt_chk')
                    padding = (self.opts.get("c_opt_padding", 0) != 0)
                    comment = (self.opts.get("c_opt_comment", 0) != 0)

                    raw_assembly = self.kp_asm.ida_resolve(assembly, address)

                    print("Keypatch: attempting to modify \"{0}\" at 0x{1:X} to \"{2}\"".format(
                            self.kp_asm.ida_get_disasm(address), address, assembly))

                    length = self.kp_asm.patch_code(address, raw_assembly, syntax, padding, comment, None)
                    if length > 0:
                        # update start address pointing to the next instruction
                        init_assembly = None
                        address += length
                    else:
                        init_assembly = f.c_assembly.value
                        if length == 0:
                            idc.Warning("ERROR: Keypatch found invalid assembly [{0}]".format(assembly))
                        elif length == -1:
                            idc.Warning("ERROR: Keypatch failed to patch binary at 0x{0:X}!".format(address))
                        elif length == -2:
                            idc.Warning("ERROR: Keypatch can't read original data at 0x{0:X}, try again".format(address))

                except KsError as e:
                    print("Keypatch Error: {0}".format(e))
            else:   # Cancel
                break
            f.Free()

    # handler for Fill Range menu
    def fill_range(self):
        # be sure that this arch is supported by Keystone
        if self.kp_asm.arch is None:
            idc.Warning("ERROR: Keypatch cannot handle this architecture (unsupported by Keystone), quit!")
            return
               
        selection, addr_begin, addr_end = idaapi.read_selection()
        if not selection:
            idc.Warning("ERROR: Keypatch requires a range to be selected for fill in, try again")
            return

        if self.opts is None:
            self.load_configuration()

        init_assembly = None
        f = Keypatch_FillRange(self.kp_asm, addr_begin, addr_end, assembly=init_assembly, opts=self.opts)
        ok = f.Execute()
        if ok == 1:
            try:
                syntax = None
                if f.kp_asm.arch == KS_ARCH_X86:
                    syntax_id = f.c_syntax.value
                    syntax = self.kp_asm.get_syntax_by_idx(syntax_id)

                assembly = f.c_assembly.value
                self.opts = f.get_opts('c_opt_chk')
                padding = (self.opts.get("c_opt_padding", 0) != 0)
                comment = (self.opts.get("c_opt_comment", 0) != 0)

                raw_assembly = self.kp_asm.ida_resolve(assembly, addr_begin)

                print("Keypatch: attempting to fill range [0x{0:X}:0x{1:X}] with \"{2}\"".format(
                    addr_begin, addr_end - 1, assembly))

                length = self.kp_asm.fill_code(addr_begin, addr_end, raw_assembly, syntax, padding, comment, None)
                if length == 0:
                    idc.Warning("ERROR: Keypatch failed to process this input.")
                    print("Keypatch: FAILED to process this input '{0}'".format(assembly))
                elif length == -1:
                    idc.Warning("ERROR: Keypatch failed to patch binary at 0x{0:X}!".format(addr_begin))

            except KsError as e:
                print("Keypatch Error: {0}".format(e))

        # free this form
        f.Free()

    def run(self, arg):
        self.patcher()


# register IDA plugin
def PLUGIN_ENTRY():
    return Keypatch_Plugin_t()
