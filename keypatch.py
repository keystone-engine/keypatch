# -*- coding: utf-8 -*-

# Keypatch IDA Plugin, powered by Keystone Engine (www.keytone-engine.org).
# By Nguyen Anh Quynh & Thanh Nguyen, 2016.

# Keypatch is released under the GPL v2. See COPYING for more information.
# Find docs & latest version at http://www.keystone-engine.org/keypatch

# This IDA plugin includes 2 tools inside: Patcher & Assembler.
# Access to both tools via menu "Edit | Keypatch"
# Hotkey to activate Keypatch Patcher is CTRL+ALT+K

# To revert (undo) the last patching, choose menu "Edit | Keypatch | Undo last patching".
# To check for update version, choose menu "Edit | Keypatch | Check for update".

import idc
import idaapi
import re
import json
from keystone import *


# bleeding-edge version
VERSION = "1.1"


MAX_INSTRUCTION_STRLEN = 64
MAX_ENCODING_LEN = 40
MAX_ADDRESS_LEN = 40
ENCODING_ERR_OUTPUT = "..."
KP_GITHUB_VERSION = "https://raw.githubusercontent.com/keystone-engine/keypatch/master/VERSION_STABLE"
KP_HOMEPAGE = "http://keystone-engine.org/keypatch"

# Configuration file
KP_CFGFILE = os.path.join(idaapi.get_user_idadir(), "keypatch.cfg")

# save all the info on patching
patch_info = []


def to_hexstr(buf, sep=' '):
    return sep.join("{:02x}".format(ord(c)) for c in buf).upper()


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
        cpuname = info.procName.lower()
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
                mode = KS_MODE_LITTLE_ENDIAN
            else:
                arch = KS_ARCH_ARM
                # either big-endian or little-endian
                if cpuname == "arm":
                    mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
                else:
                    mode = KS_MODE_ARM | KS_MODE_BIG_ENDIAN
        elif cpuname.startswith("sparc"):
            arch = KS_ARCH_SPARC
            if info.is_64bit():
                mode = KS_MODE_SPARC64
            else:
                mode = KS_MODE_SPARC32
            if cpuname == "sparcb":
                mode += KS_MODE_BIG_ENDIAN
            else:
                mode += KS_MODE_LITTLE_ENDIAN
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
            if cpuname == "mipsl":
                mode += KS_MODE_LITTLE_ENDIAN
            else:
                mode += KS_MODE_BIG_ENDIAN
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
            names = re.findall(r"\b[a-z0-9_:\.]+\b", _op, re.I)

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

                (t, v) = idaapi.get_name_value(address, sym)

                # skip if name doesn't exist or segment / segment registers
                if t in (idaapi.NT_SEG, idaapi.NT_NONE):
                    continue

                _op = _op.replace(sym, '0x{:X}'.format(v))

            return _op

        if self.check_address(address) == 0:
            print("Keypatch: WARNING: invalid input address {}".format(address))
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

        asm = "{} {}".format(mnem, ','.join(opers))
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
    def ida_get_disasms(self, start, end):
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
            if (sp == -1):
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

            if t in (idc.o_mem, o_displ):
                parts = list(o.partition(':'))
                if parts[2] == '':
                    parts[2] = parts[0]
                    parts[0] = ''

                if '[' not in parts[2]:
                    parts[2] = '[{}]'.format(parts[2])

                o = ''.join(parts)

                if 'ptr ' not in o:
                    dtyp_name = self.get_op_dtype_name(i)
                    if dtyp_name != None:
                        o = "{} ptr {}".format(dtyp_name, o)

            opers.append(o)
            i += 1

        asm = mnem
        for o in opers:
            if o != '':
                asm = "{} {},".format(asm, o)

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

            #print(">> asm =", _asm)
            #print(">> mnem =", mnem)

            # for PPC, Keystone does not accept registers with 'r' prefix,
            # but only the number behind. lets try to fix that here by
            # removing the prefix 'r'.
            if self.arch == KS_ARCH_PPC:
                #print(">> PPC asm =", assembly)
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
            #print("Keypatch Err: {}".format(e))
            #print("Original asm: {}".format(assembly))
            #print("Fixed up asm: {}".format(fix_ida_syntax(assembly)))
            encoding, count = None, 0

        return (encoding, count)

    # return number of bytes patched
    # return
    #    0  Invalid assembly
    #   -1  PatchByte failure
    #   -2  Can't read original data
    #   -3  Invalid address
    def patch_code(self, address, assembly, syntax, padding, save_origcode, orig_asm = None, patch_data = None):
        global patch_info

        # patch at address, return the number of written bytes & original data
        def _patch(address, patch_data, len):
            ea = address
            orig_data = ''
            invalid_value = False

            while ea < (address + len):
                if not invalid_value:
                    orig_byte = idc.Byte(ea)

                    if not idc.hasValue(idc.GetFlags(ea)):
                        print("Keypatch: WARNING: 0x{:X} has no defined value. ".format(ea))
                        invalid_value = True
                    else:
                        orig_data += chr(orig_byte)

                patch_byte = ord(patch_data[ea - address])
                if patch_byte != orig_byte:
                    # patch one byte
                    if idaapi.patch_byte(ea, patch_byte) != 1:
                        print("Keypatch: FAILED to patch byte at 0x{:X} [0x{:X}]".format(ea, patch_byte))
                        break
                ea += 1
            return (ea - address, orig_data)

        if self.check_address(address) != 1:
            # not a valid address
            return -3

        orig_comment = idc.Comment(address)

        if padding is not None:
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
                print("Keypatch: no need to patch, same encoding data [{}] at 0x{:X}".format(to_hexstr(orig_encoding), address))
                return orig_len

            # for now, only support NOP padding on Intel CPU
            if padding and self.arch == KS_ARCH_X86:
                NOP = "\x90"

                if patch_len < orig_len:
                    patch_len = orig_len
                    patch_data = patch_data.ljust(patch_len, NOP)
                elif patch_len > orig_len:
                    patch_end = address + patch_len - 1
                    ins_end = ItemEnd(patch_end)
                    padding_len = ins_end - patch_end

                    if padding_len > 0:
                        patch_len = ins_end - address
                        patch_data = patch_data.ljust(patch_len, NOP)

            orig_asm = self.ida_get_disasms(address, address + patch_len)
        else:
            # we are reverting the change via "Undo" menu
            patch_len = len(patch_data)
            # if we added comment before, we need to comment on this "Undo" now
            if orig_comment and "Keypatch" in orig_comment:
                save_origcode = True

        # save original function end to fix IDA re-analyze issue after patching
        orig_func_end = idc.GetFunctionAttr(address, idc.FUNCATTR_END)

        (plen, p_orig_data) = _patch(address, patch_data, patch_len)

        if plen != patch_len:
            # patch failure

            if plen > 0:
                # revert the changes
                (rlen, _) = _patch(address, p_orig_data, plen)
                if rlen == plen:
                    print("Keypatch: successfully reverted changes of {:d} byte(s) at 0x{:X} [{}]".format(
                                        plen, address, to_hexstr(p_orig_data)))
                else:
                    print("Keypatch: FAILED to revert changes of {:d} byte(s) at 0x{:X} [{}]".format(
                                        plen, address, to_hexstr(p_orig_data)))

            return -1

        if padding is not None:
            # we are patching via Patcher
            print("Keypatch: successfully patched {:d} byte(s) at 0x{:X} from [{}] to [{}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))
        else:
            # we are reverting (undo) the last patching
            print("Keypatch: successfully reverted {:d} byte(s) at 0x{:X} from [{}] to [{}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))

        # only save this patching if we do not "undo"
        if padding is not None:
            patch_info.append((address, assembly, p_orig_data))

        # ask IDA to re-analyze the patched area
        idaapi.analyze_area(address, orig_func_end)

        # try to fix IDA function re-analyze issue after patching
        idaapi.func_setend(address, orig_func_end)

        if save_origcode:
            # append original instruction to comments
            if orig_comment == None:
                orig_comment = ''
            else:
                orig_comment = '{}\n'.format(orig_comment)

            if padding is not None:
                # we are patching
                comments = "{}Keypatch modified this from:\n  {}".format(orig_comment, '\n  '.join(orig_asm))
            else:   # we are reverting
                comments = "{}Keypatch reverted this from:\n  {}".format(orig_comment, '\n  '.join(orig_asm))
            idc.MakeComm(address, comments)

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


# Dialog for interactive assembler & patcher
# Common ancestor form to be shared between Patcher & Assembler
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
        if self.orig_encoding == None:
            self.orig_encoding = ''

        if assembly is None:
            self.asm = self.kp_asm.ida_get_disasm(self.address, fixup=True)
        else:
            self.asm = assembly


    def __init__(self, kp_asm, address, assembly=None, patch_mode=False, opts=0):
        pass

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


# Patcher form
class Keypatch_Patcher(Keypatch_Form):
    def __init__(self, kp_asm, address, assembly=None, opts=None):
        self.setup(kp_asm, address, assembly)

        # create Patcher form
        Form.__init__(self,
            r"""STARTITEM {id:c_assembly}
BUTTON YES* Patch
KEYPATCH:: Patcher

            {FormChangeCb}
            <Endian     :{c_endian}>
            <~S~yntax     :{c_syntax}>
            <Address    :{c_addr}>
            <Original   :{c_orig_assembly}>
             <-   Encode:{c_orig_encoding}>
             <-   Size  :{c_orig_len}>
            <~A~ssembly   :{c_assembly}>
             <-   Fixup :{c_raw_assembly}>
             <-   Encode:{c_encoding}>
             <-   Size  :{c_encoding_len}>
            <~N~OPs padding until next instruction boundary:{c_opt_padding}>
            <Save ~o~riginal instructions in IDA comment:{c_opt_comment}>{c_opt_chk}>
            """, {
            'c_endian': Form.DropdownListControl(
                          items = self.kp_asm.endian_lists.keys(),
                          readonly = True,
                          selval = self.endian_id),
            'c_addr': Form.NumericInput(value=address, swidth=MAX_ADDRESS_LEN, tp=Form.FT_ADDR),
            'c_assembly': Form.StringInput(value=self.asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_orig_assembly': Form.StringInput(value=self.orig_asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_orig_encoding': Form.StringInput(value=self.orig_encoding[:MAX_ENCODING_LEN], width=MAX_ENCODING_LEN),
            'c_orig_len': Form.NumericInput(value=self.orig_len, swidth=8, tp=Form.FT_DEC),
            'c_raw_assembly': Form.StringInput(value='', width=MAX_INSTRUCTION_STRLEN),
            'c_encoding': Form.StringInput(value='', width=MAX_ENCODING_LEN),
            'c_encoding_len': Form.NumericInput(value=0, swidth=8, tp=Form.FT_DEC),
            'c_syntax': Form.DropdownListControl(
                          items = self.syntax_keys,
                          readonly = True,
                          selval = self.syntax_id),
            'c_opt_chk':idaapi.Form.ChkGroupControl(('c_opt_padding', 'c_opt_comment', ''), value=opts['c_opt_chk']),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # get Patcher options
    def get_opts(self, name=None):
        names = self.c_opt_chk.children_names
        val = self.c_opt_chk.value
        opts = {}
        for i in range(len(names)):
            opts[names[i]] = val & (2**i)

        if name != None:
            opts[name] = val

        return opts

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        (arch, mode) = (self.kp_asm.arch, self.kp_asm.mode)
        # assembly is focused
        self.SetFocusedField(self.c_assembly)

        # make address, arch, endian and syntax read-only in patch_mode mode
        self.EnableField(self.c_orig_assembly, False)
        self.EnableField(self.c_orig_encoding, False)
        self.EnableField(self.c_orig_len, False)

        self.EnableField(self.c_endian, False)
        self.EnableField(self.c_addr, False)

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


# Assembler form
class Keypatch_Assembler(Keypatch_Form):
    def __init__(self, kp_asm, address, assembly=None):
        self.setup(kp_asm, address, assembly)

        # create Assembler form
        Form.__init__(self,
            r"""STARTITEM {id:c_assembly}
BUTTON YES NONE
KEYPATCH:: Assembler

            {FormChangeCb}
            <A~r~ch       :{c_arch}>
            <E~n~dian     :{c_endian}>
            <~S~yntax     :{c_syntax}>
            <A~d~dress    :{c_addr}>
            <~A~ssembly   :{c_assembly}>
             <-   Fixup :{c_raw_assembly}>
             <-   Encode:{c_encoding}>
             <-   Size  :{c_encoding_len}>
            """, {
            'c_addr': Form.NumericInput(value=address, swidth=MAX_ADDRESS_LEN, tp=Form.FT_ADDR),
            'c_assembly': Form.StringInput(value=self.asm[:MAX_INSTRUCTION_STRLEN], width=MAX_INSTRUCTION_STRLEN),
            'c_raw_assembly': Form.StringInput(value='', width=MAX_INSTRUCTION_STRLEN),
            'c_encoding': Form.StringInput(value='', width=MAX_ENCODING_LEN),
            'c_encoding_len': Form.NumericInput(value=0, swidth=8, tp=Form.FT_DEC),
            'c_arch': Form.DropdownListControl(
                          items = self.arch_keys,
                          readonly = True,
                          selval = self.arch_id,
                          width = 32),
            'c_endian': Form.DropdownListControl(
                          items = self.kp_asm.endian_lists.keys(),
                          readonly = True,
                          selval = self.endian_id),
            'c_syntax': Form.DropdownListControl(
                          items = self.syntax_keys,
                          readonly = True,
                          selval = self.syntax_id),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        # only Assembler mode allows to select arch+mode
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
        # create Assembler form
        Form.__init__(self,
            r"""STARTITEM 0
BUTTON YES* Open Keypatch Website
KEYPATCH:: About

            {FormChangeCb}
            Keypatch IDA plugin v%s, using Keystone Engine v%s.
            (c) Nguyen Anh Quynh + Thanh Nguyen, 2016.

            Keypatch is released under the GPL v2.
            Find more info at http://www.keystone-engine.org/keypatch
            """ %(version, keystone.__version__), {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open in a new tab, if possible
            webbrowser.open(KP_HOMEPAGE, new = 2)

        return 1


# Check-for-update form
class Update_Form(idaapi.Form):
    def __init__(self, version, message):
        # create Assembler form
        Form.__init__(self,
            r"""STARTITEM 0
BUTTON YES* Open Keypatch Website
KEYPATCH:: Check for update

            {FormChangeCb}
            Your Keypatch is v%s
            %s
            """ %(version, message), {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open in a new tab, if possible
            webbrowser.open(KP_HOMEPAGE, new = 2)

        return 1


class Binary_Fill_NOPs(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.fill_value = 0x90  # nop opcode

    @classmethod
    def get_name(cls):
        return cls.__name__

    def get_label(self):
        return 'Fill with NOPs'

    @classmethod
    def register(cls):
        instance = cls()
        return idaapi.register_action(idaapi.action_desc_t(
            cls.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(cls):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    def activate(self, ctx):
        selection, start_ea, end_ea = idaapi.read_selection()
        if selection:
            print("Keypatch: Fill data from 0x{:08x} to 0x{:08x}".format(start_ea, end_ea))
            for ea in range(start_ea, end_ea):
                idaapi.patch_byte(ea, self.fill_value)
        else:
            print("Keypatch: Select a range of code.")
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM


class Binary_Fill_NULLs(Binary_Fill_NOPs):
    def __init__(self):
        Binary_Fill_NOPs.__init__(self)
        self.fill_value = 0x00

    def get_label(self):
        return "Fill with 00's"


class Hooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        # We'll add our action to all "IDA View-*"s.
        # If we wanted to add it only to "IDA View-A", we could
        # also discriminate on the widget's title:
        #
        #  if idaapi.get_tform_title(form) == "IDA View-A":
        #      ...
        #
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, Binary_Fill_NULLs.get_name(), 'Keypatch/')
            arch, _ = Keypatch_Asm.get_hardware_mode()
            # for now, only support NOP on Intel CPU
            if arch == KS_ARCH_X86:
                idaapi.attach_action_to_popup(form, popup, Binary_Fill_NOPs.get_name(), 'Keypatch/')
            


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Keypatch_Plugin_t(idaapi.plugin_t):
    comment = "Keypatch plugin for IDA Pro (using Keystone framework)"
    help = "Find more information on Keypatch at http://keystone-engine.org/keypatch"
    wanted_name = "Keypatch patcher (CTRL+ALT+K)"
    wanted_hotkey = ""
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
            print("Keypatch: Use default configuration.")
        except Exception as e:
            print("Keypatch: Exception: %s" % (str(e)))

        # use default values if not defined in config file
        self.opts['c_opt_padding'] = self.opts.get('c_opt_padding', 1)
        self.opts['c_opt_comment'] = self.opts.get('c_opt_comment', 2)
        self.opts['c_opt_chk'] = self.opts.get('c_opt_chk', 3)

    def init(self):
        # patch binary with NOP or NULL bytes
        Binary_Fill_NULLs.register()
        arch, _ = Keypatch_Asm.get_hardware_mode()
        # for now, only support NOP on Intel CPU
        if arch == KS_ARCH_X86:
            Binary_Fill_NOPs.register()

        # setup context menu
        self.hooks = Hooks()
        self.hooks.hook()

        self.opts = None
        # add a menu for Keypatch patcher & assembler
        menu_ctx = idaapi.add_menu_item("Edit/Keypatch/", "Patcher", "Ctrl-Alt-K", 1, self.patcher, None)
        if menu_ctx is not None:
            idaapi.add_menu_item("Edit/Keypatch/", "About", "", 1, self.about, None)
            idaapi.add_menu_item("Edit/Keypatch/", "Check for update ...", "", 1, self.updater, None)
            idaapi.add_menu_item("Edit/Keypatch/", "-", "", 1, self.menu_null, None)
            idaapi.add_menu_item("Edit/Keypatch/", "Assembler", "", 1, self.assembler, None)
            idaapi.add_menu_item("Edit/Keypatch/", "-", "", 1, self.menu_null, None)
            idaapi.add_menu_item("Edit/Keypatch/", "Undo last patching", "", 1, self.undo, None)
            print("=" * 80)
            print("Keypatch registered IDA plugin {} (c) Nguyen Anh Quynh & Thanh Nguyen, 2016".format(VERSION))
            print("Keypatch is using Keystone v{}".format(keystone.__version__))
            print("Keypatch Patcher's shortcut key is CTRL+ALT+K")
            print("To revert (undo) the last patching, choose menu Edit | Keypatch | Undo last patching")
            print("Keypatch Assembler is available from menu Edit | Keypatch | Assembler")
            print("Find more information about Keypatch at http://keystone-engine.org/keypatch")

            self.load_configuration()

            print("=" * 80)
            self.kp_asm = Keypatch_Asm()

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
            arch, _ = Keypatch_Asm.get_hardware_mode()
            # for now, only support NOP on Intel CPU 
            if arch == KS_ARCH_X86:
                Binary_Fill_NOPs.unregister()
            Binary_Fill_NULLs.unregister()

        if self.opts is None:
            return
        #save configuration to file
        try:
            json.dump(self.opts, open(KP_CFGFILE, "wt"))
        except Exception as e:
            print("Keypatch: Exception: %s" % (str(e)))
        else:
            print("Keypatch: Configuration is saved to %s" % (KP_CFGFILE))

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
                f.Free()
            else:
                f = Update_Form(VERSION, "Download latest stable version {} from http://keystone-engine.org/keypatch".format(version_stable))
                f.Execute()
                f.Free()
        else:
            # fail to download
            idc.Warning("ERROR: failed to connect to internet (Github). Try again later.")
            print("ERROR: failed to connect to Github to check for latest Keypatch version. Try again later.")


    # handler for Undo menu
    def undo(self):
        global patch_info
        if len(patch_info) == 0:
            # TODO: disable Undo menu?
            idc.Warning("ERROR: no more patching to undo!")
        else:
            (address, assembly, p_orig_data) = patch_info[-1]
            self.kp_asm.patch_code(address, None, None, None, None, [assembly], p_orig_data)
            del(patch_info[-1])

    # handler for Assembler menu
    def assembler(self):
        address = idc.ScreenEA()
        f = Keypatch_Assembler(self.kp_asm, address)
        f.Execute()
        f.Free()

    # handler for Patcher menu
    def patcher(self):
        # be sure that this arch is supported by Keystone
        if self.kp_asm.arch is None:
            idc.Warning("ERROR: this architecture is unsupported by Keystone, quit!")
            return

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

                    print("Keypatch: attempt to modify \"{}\" at 0x{:X} to \"{}\"".format(
                            self.kp_asm.ida_get_disasm(address), address, assembly))

                    length = self.kp_asm.patch_code(address, raw_assembly, syntax, padding, comment)

                    if length > 0:
                        # update start address pointing to the next instruction
                        init_assembly = None
                        address += length
                    else:
                        init_assembly = f.c_assembly.value
                        if length == 0:
                            idc.Warning("ERROR: invalid assembly [{}]".format(assembly))
                        elif length == -1:
                            idc.Warning("ERROR: failed to patch binary at 0x{:X}!".format(address))
                        elif length == -2:
                            idc.Warning("ERROR: can't read original data at 0x{:X}, try again".format(address))


                except KsError as e:
                    print("Keypatch Err: {}".format(e))
            else:   # Cancel
                f.Free()
                break
            f.Free()


    def run(self, arg):
        self.patcher()


# register IDA plugin
def PLUGIN_ENTRY():
    return Keypatch_Plugin_t()
