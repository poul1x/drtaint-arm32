from collections import deque
from idaapi import *
import codecs
import json

# IDA Pro 7.4

def rebase(json_content):
    current_image_base = get_imagebase()
    print(json_content[0])
    new_image_base = int(json_content[0]['address'], 16)
    delta = new_image_base - current_image_base
    return rebase_program(delta, MSF_FIXONCE)


def mark_instructions(mi_list):
    for instr in mi_list:
        addr_int = int(instr['address'], 16)
        set_color(addr_int, CIC_ITEM, 0x8EFDB7)


def filter_bad_items(mi_list):
    bad_items = []
    cnt_all = len(mi_list)
    for instr in mi_list:
        opcodes = int(instr['bytes'], 16)
        addr_int = int(instr['address'], 16)
        ida_opcodes = get_bytes(addr_int, get_item_size(addr_int))
        ida_opcodes = int(codecs.encode(ida_opcodes, 'hex'), 16)

        if opcodes != ida_opcodes:
            bad_items.append(instr)
            print('[-] failed to load instruction at address %s' %
                  instr['address'])

    mi_list = list(filter(
        lambda x: x in bad_items, mi_list))

    return cnt_all-len(bad_items), cnt_all


def add_info_comments(mi_list):
    for instr in mi_list:
        operands = instr['operands']
        addr = int(instr['address'], 16)

        taint_opnds = []
        for opnd in operands:
            taint_opnds.append('n=%s,v=%s,t=%s' % (opnd['name'], opnd['value'], opnd['taint']))

        cmt = '{%s}' % (', '.join(taint_opnds))
        set_cmt(addr, cmt, 1)


class InstructionWalker(object):
    def __init__(self, mi_list):
        self.status = False
        self.address_queue = deque()
        self.me = type(self).__name__
        self.PopulateAddressList(mi_list)

    def PopulateAddressList(self, mi_list):
        for instr in mi_list:
            addr = int(instr['address'], 16)
            self.address_queue.append(addr)

    def HotkeyPressed(self):
        if self.address_queue:
            addr = self.address_queue[0]
            self.address_queue.rotate(-1)
            jumpto(addr)
        else:
            print('%s: Alert! Empty queue' % self.me)

    def AddSearchHotkey(self, hotkey):

        # Check we have hotkey context
        # If so, then remove it first
        global hotkey_taint_search
        if 'hotkey_taint_search' in globals():
            if idaapi.del_hotkey(hotkey_taint_search):
                print('%s: Hotkey unregistered' % self.me)
                del hotkey_taint_search
            else:
                print('%s: Unable to unregister hotkey' % self.me)
                return

        hotkey_taint_search = idaapi.add_hotkey(hotkey, self.HotkeyPressed)
        if hotkey_taint_search is None:
            print('%s: Failed to register hotkey' % self.me)
            del hotkey_taint_search
        else:
            self.status = True
            print('%s: Added hotkey' % self.me)

    def GetStatus(self):
        return self.status


class InstructionView(Choose):

    def __init__(self, title, mi_list):
        Choose.__init__(self, title, [
            ["Address", 10 | Choose.CHCOL_HEX],
            ["Instruction", 20 | Choose.CHCOL_PLAIN],
            ["Comment", 40 | Choose.CHCOL_PLAIN],
        ])
        self.n = 0
        self.me = type(self).__name__
        self.icon = 42
        self.items = []
        self.PopulateItems(mi_list)

    def PopulateItems(self, mi_list):
        print('%s: Loading instructions...' % self.me)
        for instr in mi_list:
            addr_str = instr['address']
            addr_int = int(addr_str, 16)
            disasm_and_cmt = GetDisasm(addr_int).split(';')
            disasm = disasm_and_cmt[0]
            if len(disasm_and_cmt) > 1:
                comment = disasm_and_cmt[1][1:]
            else:
                comment = ''

            self.items.append([addr_str, disasm, comment, addr_int])

    def OnSelectLine(self, n):
        jumpto(self.items[n][3])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnClose(self):
        pass


# Main: open json file (JF)
filepath = ask_file(0, "*.json", "Open modules file")
if not filepath:
    print('[-] No file chosen')
    exit(1)
else:
    print('[+] Loading file %s' % filepath)

with open(filepath, "r") as f:
    modules = json.load(f)

# Rebase programm according to image base specified in JF
err = rebase(modules)
if not err == MOVE_SEGM_OK:
    print('[-] Rebase program failed: %d' % err)
    exit(1)
else:
    print('[+] Rebase program is OK')

# Apply filter to input
filepath = ask_file(0, "*.json", "Open instructions file")
if not filepath:
    print('[-] No file chosen')
    exit(1)
else:
    print('[+] Loading file %s' % filepath)

with open(filepath, "r") as f:
    instrs = json.load(f)

cnt_ok, cnt_all = filter_bad_items(instrs)
if cnt_ok == 0:
    print('[-] No valid items found in opened file')
    exit(1)
else:
    print('[+] Items processed: %d/%d' % (cnt_ok, cnt_all))

# Mark instructions in disassembly
mark_instructions(instrs)
print('[+] Mark instuctions completed')

# Add comments about tainted operands information
add_info_comments(instrs)
print('[+] Added comments')

# Create table view containing all tainted instructions
mi_view = InstructionView("Marked Instructions", instrs)
mi_view.Show()
print('[+] InstructionView is ON')

# Bind hotkeys to navigate marked intsructions
hotkey = 'Shift-T'
mi_walker = InstructionWalker(instrs)
mi_walker.AddSearchHotkey(hotkey)
if not mi_walker.GetStatus():
    print('[-] InstructionWalker is OFF')
else:
    print('[+] InstructionWalker is ON')
    print("[+] Use %s to navigate marked instructions" % hotkey)

print('[+] Init OK')
