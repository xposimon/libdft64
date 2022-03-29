'''
Date: 2022-03-29 18:27:40
LastEditors: zx Zhou
LastEditTime: 2022-03-29 19:12:16
FilePath: /libdft64/tools/scripts/info_collect/collector.py
'''
import copy, re, os, ast
from intervaltree import * 

ENTRY_FUNC_NAME = "main"
ENTRY_ADDR = 0
TAINTED_TAG = "ttd_tag"
CMP_LEN = "cmp_len"


class state_node:
    def __init__(self, begin, end, info={}, ex_pred=[], ex_next=[], im_pred=[], im_next=[]):
        self.begin = begin
        self.end = end
        self.info = info 
        self.ex_next = ex_next
        self.ex_pred = ex_pred
        self.im_next = im_next
        self.im_pred = im_pred

class fuzz_state_cfg:
    def __init__(self, cfg = {}):
        self.cfg = cfg
        self.search_tree = IntervalTree()
    
    def add_node(self, addr, node):
        if addr in self.cfg:
            print("Repeated node")
            return
        self.cfg[addr] = node 
        # Add 1 for end addr in case of only one instruction
        self.search_tree.add(Interval(node.begin, node.end+1))

    def update_relation(self, addr, ex_pred=[], ex_next=[], im_next=[], im_pred=[]):
        if addr not in self.cfg:
            print("Non-existant addr")
            return
        if len(ex_pred)>0:
            self.cfg[addr].ex_pred.extend(ex_pred)
        if len(ex_next)>0:
            self.cfg[addr].ex_next.extend(ex_next)
        if len(im_pred)>0:
            self.cfg[addr].im_pred.extend(im_pred)
        if len(im_next)>0:
            self.cfg[addr].im_next.extend(im_next)

    def search_block_addr(self, addr):
        res =  self.search_tree.at(addr)
        if len(res) == 1:
            return res.pop().begin
        else:
            return 0

fscfg = fuzz_state_cfg()

def cfg_generate(cfg_info):
    global ENTRY_ADDR
    cfg_info = cfg_info.split("\n")
    rtn_name = ""
    for il in cfg_info:
        if il.startswith("[RT]"):
            rtn_name = il[4:].strip()
        
        if il.startswith("[BB]"):
            begin, end = il[4:].split(":")
            begin = int(begin, 16)
            end = int(end, 16)
            if rtn_name == ENTRY_FUNC_NAME and not ENTRY_ADDR:
                ENTRY_ADDR = begin
            fscfg.add_node(begin, copy.deepcopy(state_node(begin, end)))

    for il in cfg_info:   
        if il.startswith("[Ex]"):
            pred, cur = il[4:].split("=>")
            pred = int(pred, 16)
            cur = int(cur, 16)
            fscfg.update_relation(cur, ex_pred=[pred])
            fscfg.update_relation(pred, ex_next=[cur])


    for il in cfg_info:   
        if il.startswith("[Im]"):
            pass

def cfg_check(func):
    def wrap(*args, **kwargs):
        if len(fscfg.cfg) == 0:
            print("Not exist a cfg")
            return -1
        return func(*args, **kwargs)
    return wrap
        

@cfg_check
def cmp_analysis(cmp_info):
    cmp_info = cmp_info.split("\n")
    for il in cmp_info:
        if(len(il) == 0):
            continue
        addr, info = il.split(":")
        addr = int(addr, 16)
        bbl_addr = fscfg.search_block_addr(addr)
        if bbl_addr in fscfg.cfg:
            cmp_len, tag = info.split("|")
            cmp_len = int(cmp_len)
            fscfg.cfg[bbl_addr].info[CMP_LEN] = cmp_len
            res = re.findall(r"\(\s*\d+\s*,\s*\d+\s*\)", tag)
            tags = [ast.literal_eval(pair) for  pair in  res]
            for pair in tags:
                tainted_tag = (1<<(pair[1])) - (1<<(pair[0]))
                if TAINTED_TAG not in fscfg.cfg[bbl_addr].info:
                    fscfg.cfg[bbl_addr].info[TAINTED_TAG] = 0
                fscfg.cfg[bbl_addr].info[TAINTED_TAG] |= tainted_tag
            print(hex(bbl_addr), bin(fscfg.cfg[bbl_addr].info[TAINTED_TAG] ))
