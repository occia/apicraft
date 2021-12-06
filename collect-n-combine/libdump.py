# -*- coding: utf-8 -*-


MAGIC_BASIC='BASIC'
MAGIC_INARGS='INARGS'
MAGIC_INMEMDUMP='INMEMDUMP'
MAGIC_OUTARGS='OUTARGS'
MAGIC_OUTMEMDUMP='OUTMEMDUMP'


ARGDUMPDUMMY = 0
ARGDUMPSUCC = 1
ARGDUMPFAIL = 2


class ArgDump:
    def __init__ (self, is_csv, cnt):
        if is_csv:
            self.parse_from_csv(cnt)
        else:
            self.parse_from_json(cnt)

    def parse_from_csv(self, one_arg_str):
        #print("one_arg_str %s" % (one_arg_str))
        arg_tag, arg_dump_type, arg_dump_val, arg_dump_len = one_arg_str.split(',')
        self.tag = arg_tag
        if arg_dump_type == 'succ':
            self.type = ARGDUMPSUCC
        elif arg_dump_type == 'fail':
            self.type = ARGDUMPFAIL
        else:
            print('invalid arg_dump_type %s' % (arg_dump_type))
            exit(1)
        self.val = arg_dump_val
        self.width = int(arg_dump_len)

    def parse_from_json(self, one_arg):
        self.tag, arg_dump_type = one_arg['tag'], one_arg['type']
        if arg_dump_type == 'succ':
            self.type = ARGDUMPSUCC
        elif arg_dump_type == 'fail':
            self.type = ARGDUMPFAIL
        else:
            print('invalid arg_dump_type %s' % (arg_dump_type))
            exit(1)
        self.val = ''.join(one_arg['cnt'])
        self.width = 8 * len(one_arg['cnt'])

    def get_val_as_little_endian(self):
        size = self.width
        val = [ self.val[2*i:2*i+2] for i in range(0, size/8) ]
        return int(''.join(val[::-1]), base=16)

    @property
    def succ(self):
        return self.type == ARGDUMPSUCC


class FuncTrace:
    def __init__ (self, is_csv, idx, cnt, fmap):
        self.cnt = cnt
        if is_csv:
            self.parse_from_csv(idx, cnt, fmap)
        else:
            self.parse_from_json(idx, cnt, fmap)

    def parse_from_csv(self, idx, lines, fmap):
        self.idx = idx
        basic, inargs, inmemdump, outargs, outmemdump = [ line.strip() for line in lines ]
        # BASIC
        # WARN: the value of self.func_name is MANGLED OR NOT depends on the trace technique (lib func hook or binary hook)
        _, self.tid, self.level, self.paired, self.func_name, self.ori_func_name, self.caller0, self.caller1 = basic.split(' ')[1:]
        #_, self.tid, self.level, self.paired, self.func_name, self.ori_func_name = basic.split(' ')[1:]
        self.tid = int(self.tid)
        self.level = int(self.level)
        self.paired = True if self.paired == 'pair' else False
        # INARGS
        self.inargs = {}
        for one_arg_str in inargs.split(' ')[1:]:
            one_arg_str = one_arg_str.strip()
            if one_arg_str != "":
                arg = ArgDump(True, one_arg_str)
                self.inargs[arg.tag] = arg
        # INMEMDUMP
        self.inmemdump = {}
        #print('inmemdump %s' % (inmemdump))
        for one_mem_str in inmemdump.split(' ')[1:]:
            one_mem_str = one_mem_str.strip()
            if one_mem_str != "":
                #print("one_mem_str %s" % (one_mem_str))
                addr, val = one_mem_str.split(',')
                #self.inmemdump[int(addr, base=16)] = int(val, base=16)
                self.inmemdump[int(addr, base=16)] = val
        # OUTARGS
        self.outargs = {}
        for one_arg_str in outargs.split(' ')[1:]:
            one_arg_str = one_arg_str.strip()
            if one_arg_str != "":
                arg = ArgDump(True, one_arg_str)
                self.outargs[arg.tag] = arg
        # OUTMEMDUMP
        self.outmemdump = {}
        for one_mem_str in outmemdump.split(' ')[1:]:
            one_mem_str = one_mem_str.strip()
            if one_mem_str != "":
                addr, val = one_mem_str.split(',')
                #self.outmemdump[int(addr, base=16)] = int(val, base=16)
                self.outmemdump[int(addr, base=16)] = val
        # analyzed dependency
        self.depends = {}
        self.top_depends = {}
        self.dep_updated = False
        # cache arg type
        self.inty = { d['tag'] : d for d in fmap[self.ori_func_name]['in'] }
        self.outty = { d['tag'] : d for d in fmap[self.ori_func_name]['out'] }
        
    def parse_from_json(self, idx, trace, fmap):
        self.idx = idx
        # BASIC
        basic = trace['basic']
        self.tid, self.level, self.paired, self.idx = basic['tid'], basic['lvl'], basic['paired'], int(basic['idx'])
        self.caller0, self.caller1, self.func_name, self.ori_func_name = basic['caller0'], basic['caller1'], basic['name'], basic['demangled_name']
        #self.func_name, self.ori_func_name = basic['name'], basic['demangled_name']
        # INARGS
        self.inargs = {}
        for tag, inarg in trace['in']['args'].items():
            arg = ArgDump(False, inarg)
            self.inargs[tag] = arg
            #print('----> libdump %s %s => %s' % (self.func_name, tag, inarg))
        # INMEMDUMP
        self.inmemdump = {}
        for addr, val in trace['in']['memdump'].items():
            self.inmemdump[int(addr, base=16)] = val
        # OUTARGS
        self.outargs = {}
        for tag, outarg in trace['out']['args'].items():
            arg = ArgDump(False, outarg)
            self.outargs[tag] = arg
        # OUTMEMDUMP
        self.outmemdump = {}
        for addr, val in trace['out']['memdump'].items():
            self.outmemdump[int(addr, base=16)] = val

        # analyzed dependency
        self.depends = {}
        self.top_depends = {}
        self.dep_updated = False

        # cache arg type
        self.inty = { d['tag'] : d for d in fmap[self.ori_func_name]['in'] }
        self.outty = { d['tag'] : d for d in fmap[self.ori_func_name]['out'] }

    def get_arg_type(self, tag):
        # TODO: maybe we need to move the out_arg thing to here
        if tag in self.inty:
            return self.inty[tag]
        if tag in self.outty:
            return self.outty[tag]
        raise Exception('no matching tag %s' % (tag))

    def has_val_dependency(self, intag, another, outtag):
        if not another.paired:
            return False

        # check whether self.inargs[tag]'s type and val depends on another.outargs[tag]'s
        # is type same
        in_ty = self.get_arg_type(intag)
        out_ty = another.get_arg_type(outtag)
        #print("one %s %s %s, another %s %s %s" % (self.idx, intag, in_ty, another.idx, outtag, out_ty))
        if (not in_ty['need_cmp']) or (not out_ty['need_cmp']):
            return False
        elif in_ty['cmp_type'] != out_ty['cmp_type']:
            return False
        # is val same
        has_in_val, in_val = self.inargs[intag].succ, self.inargs[intag].val
        has_out_val, out_val = another.outargs[outtag].succ, another.outargs[outtag].val
        #print("one val %s %s, another val %s %s" % (has_in_val, in_val, has_out_val, out_val))
        if has_in_val != has_out_val:
            return False
        elif has_in_val == False:
            # TODO: skip this condition now
            return False
        elif in_val != out_val:
            return False
        elif int(in_val, base=16) == 0:
            # TODO: need to check this more
            return False
        return True

    def add_dependency(self, intag, another_idx, outtag):
        # this makes our answer space too large
        # shrink to biggest one
        if self.depends.get(intag, None) == None:
            self.depends[intag] = set()
        self.depends[intag].add((another_idx, outtag))
        self.dep_updated = True

    def top_k_depends(self, k=1):
        # this makes our answer space too large
        # shrink to biggest one
        if self.dep_updated:
            self.top_depends = {}
            for intag, dset in self.depends.items():
                self.top_depends[intag] = list(dset)
                self.top_depends[intag].sort(key=lambda x: x[0], reverse=False)
            self.dep_updated = False

        top_k = {}
        for intag, dlist in self.top_depends.items():
            top_k[intag] = dlist[0:k]
        return top_k
