# -*- coding: utf-8 -*-


import os
import copy
import json
import utils
import random
import datetime
import numpy as np
import libdyn
import math
from keyedset import KeyedSet
from graphviz import Digraph


tmap = None
fmap = None
ftraces = None
harness_cfg = None
# ida cov: (libname, offset) => func
ida_cov = None

all_slices = {}
all_forests = {}
ga = None

debug_info = []

def set_globals(_ftraces, _tmap, _fmap, _harness_cfg, _ida_cov):
    global ftraces
    global tmap
    global fmap
    global harness_cfg
    global ida_cov

    ftraces = _ftraces
    tmap = _tmap
    fmap = _fmap
    harness_cfg = _harness_cfg
    ida_cov = _ida_cov

class BasicGenVar(object):
    def __init__(self, id, seq, is_in, tag):
        global fmap
        global tmap

        if id == None:
            self._void = True
            return
        else:
            self._void = False

        self.id = id
        self._name = "v_%s" % (self.id)
        if seq == None and is_in == None and tag == None:
            # fake var
            self.fake = True
            self._type = "UNKNOWN"
        else:
            self.fake = False
            self.func_trace = seq.ftref
            finfo = fmap[seq.ftref.ori_func_name]
            if is_in:
                self.arg_dump = self.func_trace.inargs[tag]
                for intag_info in finfo['in']:
                    if intag_info['tag'] == tag:
                        self.tag_info = intag_info
                        self.ty_info = tmap[intag_info['tkey']]
                        self.mem_dump = self.func_trace.inmemdump
                        self._type = "%s" % (self.ty_info['tspell'])
                        break
            else:
                self.arg_dump = self.func_trace.outargs[tag]
                for outtag_info in finfo['out']:
                    if outtag_info['tag'] == tag:
                        self.tag_info = outtag_info
                        self.ty_info = tmap[outtag_info['tkey']]
                        self.mem_dump = self.func_trace.outmemdump
                        self._type = "%s" % (self.ty_info['tspell'])
                        break

    @property
    def name(self):
        return self._name
    
    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name
    
    @property
    def type(self):
        return self._type
    
    @property
    def void(self):
        return self._void
    
    def gen_definition(self):
        raise Exception("not implemented")

class KnowledgeBaseVar(BasicGenVar):
    def __init__(self, id, seq, is_in, tag, gen):
        super(KnowledgeBaseVar, self).__init__(id, seq, is_in, tag)
        self.gen = gen

    def gen_definition(self):
        code = self.gen['code']
        return "\t%s %s = %s;" % (self.type, self.name, code)

class MemDumpVar(BasicGenVar):
    def __init__(self, id, seq, is_in, tag):
        super(MemDumpVar, self).__init__(id, seq, is_in, tag)

    def dump(self, ty, name, val, size, pointees, dumped_addrs=None):
        global tmap
        ty_validation = lambda ty: ty.replace('enum ', '') if ty.startswith('enum ') else ty

        srcs = [""]
        if ty != None:
            s1 = "u8 __%s [%d] = {%s};" % (name, size//8, ','.join([ ('\'\\x' + v + '\'') for v in val ]))
            s2 = "%s %s;" % (ty_validation(ty), name)
            s3 = "memcpy((u8 *)&%s, (u8 *)__%s, %s);" % (name, name, size//8)

            srcs.append(s1)
            srcs.append(s2)
            srcs.append(s3)
        else:
            # simpler mode for generating fields cnt, as the type is not important we use a general one -- u8 []
            s1 = "u8 %s [%d] = {%s};" % (name, size//8, ','.join([ ('\'\\x' + v + '\'') for v in val ]))
            srcs.append(s1)

        if int(''.join(val), base=16) != 0:
            # dump pointee only if it is a valid pointer, now we only handle null pointer
            # we also handle the loop of recursively dump members (will not dump same addr twice in dumping one var)
            # we also fix the non-null pointer addresses
            if dumped_addrs == None:
                dumped_addrs = set([])

            for pointee in pointees:
                field_tkey = pointee['tkey']
                field_off = pointee['offset']
                field_name = name + ('_off_%d' % (field_off))
                field_ty = tmap[field_tkey]['tspell']
                field_size = tmap[field_tkey]['size']
                field_pointees = tmap[field_tkey]['pointees']
                field_addr = None
                field_val = []
                if field_size > 0 and field_off % 8 == 0 and field_size % 8 == 0:
                    field_addr = 0
                    # WARN: now only for little endian
                    for i in range(8):
                        #print("trace idx ", self.func_trace.idx, "val ", val, "field_off", field_off, "i", i , "field_size", field_size, field_tkey, field_name)
                        b = int(val[field_off // 8 + i], base=16)
                        field_addr = field_addr | (b << i*8)
                    if field_addr == 0 or (field_addr in dumped_addrs):
                        continue

                    dumped_addrs.add(field_addr)

                    for i in range(field_size // 8):
                        field_val.append(self.mem_dump[field_addr + i])
                    # here fix the pointer of the field members
                    ss1 = "*(void **)((u8 *)(void *)(&%s) + %s) = (void *)(&%s);" % (name, field_off//8, field_name)
                    srcs.extend(self.dump(None, field_name, field_val, field_size, field_pointees))
                    srcs.append(ss1)
                elif field_size == 0:
                    # TODO: currently we set all zero_size cases into null
                    #   should consider more on function/void */...
                    ss1 = "*(void **)((u8 *)(void *)(&%s) + %s) = (void *)(0x0); // ZERO_SIZE" % (name, field_off//8)
                    srcs.append(ss1)
                elif field_size < 0:
                    #print(field_tkey, field_ty, field_size, field_addr, field_off)
                    # see libtype.py line 86 is_size_error for more details
                    reasons = { 0: 'ZERO_SIZE', -2: 'OPAQUE'}
                    ss1 = "%s = %s(%s);" % (field_name, reasons.get(field_size, 'UNHANDLED'), field_ty)
                    ss2 = "*(void **)((u8 *)(void *)(&%s) + %s) = (void *)(&%s);" % (name, field_off//8, field_name)
                    srcs.append(ss1)
                    srcs.append(ss2)
                else:
                    print(field_tkey, field_ty, field_size, field_addr, field_off)
                    raise Exception("not implemented for bit fields")

        srcs.append("\n")

        return srcs

    def gen_definition(self):
        ty = self.type
        name = self.name
        size = self.arg_dump.width
        val = [ self.arg_dump.val[2*i:2*i+2] for i in range(0, size//8) ]
        #print('val ', val, 'size', size)
        pointees = self.ty_info['pointees']
        # TODO: we ignore the case now: func arg is passing record by value but has member pointing back to its addr
        return '\n\t'.join(self.dump(ty, name, val, size, pointees))

class FuncOutVar(BasicGenVar):
    def __init__(self, id, seq, is_in, tag):
        super(FuncOutVar, self).__init__(id, seq, is_in, tag)

class FakeVar(BasicGenVar):
    def __init__(self, id):
        super(FakeVar, self).__init__(id, None, None, None)

class VoidVar(BasicGenVar):
    def __init__(self):
        super(VoidVar, self).__init__(None, None, None, None)


class Node(object):
    def __init__(self, trace_file, thread_id, trace_idx, slice_idx = None, seq_idx = None):
        global ftraces

        self.tfile = trace_file
        self.tid = thread_id
        self.tidx = trace_idx
        self.totag = None
        self.ty = None
        self.sidx = slice_idx
        self.seq_idx = seq_idx

        ftrace_ref = None
        if self.tfile != None and self.tidx != None:
            ftrace_ref = ftraces[self.tfile][self.tidx]
        self.ftref = ftrace_ref

        #self.gaid = (self.tfile, self.tid, self.tidx, self.totag, self.ty)
        self.gaid = (None, None, self.ty)
        self.id = (self.tfile, self.tid, self.tidx, self.totag, self.ty, self.sidx, self.seq_idx)

        if (not (self.id == (None, None, None, None, None, None, None))) and (ftrace_ref == None):
            raise Exception("ftrace_ref is None")

    def __str__(self):
        #return "(%s, %s, %s, %s)" % (self.id[0], self.id[2], self.id[3], self.id[4])
        return "(%s)" % (str(self.gaid))

    def __repr__(self):
        #return "(%s, %s, %s, %s)" % (self.id[0], self.id[2], self.id[3], self.id[4])
        return "(%s)" % (str(self.gaid))

    def is_func(self):
        raise Exception("has not implement")

    def is_value(self):
        raise Exception("has not implement")

    def set_slice(self, slice_idx, seq_idx):
        self.sidx =  slice_idx
        self.seq_idx = seq_idx
        self.id = (self.tfile, self.tid, self.tidx, self.totag, self.ty, self.sidx, self.seq_idx)
        return self

    @staticmethod
    def from_id(_id):
        global ftraces
        
        tfile, tid, tidx, tag, ty, sidx, seqidx = _id
        #print("Node.from_id ", _id)

        ftref = None
        if tfile != None and tidx != None:
            ftref = ftraces[tfile][tidx]

        if ty == None:
            return Node(tfile, tid, tidx, sidx, seqidx)

        if ftref == None:
            raise Exception("ftref is None")
        elif ty == 'FUNC':
            return FuncNode(tfile, tid, tidx, sidx, seqidx)
        elif ty == 'FAKE':
            return FakeNode(tfile, tid, tidx, tag, sidx, seqidx)
        elif ty == 'DUMP':
            return DumpNode(tfile, tid, tidx, tag, sidx, seqidx)
        elif ty == 'KB':
            return KBNode(tfile, tid, tidx, tag, sidx, seqidx)
        else:
            raise Exception("ty is unknown %s" % (ty))


class FuncNode(Node):
    def __init__(self, trace_file, thread_id, trace_idx, slice_idx = None, seq_idx = None):
        super(FuncNode, self).__init__(trace_file, thread_id, trace_idx, slice_idx, seq_idx)
        self.ty = 'FUNC'
        #self.gaid = (self.tfile, self.tid, self.tidx, self.totag, self.ty)
        self.gaid = (self.ftref.ori_func_name, self.totag, self.ty)
        self.id = (self.tfile, self.tid, self.tidx, self.totag, self.ty, self.sidx, self.seq_idx)

    def is_func(self):
        return True

    def is_value(self):
        return False

    def get_use(self, vars):
        global tmap
        global fmap

        #print('%s vars %s' % (self.gaid, vars))
        ty_validation = lambda ty: ty.replace('enum ', '') if ty.startswith('enum ') else ty
        get_tspell = lambda ft, intag: ty_validation(tmap[ft.get_arg_type(intag)['tkey']]['tspell'])
        args = [ (int(intag[3:]), '(%s)%s' % (get_tspell(self.ftref, intag), vars[self.id][intag].name)) for intag in self.ftref.inargs ]
        args.sort(key=lambda x: x[0])
        args = [ arg[1] for arg in args ]

        code = ''
        has_ret = 'ret' in vars[self.id]

        func_name = self.ftref.ori_func_name
        if func_name.startswith('fkcppmf_'):
            arg0_var_name = vars[self.id]['arg0'].name
            func_name = '%s->lpVtbl->%s' % (arg0_var_name, fmap[func_name]['gen_name'])

        # TODO: here didn't consider non-ret out tag
        # TODO 2: ???
        if not has_ret:
            code += '\t%s(%s);\n' % (func_name, ','.join(args))
        else:
            ret = vars[self.id]['ret']
            code += '\t%s %s = %s(%s);\n' % (ty_validation(ret.type), ret.name, func_name, ','.join(args))

        for tag, var in vars[self.id].items():
            if tag.startswith('out_arg'):
                intag = tag.replace('out_arg', 'arg')
                invar = vars[self.id][intag]
                code += '\t//extra out arg\n'
                code += '\t%s %s = *(%s);\n' % (ty_validation(var.type), var.name, invar.name)
        
        return code


class ValueNode(Node):
    def __init__(self, trace_file, thread_id, trace_idx, totag, val_ty, val, slice_idx = None, seq_idx = None):
        super(ValueNode, self).__init__(trace_file, thread_id, trace_idx, slice_idx, seq_idx)
        self.totag = totag
        self.ty = val_ty
        self.val = val
        #self.gaid = (self.tfile, self.tid, self.tidx, self.totag, self.ty)
        self.gaid = (self.ftref.ori_func_name, self.totag, self.val, self.ty)
        self.id = (self.tfile, self.tid, self.tidx, self.totag, self.ty, self.sidx, self.seq_idx)

    def is_func(self):
        return False

    def is_value(self):
        return True

    def is_fake(self):
        raise Exception("has not implement")
    
    def is_dump(self):
        raise Exception("has not implement")

    def is_KB(self):
        raise Exception("has not implement")

    def get_def(self):
        raise Exception("has not implement")


# trace dump value node
class FakeNode(ValueNode):
    def __init__(self, trace_file, thread_id, trace_idx, totag, slice_idx = None, seq_idx = None):
        super(FakeNode, self).__init__(trace_file, thread_id, trace_idx, totag, 'FAKE', None, slice_idx, seq_idx)

    def is_fake(self):
        return True

    def is_dump(self):
        return False

    def is_KB(self):
        return False

    def get_def(self, var):
        return '%s %s = FAKEFAKEFAKE;' % (var.type, var.name)


# trace dump value node
class DumpNode(ValueNode):
    def __init__(self, trace_file, thread_id, trace_idx, totag, slice_idx = None, seq_idx = None):
        ftrace_ref = None
        if trace_file != None and trace_idx != None:
            ftrace_ref = ftraces[trace_file][trace_idx]
        if ftrace_ref == None:
            raise Exception("ftrace_ref is None")
        val = ftrace_ref.inargs[totag].val
        super(DumpNode, self).__init__(trace_file, thread_id, trace_idx, totag, 'DUMP', val, slice_idx, seq_idx)

    def is_fake(self):
        return False

    def is_dump(self):
        return True

    def is_KB(self):
        return False

    def get_def(self, var):
        return var.gen_definition()


# knowledge base node
class KBNode(ValueNode):
    def __init__(self, trace_file, thread_id, trace_idx, totag, slice_idx = None, seq_idx = None):
        # TODO: now we set val as None as we assume the KB node for a given (func, arg) has at most one
        super(KBNode, self).__init__(trace_file, thread_id, trace_idx, totag, 'KB', None, slice_idx, seq_idx)

    def is_fake(self):
        return False

    def is_dump(self):
        return False

    def is_KB(self):
        return True

    def get_def(self, var):
        return var.gen_definition()


class Edge(object):
    def __init__(self, from_node, from_tag, to_node, to_tag):
        self.from_node = from_node
        self.from_tag = from_tag
        self.to_node = to_node
        self.to_tag = to_tag
        self.gaid = (self.from_node.gaid, self.from_tag, self.to_node.gaid, self.to_tag)
        self.id = (self.from_node.id, self.from_tag, self.to_node.id, self.to_tag)
    
    def __str__(self):
        return "(%s::%s => %s::%s)" % (self.from_node, self.from_tag, self.to_node, self.to_tag)

    def __repr__(self):
        return "(%s::%s => %s::%s)" % (self.from_node, self.from_tag, self.to_node, self.to_tag)

    @staticmethod
    def from_id(_id):
        return Edge(Node.from_id(_id[0]), _id[1], Node.from_id(_id[2]), _id[3])


class Individual(object):
    
    def __init__(self, _id):
        self.rank = None
        self.crowding_distance = None
        self.domination_count = None
        self.dominated_solutions = None
        self.sli_id = _id
        self.objectives = None

    def __eq__(self, other):
        if isinstance(self, other.__class__):
            return self.sli_id == other.sli_id
        return False

    def dominates(self, other_individual):
        and_condition = True
        or_condition = False
        for first, second in zip(self.objectives, other_individual.objectives):
            #and_condition = and_condition and first <= second
            #or_condition = or_condition or first < second
            # according to our objectives' score formula, we need to define partial relation as >/>=
            and_condition = and_condition and first >= second
            or_condition = or_condition or first > second
        return (and_condition and or_condition)


class Slice(object):
    _id = 0

    # edge: (from_idx, from_tag, to_idx, to_tag)
    def __init__ (self, core_seq=None, seqs=None, edges=None, add_val_node=False, tracing=False, label='', no_id=False, from_forest=False):
        global all_slices

        if no_id:
            # WARN: this no_id case is used for serialization/deserialization of a slice (wiping the slice id in edges/nodes)
            self.id = None
        else:
            Slice._id += 1
            self.id = Slice._id

        self.label = label

        key_func = lambda x: x.id

        self.core_seq = None
        self.edges, self.seqs = KeyedSet([], key=key_func), KeyedSet([], key=key_func)
        # recording the k:v from initial seq/edge.id to internal seq/edge
        self.map_init_seqs, self.map_init_edges= {}, {}
        # used for traverse
        self.from_edges, self.to_edges = {}, {}
        # set of func names
        self._funcs = {}

        if edges != None and len(edges) != 0:
            for edge in edges: 
                if not edge.to_node.is_func():
                    raise Exception("invalid edge that is neither func is not to_node")
                new_edge = self.add_edge(edge)
        elif seqs != None:
            for seq in seqs:
                new_node = self.add_seq(seq)
        else:
            raise Exception("no seqs or edges to initialize the Slice")

        if core_seq != None:
            self.core_seq = self.map_init_seqs.get(core_seq.id, None)
            if self.core_seq == None:
                raise Exception("param core_seq is not in the given seqs or edges")

        if add_val_node:
            # when initialized, only FuncNode is initialized, we add other nodes for them
            self.fixup_value_nodes()

        # generation related
        # For now, fail reason could be HAS_RING/NO_INIT_FUNC
        self.can_be_harness, self.cannot_har_reason = self.harness_preparation(from_forest)
        self.dyninfo = None
        self.is_dyninfo_set = False
        self.gen_tries = 0
        self.last_succ_order = None

        self.relation_built = False

        if tracing:
            self.register_slice()

    def __str__(self):
        #seqs = list(self.seqs)
        #seqs.sort(key=lambda x: x.id)
        #return '\n'.join([ "%s: %s" % (seq, seq.ftref.func_name) for seq in seqs ])
        return self.name + " <\n" + "\n".join([ str(edge) for edge in self.edges ]) + "\n>" 

    def __repr__(self):
        #seqs = list(self.seqs)
        #seqs.sort(key=lambda x: x.id)
        #return '\n'.join([ "%s: %s" % (seq, seq.ftref.func_name) for seq in seqs ])
        return self.name + " <\n" + "\n".join([ str(edge) for edge in self.edges ]) + "\n>"
    
    @property
    def name(self):
        return "slice_%s_%s" % (self.id, self.label)

    @property
    def simple_name(self):
        return "s_%s_%s" % (self.id, self.label)
    
    def register_slice(self):
        if self.id in all_slices:
            raise Exception("slice %s already has been registered", self.name)
        all_slices[self.id] = self
    
    def deregister_slice(self):
        del all_slices[self.id]

    def add_seq(self, ori_seq):
        if ori_seq in self.seqs:
            return ori_seq
        elif ori_seq.id in self.map_init_seqs:
            return self.map_init_seqs[ori_seq.id]
        else:
            seq_idx = len(self.map_init_seqs)
            new_node = Node.from_id(ori_seq.id).set_slice(self.id, seq_idx)
            self.map_init_seqs[ori_seq.id] = new_node
            self.seqs.add(new_node)
            if new_node.is_func():
                func_name = new_node.ftref.ori_func_name
                if func_name not in self._funcs:
                    self._funcs[func_name] = 1
                else:
                    self._funcs[func_name] += 1
            return new_node

    def add_edge(self, ori_edge):
        key_func = lambda x: x.id

        if ori_edge in self.edges:
            return ori_edge
        elif ori_edge.id in self.map_init_edges:
            return self.map_init_edges[ori_edge.id]
        else:
            from_seq, to_seq = self.add_seq(ori_edge.from_node), self.add_seq(ori_edge.to_node)
            from_tag, to_tag = ori_edge.from_tag, ori_edge.to_tag
            new_edge = Edge(from_seq, from_tag, to_seq, to_tag)

            self.map_init_edges[ori_edge.id] = new_edge

            if from_seq.id not in self.from_edges:
                self.from_edges[from_seq.id] = {}
            if from_tag not in self.from_edges[from_seq.id]:
                self.from_edges[from_seq.id][from_tag] = KeyedSet([], key=key_func)
            self.from_edges[from_seq.id][from_tag].add(new_edge)

            if to_seq.id not in self.to_edges:
                self.to_edges[to_seq.id] = {}
            if to_tag not in self.to_edges[to_seq.id]:
                self.to_edges[to_seq.id][to_tag] = KeyedSet([], key=key_func)
            self.to_edges[to_seq.id][to_tag].add(new_edge)

            self.edges.add(new_edge)
            return new_edge

    def fixup_value_nodes(self):
        # this func is only called when minimal harnesses are built
        # judge whether the in tag needs a value node
        value_node_tags = {}
        for seq in self.seqs:
            for intag in seq.ftref.inargs:
                value_node_tags[(seq.id, intag)] = seq
        for edge in self.edges:
            if edge.from_node.is_func():
                # remove funced tags
                value_node_tags.pop((edge.to_node.id, edge.to_tag), None)
        # add value tags
        for (sid, totag), seq in value_node_tags.items():
            node = None
            if Slice.in_knowledge_base(seq, totag):
                node = KBNode(seq.tfile, seq.tid, seq.tidx, totag)
            elif seq.ftref.inargs[totag].succ:
                node = DumpNode(seq.tfile, seq.tid, seq.tidx, totag)
            else:
                node = FakeNode(seq.tfile, seq.tid, seq.tidx, totag)

            self.add_edge( Edge(node, '.', seq, totag) )

    def dotize(self, path_prefix, func_only=True, test=None, highlighted={}, draw=True):
        dot = Digraph(comment=self.name, format='png')
        #print('current dotize slice is %s %s' % (self.name, self))
        for seq in self.seqs:
            #print('seq is %s' % (seq))
            if seq.is_func():
                vals = []
                for tag, arg in seq.ftref.inargs.items():
                    if arg.succ:
                        vals.append('%s:%s' % (tag, arg.val))
                    else:
                        vals.append('%s:%s' % (tag, '-'))
                for tag, arg in seq.ftref.outargs.items():
                    if arg.succ:
                        vals.append('%s:%s' % (tag, arg.val))
                    else:
                        vals.append('%s:%s' % (tag, '-'))
                node_label = '[%d] %s\n%s\n%s' % (seq.seq_idx, seq.ftref.ori_func_name, fmap[seq.ftref.ori_func_name]['tspell'], ' '.join(vals))
                if seq.ftref.ori_func_name in highlighted:
                    dot.node(str(seq.seq_idx), label=node_label, color=highlighted[seq.ftref.ori_func_name], style='filled')
                else:
                    dot.node(str(seq.seq_idx), label=node_label)
            else:
                if not func_only:
                    node_label = '%s.%s.%s' % (str(seq.seq_idx), seq.totag, seq.ty)
                    dot.node(node_label, label=node_label)
        for edge in self.edges:
            from_idx, from_tag, to_idx, to_tag = edge.from_node.seq_idx, edge.from_tag, edge.to_node.seq_idx, edge.to_tag
            if not edge.to_node.is_func():
                raise Exception('only from node is possible to have value type node, edge: %s' % (str(edge.id)))
            if not edge.from_node.is_func():
                if not func_only:
                    from_idx = '%s.%s.%s' % (edge.from_node.seq_idx, edge.from_node.totag, edge.from_node.ty)
                else:
                    continue
            edge_label = '%s -> %s' % (from_tag, to_tag)
            dot.edge(str(from_idx), str(to_idx), label=edge_label)
        if test != None:
            if draw:
                dot.render((path_prefix + '%s.gv') % ('test' + test), view=False)
            else:
                dot.save((path_prefix + '%s.gv') % ('test' + test))
        else:
            if draw:
                dot.render((path_prefix + '%s.gv') % (self.name), view=False)
            else:
                dot.save((path_prefix + '%s.gv') % (self.name))

    def new_var(self):
        _id = self.var_num
        self.var_num += 1
        return _id

    def harness_preparation(self, from_forest):
        # build to_harness scaffold
        self.vars = { seq.id : {} for seq in self.seqs }

        self.top_table = { seq.id : set([]) for seq in self.seqs }
        self.indegrees = { seq.id : 0 for seq in self.seqs }
        var_num = 0

        for edge in self.edges:
            if edge.to_node.is_func():
                var = None
                from_id, from_tag = edge.from_node.id, edge.from_tag
                to_id, to_tag = edge.to_node.id, edge.to_tag

                # def
                if from_id not in self.vars:
                    self.vars[from_id] = {}
                if from_tag not in self.vars[from_id]:
                    # create a new var
                    # TODO: here didn't consider the non-ret out tag for func
                    #       if from is a func node and non-ret out, use it 
                    #       rather than def a new one
                    var_id = var_num
                    if edge.from_node.is_func():
                        var = FuncOutVar(var_id, edge.from_node, False, from_tag)
                    elif edge.from_node.is_fake():
                        # for value, we use func's tag to label it
                        var = FakeVar(var_id, edge.from_node, None, to_tag)
                    elif edge.from_node.is_dump():
                        # for value, we use func's tag to label it
                        var = MemDumpVar(var_id, edge.from_node, True, to_tag)
                    elif edge.from_node.is_KB():
                        # for value, we use func's tag to label it
                        var = KnowledgeBaseVar(var_id, edge.from_node, True, to_tag, Slice.get_kb_gen(edge.from_node, to_tag))
                    else:
                        raise Exception('from node type is nothing we known')
                    self.vars[from_id][from_tag] = var
                    var_num += 1
                else:
                    # get the var
                    var = self.vars[from_id][from_tag]

                # use
                if to_id not in self.vars:
                    self.vars[to_id] = {}
                self.vars[to_id][to_tag] = var

            self.indegrees[edge.to_node.id] += 1
            self.top_table[edge.from_node.id].add(edge.to_node.id)
        
        indegrees = copy.deepcopy(self.indegrees)

        # top sort to detect ring
        while len(indegrees) != 0:
            zero_ins = [ seqid for seqid, indeg in indegrees.items() if indeg == 0 ]

            if len(zero_ins) == 0:
                # here has a ring!
                return False, 'HAS_RING'

            for _0in in zero_ins:
                del indegrees[_0in]

            for _from in zero_ins:
                for _to in self.top_table[_from]:
                    indegrees[_to] -= 1
        
        # check whether contain init funcs
        # TODO: this should be done earlier, now just put it here
        if not Slice.contain_init_func(self):
            return False, 'NO_INIT_FUNC'

        if not Slice.contain_must_used(self):
            return False, 'NO_MUST_USED'

        if not Slice.contain_uniq_func_at_most_once(self):
            return False, 'UNIQ_FUNC_DISOBEY' 

        if not from_forest:
            for sid in self.to_edges:
                for tag in self.to_edges[sid]:
                    if len(self.to_edges[sid][tag]) > 1:
                        raise Exception('WHY find more than 1 in edge for a given (seq, tag)')

        return True, None

    def to_json(self):
        return { "id": self.id, "name": self.name, "label": self.label, "edges" : [ e.id for e in self.edges ], "core_seq": None if self.core_seq == None else self.core_seq.id}

    @staticmethod
    def skeleton_backward():
        global harness_cfg
        return harness_cfg['input']['skeleton_backward']

    @staticmethod
    def in_knowledge_base(seq, intag):
        return Slice.get_kb_gen(seq, intag) != None

    @staticmethod
    def get_kb_gen(seq, intag):
        global harness_cfg
        global fmap

        types = harness_cfg['types']
        funcargs = harness_cfg['funcargs']

        # is the specific func, intag in kb
        funcname = seq.ftref.ori_func_name
        if (funcname, intag) in funcargs:
            return funcargs[(funcname, intag)]

        typename = None
        for info in fmap[funcname]['in']:
            if info['tag'] == intag:
                typename = tmap[info['tkey']]['tspell']
        for info in fmap[funcname]['out']:
            if info['tag'] == intag:
                typename = tmap[info['tkey']]['tspell']
        
        # is the specific type in kb
        if typename in types:
            return types[typename]
        
        return None

    @staticmethod
    def contain_init_func(sli):
        global harness_cfg

        if harness_cfg['input']['must_contain']:
            return len(set(sli._funcs.keys()) & harness_cfg['input']['init_funcs']) > 0
        else:
            return True

    @staticmethod
    def contain_must_used(sli):
        global harness_cfg
        global fmap

        if len(harness_cfg['must_used']['funcargs']) == 0 and len(harness_cfg['must_used']['types']) == 0:
            return True

        kbseqs = [ seq for seq in sli.seqs if seq.is_value() and seq.is_KB() ]
        kbargs = set([ (seq.ftref.ori_func_name, seq.totag) for seq in kbseqs ])

        if len(harness_cfg['must_used']['funcargs'] & kbargs) > 0:
            return True
        
        kbtys = set()
        for funcname, totag in kbargs:
            typename = None
            for info in fmap[funcname]['in']:
                if info['tag'] == totag:
                    typename = tmap[info['tkey']]['tspell']
            for info in fmap[funcname]['out']:
                if info['tag'] == totag:
                    typename = tmap[info['tkey']]['tspell']
            kbtys.add(typename)
        if len(harness_cfg['must_used']['types'] & kbtys) > 0:
            return True

        return False

    @staticmethod
    def get_init_funcs():
        global harness_cfg
        return set([ func for func in harness_cfg['input']['init_funcs'] ])

    @staticmethod
    def get_steps_to_skeletion():
        global harness_cfg
        return harness_cfg['input']['k_steps_to_core']

    @staticmethod
    def contain_uniq_func_at_most_once(sli):
        for limit_s, list_of_func_list in harness_cfg['input']['uniq_funcs'].items():
            sli_funcs = set(sli._funcs.keys())
            for func_list in list_of_func_list:
                intersection = sli_funcs & set(func_list)
                if len(intersection) > int(limit_s):
                    return False
                counts = 0
                for inter_func in intersection:
                    counts += sli._funcs[inter_func]
                if counts > int(limit_s):
                    return False

        return True

        #overlaps = { func: 0 for func in (set(sli._funcs.keys()) & harness_cfg['input']['uniq_funcs']) }

        #for seq in sli.seqs:
        #    if seq.is_func() and (seq.ftref.ori_func_name in overlaps):
        #        overlaps[seq.ftref.ori_func_name] += 1
        #        if overlaps[seq.ftref.ori_func_name] > 1:
        #            return False
        #return True

    def gen_func_code(self, seq, vardict = {}, gen = lambda x,y,z: None):
        global fmap

        sid = seq.id
        if vardict.get(sid, None) == None:
            vardict[sid] = {}
        else:
            return

        # 1. generate IN
        rest_args = set([ intag for intag in seq.ftref.inargs ])
        # add var from dependency
        vardict[sid]['in'] = {}
        for edge in self.edges:
            if edge.to_node.id == sid:
                dep_seq, dep_tag, tag = edge.from_node, edge.from_tag, edge.to_tag
                self.gen_func_code(dep_seq, vardict, gen)
                #print('edge ', edge)
                vardict[sid]['in'][tag] = vardict[dep_seq.id]['out'][dep_tag]
                rest_args.remove(tag)

        # create var from memory dump or knowledge base
        vardict[sid]['kbase'] = []
        vardict[sid]['mdump'] = []
        for arg_tag in rest_args:
            if Slice.in_knowledge_base(arg_tag):
                var = KnowledgeBaseVar(self.new_var(), seq, True, arg_tag, None)
                vardict[sid]['in'][arg_tag] = var
                vardict[sid]['kbase'].append(var)
            elif seq.ftref.inargs[arg_tag].succ:
                var = MemDumpVar(self.new_var(), seq, True, arg_tag)
                vardict[sid]['in'][arg_tag] = var
                vardict[sid]['mdump'].append(var)
            else:
                vardict[sid]['in'][arg_tag] = FakeVar("XXXX")

        # 2. generate OUT
        #print("ftrace outargs ", seq.ftref.ori_func_name, seq.ftref.outargs)
        vardict[sid]['out'] = {}
        paired = seq.ftref.paired
        if paired:
            for outtag in seq.ftref.outargs:
                #print("fmap ", seq.ftref.ori_func_name, fmap[seq.ftref.ori_func_name]['arg_sizes'])
                if outtag == 'ret' and fmap[seq.ftref.ori_func_name]['arg_sizes'][-1] == -2:
                    vardict[sid]['out'][outtag] = VoidVar()
                else:
                    vardict[sid]['out'][outtag] = FuncOutVar(self.new_var(), seq, False, outtag)
        else:
            if fmap[seq.ftref.ori_func_name]['arg_sizes'][-1] == -2:
                vardict[sid]['out']['ret'] = VoidVar()
            else:
                vardict[sid]['out']['ret'] = FakeVar("YYYY")
        
        gen(self, seq, vardict)

    def to_harness1(self, f):
        if not self.can_be_harness:
            raise Exception("calling to_harness1 while self.can_be_harness == False")

        genseqs = []
        def gen(this, seq, vardict):
            genseqs.append(seq)

        vardict = {}
        self.gen_func_code(self.core_seq, vardict=vardict, gen=gen)

        f.write("int main(int argc, const char * argv[])\n{")

        for seq in genseqs:
            vs = vardict[seq.id]
            # generate vars
            for kbvar in vs['kbase']:
                f.write(kbvar.gen_definition())
            for mdvar in vs['mdump']:
                f.write(mdvar.gen_definition())
            # generate func
            args = [ (int(intag[3:]), str(vs['in'][intag])) for intag in seq.ftref.inargs ]
            args.sort(key=lambda x: x[0])
            args = [ arg[1] for arg in args ]
            #print('%s vs out %s' % (seq.ftref.ori_func_name, vs['out']))
            ret = vs['out']['ret']
            if ret.void:
                f.write('\t\t%s(%s);\n\n' % (seq.ftref.ori_func_name, ','.join(args)))
            else:
                f.write('\t\t%s %s = %s(%s);\n\n' % (ret.type, ret, seq.ftref.ori_func_name, ','.join(args)))

        f.write("\treturn 0;\n}\n")

    def get_var_defs(self):
        codes = []
        for seqid, info in self.vars.items():
            seq = Node.from_id(seqid)
            if seq.is_value():
                for _, var in info.items():
                    codes.append(seq.get_def(var))
        return codes

    def to_harness(self, wrapper, func_seqids):
        global harness_cfg

        if not self.can_be_harness:
            print(self)
            raise Exception("calling to_harness while self.can_be_harness == False")

        codes = []

        codes.append(harness_cfg['wrapper']['prolog'])
        for _, func in wrapper['funcs'].items():
            codes.append(func)

        # harness main code
        if 'harness_main_proto' in wrapper:
            # windows now go to here
            codes.append('%s\n{\n' % (wrapper['harness_main_proto']))
        else:
            codes.append('int harness_main(int argc, const char * argv[])\n{\n')

        codes.append(wrapper['harness_prolog'])

        # var defs
        for seqid, info in self.vars.items():
            seq = Node.from_id(seqid)
            if seq.is_value():
                for _, var in info.items():
                    codes.append(seq.get_def(var))

        # seqed funcs
        for func_seqid in func_seqids:
            seq = Node.from_id(func_seqid)
            #print('generating code of func ', seq, seq.ftref.ori_func_name)
            codes.append(seq.get_use(self.vars))

        codes.append(wrapper['harness_epilog'])

        codes.append('\n\treturn 0;\n}\n')

        # main code
        codes.append(wrapper['main'])

        return '\n'.join(codes)

    def _build_up_relation(self, ins, outs):
        # ins/outs: {(node gaid, node tag) : set([ (slice idx, edge id), ... ])}
        # edge:      (from node, from tag, to node, to tag)
        for edge in self.edges:
            # to node => in table
            inkey = (edge.to_node.gaid, edge.to_tag)
            if inkey not in ins:
                ins[inkey] = set([])
            inval = (self.id, edge.id)
            ins[inkey].add(inval)

            # from node => out table
            outkey = (edge.from_node.gaid, edge.from_tag)
            if outkey not in outs:
                outs[outkey] = set([])
            outval = (self.id, edge.id)
            outs[outkey].add(outval)

    def get_relation_tables(self):
        if not self.relation_built:
            # ins/outs: {(node gaid, node tag) : set([ (slice idx, edge id), ... ])}
            # edge:      (from node, from tag, to node, to tag)
            self._ins, self._outs = {}, {}
            self._build_up_relation(self._ins, self._outs)
            self.relation_built = True
        return self._ins, self._outs

    def build_up_relation(self, ins, outs):
        _ins, _outs = self.get_relation_tables()

        for k, v in _ins.items():
            if k not in ins:
                ins[k] = set([])
            ins[k].update(v)

        for k, v in _outs.items():
            if k not in outs:
                outs[k] = set([])
            outs[k].update(v)

    def relieve_relation(self, ins, outs):
        _ins, _outs = self.get_relation_tables()

        for k, v in _ins.items():
            if k in ins:
                ins[k] = ins[k] - v

        for k, v in _outs.items():
            if k in outs:
                outs[k] = outs[k] - v

    def layered_dep_search(self, seq, tags, edge2key, edge2val, edges, step=-1):
        if not self.can_be_harness:
            raise Exception("calling layered_dep_search while self.can_be_harness == False")

        get_key = lambda x: x.id
        deps = KeyedSet([],key=get_key)

        # get all edges related
        if seq.is_func():
            cache = {}
            for edge in edges:
                k = edge2key(edge)
                if k not in cache:
                    cache[k] = KeyedSet([], key=get_key)
                cache[k].add(edge)

            stack = set([ (seq.id, tag) for tag in tags ])

            while True:
                if len(stack) == 0 or step == 0:
                    break
                
                next_stack = set([])

                while len(stack) > 0:
                    ele = stack.pop()
                    #print('stack pop ', (ele))
                    #print('cache get ', (cache.get(ele, [])))
                    for dep_edge in cache.get(ele, []):
                        deps.add(dep_edge)
                        #print('dep edge ', (dep_edge))
                        #print('stack updates ', (edge2val(dep_edge)))
                        next_stack.update(edge2val(dep_edge))

                stack = next_stack
                if step > 0:
                    step -= 1

        return deps

    # traverse uni-directional, towards backward
    # WARN: backward means from b to a if has relation a -> b
    def get_backward_deps(self, seq, step=-1):
        edge2key = lambda e: (e.to_node.id, e.to_tag)
        edge2val = lambda e: [ (e.from_node.id, intag) for intag in e.from_node.ftref.inargs.keys() ]
        intags = seq.ftref.inargs.keys()
        #print('func name', seq.ftref.func_name, 'seq intags', intags)
        return self.layered_dep_search(seq, intags, edge2key, edge2val, self.edges, step)

    # traverse uni-directional, towards forward
    # WARN: forward means from a to b if has relation a -> b
    def get_forward_deps(self, seq, step=-1):
        edge2key = lambda e: (e.from_node.id, e.from_tag)
        edge2val = lambda e: [ (e.to_node.id, outtag) for outtag in e.to_node.ftref.outargs.keys() ]
        outtags = seq.ftref.outargs.keys()
        return self.layered_dep_search(seq, outtags, edge2key, edge2val, self.edges, step)

    # traverse bi-directional
    def traverse_from_node(self, start_seq, exclude_edges=None, step=-1):
        if not self.can_be_harness:
            raise Exception("calling traverse_from_node while self.can_be_harness == False")

        key_func = lambda x: x.id

        if exclude_edges == None:
            exclude_edges = KeyedSet([], key=lambda x: x.id)
        edges, stack = KeyedSet([], key=key_func), KeyedSet([ start_seq ], key=key_func)

        while True:
            if len(stack) == 0 or step == 0:
                break

            next_stack = KeyedSet([], key=key_func)

            while len(stack) > 0:
                seq = stack.pop()

                for tag in self.from_edges.get(seq.id, set([])):
                    for edge in self.from_edges[seq.id].get(tag, set([])):
                        if edge not in exclude_edges and edge not in edges:
                            edges.add(edge)
                            next_stack.add(edge.to_node)

                for tag in self.to_edges.get(seq.id, set([])):
                    for edge in self.to_edges[seq.id].get(tag, set([])):
                        if edge not in exclude_edges and edge not in edges:
                            edges.add(edge)
                            next_stack.add(edge.from_node)

            stack = next_stack
            if step > 0:
                step -= 1
        
        return edges

    def remove_unnecessary_edges(self, edges, keep_edge):
        # find the node whose outdegree is zero
        outdegrees = {}
        for edge in edges:
            k1 = edge.from_node.id
            k2 = edge.to_node.id
            if k1 not in outdegrees:
                outdegrees[k1] = 0
            if k2 not in outdegrees:
                outdegrees[k2] = 0
            outdegrees[k1] = outdegrees[k1] + 1

        sids = set([])
        for sid, outdeg in outdegrees.items():
            if outdeg == 0:
                sids.add(sid)
        
        if len(sids) == 0:
            raise Exception('wierd, no node outdeg is 0')
        elif len(sids) == 1:
            return Node.from_id(sids.pop()), edges
        else:
            # if more than one, keep the one has the keep_edge
            for sid in sids:
                seq = Node.from_id(sid)
                tags = seq.ftref.inargs.keys()
                edge2key = lambda e: (e.to_node.id, e.to_tag)
                edge2val = lambda e: (e.from_node.id, e.from_tag)
                deps = self.layered_dep_search(seq, tags, edge2key, edge2val, edges)
                if keep_edge in deps:
                    # this is the subgraph contains the keep_edge
                    return seq, deps

    def apply_replace_in(self, edge_change):
        global all_slices

        get_key = lambda x: x.id
        edges = KeyedSet([],key=get_key)
        eaid, ebid, ebsid = edge_change.eaid, edge_change.ebid, edge_change.ebsid
        for ori_edge in self.edges:
            # skip old edge
            if ori_edge.id != eaid:
                edges.add(ori_edge)

        ea = Edge.from_id(eaid)

        # put in the new edges and its backward dependency
        ebsli = all_slices[ebsid]
        eb = Edge.from_id(ebid)

        new_edge = Edge(eb.from_node, eb.from_tag, ea.to_node, ea.to_tag)
        dep_edges = ebsli.get_backward_deps(eb.from_node)

        edges.add(new_edge)
        edges.update(dep_edges)

        #print("RI new edge %s" % (new_edge))
        #print("RI %s dep edges %s" % (ebsli.name, 'dep edges<\n' + '\n'.join([ str(e) for e in dep_edges ]) + '\n>'))
        #print("RI edges %s" % ('edges<\n' + '\n'.join([ str(e) for e in edges ]) + '\n>'))

        # traverse to remove unnecessary edges
        # TODO: currently we still use core_seq in GA, this is due to the use of old 
        #       to_harness code, will update it later
        tmp_slice = Slice(edges=edges)
        if not tmp_slice.can_be_harness:
            return None
        tmp_core_seq = tmp_slice.map_init_seqs[eb.from_node.id]
        edges_subset = tmp_slice.traverse_from_node(tmp_core_seq)

        # return new slice
        #sli = Slice(core_seq=tmp_core_seq, edges=edges_subset, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        #sli.dotize("../workdir/harness_gen/", func_only=True, test=None)
        #sli.to_harness("../workdir/harness_gen/")
        #return sli
        sli = Slice(core_seq=tmp_core_seq, edges=edges_subset, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        if not sli.can_be_harness:
            sli.deregister_slice()
            return None
        return sli

    def apply_replace_out(self, edge_change):
        global all_slices

        get_key = lambda x: x.id

        edges = KeyedSet([],key=get_key)
        removed_edges = KeyedSet([], key=get_key)

        eaid, ebid, ebsid = edge_change.eaid, edge_change.ebid, edge_change.ebsid
        ea = Edge.from_id(eaid)

        removed_seqs = KeyedSet([ edge.to_node for edge in self.get_forward_deps(ea.to_node) ], key=get_key)
        removed_seqs.add(ea.to_node)

        for ori_edge in self.edges:
            # skip old edges related with ea.to_node
            if (ori_edge.from_node not in removed_seqs) and (ori_edge.to_node not in removed_seqs):
                edges.add(ori_edge)
            else:
                removed_edges.add(ori_edge)

        # put in the new edges and its forward dependency
        ebsli = all_slices[ebsid]
        eb = Edge.from_id(ebid)

        new_edge = Edge(ea.from_node, ea.from_tag, eb.to_node, eb.to_tag)
        # TODO: here we add more than 1 layer dependencies, maybe only add one layer is better?
        dep_edges = ebsli.traverse_from_node(eb.to_node, exclude_edges=KeyedSet([ eb ],key=get_key))

        edges.add(new_edge)
        edges.update(dep_edges)

        # remove unnecessary edge
        # TODO: currently we still use core_seq in GA, this is due to the use of old 
        #       to_harness code, will update it later
        tmp_slice = Slice(edges=edges)
        if not tmp_slice.can_be_harness:
            return None
        tmp_core_seq = tmp_slice.map_init_seqs[eb.to_node.id]
        edges_subset = tmp_slice.traverse_from_node(tmp_core_seq)

        #print("RO ebsli %s %s" % (ebsli.name, ebsli))
        #print("RO eb %s" % (eb))
        #print('RO dep edges %s' % (str(dep_edges)))
        #print("RO new edge %s" % (new_edge))
        #print('RO edges_subset %s' % (str(edges_subset)))

        # return new slice
        #sli = Slice(core_seq=tmp_core_seq, edges=edges_subset, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        #print("RO new slice %s %s" % (sli.name, sli))
        #return sli
        sli = Slice(core_seq=tmp_core_seq, edges=edges_subset, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        if not sli.can_be_harness:
            sli.deregister_slice()
            return None
        return sli

    def apply_add_out(self, edge_change):
        global all_slices

        get_key = lambda x: x.id
        edges = KeyedSet([],key=get_key)
        eaid, ebid, ebsid = edge_change.eaid, edge_change.ebid, edge_change.ebsid
        for ori_edge in self.edges:
            # add edge has no old edge need to be skipped
            edges.add(ori_edge)

        ea = Edge.from_id(eaid)

        # put in the new edges and its forward dependency
        ebsli = all_slices[ebsid]
        eb = Edge.from_id(ebid)

        new_edge = Edge(ea.from_node, ea.from_tag, eb.to_node, eb.to_tag)
        # TODO: here we add more than 1 layer dependencies, maybe only add one layer is better?
        dep_edges = ebsli.traverse_from_node(eb.to_node, exclude_edges=KeyedSet([ eb ], key=get_key))

        edges.add(new_edge)
        edges.update(dep_edges)

        #print("AO ebsli %s %s" % (ebsli.name, ebsli))
        #print("AO eb %s" % (eb))
        #print("AO dep edges %s" % ('dep edges<\n' + '\n'.join([ str(e) for e in dep_edges ]) + '\n>'))
        #print("AO new edge %s" % (new_edge))
        #print("AO edges %s" % ('edges<\n' + '\n'.join([ str(e) for e in edges ]) + '\n>'))

        # return new slice
        #sli = Slice(core_seq=self.core_seq, edges=edges, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        #print("AO new slice %s %s" % (sli.name, sli))
        #return sli
        sli = Slice(core_seq=self.core_seq, edges=edges, tracing=True, label="%s_%s_%s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        if not sli.can_be_harness:
            sli.deregister_slice()
            return None
        return sli

    def apply_delete_out(self, edge_change):
        global all_slices

        get_key = lambda x: x.id

        edges = KeyedSet([],key=get_key)
        removed_edges = KeyedSet([], key=get_key)

        ea = Edge.from_id(edge_change.eaid)

        removed_seqs = KeyedSet([ edge.to_node for edge in self.get_forward_deps(ea.to_node) ], key=get_key)
        removed_seqs.add(ea.to_node)

        for ori_edge in self.edges:
            # skip old edges related with ea.to_node
            if (ori_edge.from_node not in removed_seqs) and (ori_edge.to_node not in removed_seqs):
                edges.add(ori_edge)
            else:
                removed_edges.add(ori_edge)

        # just remove old edge is ok
        core_seq = ea.from_node

        #print("DO remove edge %s" % (Edge.from_id(eaid)))
        #print("DO edges %s" % ('edges<\n' + '\n'.join([ str(e) for e in edges ]) + '\n>'))

        # remove unnecessary edge
        # TODO: currently we still use core_seq in GA, this is due to the use of old 
        #       to_harness code, will update it later
        edges_subset = self.traverse_from_node(core_seq, exclude_edges=removed_edges)

        #print("DO edges_subset %s" % ('edges<\n' + '\n'.join([ str(e) for e in edges_subset ]) + '\n>'))

        # return new slice
        # delete edge will not introduce new ring
        if len(edges_subset) > 0:
            sli = Slice(core_seq=core_seq, edges=edges_subset, tracing=True, label="%s_%s" % (edge_change.op, edge_change.easid))
            if not sli.can_be_harness:
                sli.deregister_slice()
                return None
            return sli
        else:
            # TODO: this should be avoided
            sli = Slice(core_seq=core_seq, seqs=[ core_seq ], tracing=True, label="%s_%s" % (edge_change.op, edge_change.easid))
            if not sli.can_be_harness:
                sli.deregister_slice()
                return None
            return sli

    def apply_edge_change(self, edge_change):
        if edge_change.op == EdgeChange.ReplaceIn:
            return self.apply_replace_in(edge_change)
        elif edge_change.op == EdgeChange.ReplaceOut:
            return self.apply_replace_out(edge_change)
        elif edge_change.op == EdgeChange.AddOut:
            return self.apply_add_out(edge_change)
        elif edge_change.op == EdgeChange.DeleteOut:
            return self.apply_delete_out(edge_change)
        else:
            raise Exception("invalid edge_change op")
    
    def get_fitness(self):
        if self.is_dyninfo_set:
            return self.dyninfo
        else:
            raise Exception("%s dyninfo not set" % (self.id))

    def set_fitness(self, score, dyninfo):
        self.score = score
        self.dyninfo = dyninfo
        self.is_dyninfo_set = True
    
    def fitness_is_set(self):
        return self.is_dyninfo_set
    
    def set_nsga2_score(self, dyninfo):
        self.ind = Individual(self.name)
        self.ind.objectives = dyninfo['scores']['nsga2']['objectives']


'''
Forest is different with Slice, there could have more than one edge between two nodes.
Therefore a lot of functions should have its own implementation.
We want to reuse some functions of Slice, therefore Forest is deisgned as a wrap up of 
Slice and provides limited use of inner Slice's functions.
'''
class Forest(object):
    _id = 0

    def __init__ (self, edges, label=''):
        # we reuse slice code here
        global all_forests

        Forest._id += 1
        self.id = Forest._id

        #self.inner = Slice(core_seq=None, seqs=None, edges=edges, add_val_node=False, tracing=True, label=label)
        self.inner = Slice(core_seq=None, seqs=None, edges=edges, add_val_node=False, tracing=False, label=label, from_forest=True)

        self.register_forest()

        self.ins, self.outs = {}, {}
        self.build_up_relation(self.ins, self.outs)

        # every edge & node is unique, therefore they could be indexed by its gaid
        self.nidxs, self.eidxs, self.fidxs = {}, {}, {}
        for edge in self.inner.edges:
            self.eidxs[edge.gaid] = edge

            self.nidxs[edge.from_node.gaid] = edge.from_node
            self.fidxs[edge.from_node.ftref.ori_func_name] = edge.from_node

            self.nidxs[edge.to_node.gaid] = edge.to_node
            self.fidxs[edge.to_node.ftref.ori_func_name] = edge.to_node

    def register_forest(self):
        if self.id in all_forests:
            raise Exception("forest %s already has been registered", self.name)
        all_forests[self.id] = self
    
    def deregister_forest(self):
        self.inner.deregister_slice()
        del all_forests[self.id]

    def build_up_relation(self, ins, outs):
        # ins/outs: {(node gaid, node tag) : set([ edge id, ... ])}
        # edge:      (from node, from tag, to node, to tag)
        for edge in self.inner.edges:
            # to node => in table
            inkey = (edge.to_node.gaid, edge.to_tag)
            if inkey not in ins:
                ins[inkey] = set([])
            inval = edge.id
            ins[inkey].add(inval)

            # from node => out table
            outkey = (edge.from_node.gaid, edge.from_tag)
            if outkey not in outs:
                outs[outkey] = set([])
            outval = edge.id
            outs[outkey].add(outval)

    def get_func_node(self, func_name):
        return self.fidxs.get(func_name, None)

    def find_deps_of_node(self, start_node, must_table):
        get_key = lambda x: x.id

        # must_table:
        # { node id => { intag => edge id } }

        traversed_nodes, edges = KeyedSet([],key=get_key), KeyedSet([],key=get_key)

        depth = 0
        stack = KeyedSet([ start_node ],key=get_key)
        while len(stack) > 0:
            depth += 1
            if depth % 1000 == 0:
                print('recursively call find_deps_of_node %d times now, # of traversed_nodes: %d' % (depth, len(traversed_nodes)))

            node = stack.pop()
            traversed_nodes.add(node)

            if node.is_func():
                for intag in node.ftref.inargs:
                    key = (node.gaid, intag)
                    possible_edges = self.ins.get(key, set([]))
                    if len(possible_edges) == 0:
                        #raise Exception('possible edges are empty set')
                        return None

                    the_edge_id = None
                    if (node.id in must_table) and (intag in must_table[node.id]):
                        the_edge_id = must_table[node.id][intag]
                        if the_edge_id not in possible_edges:
                            raise Exception('must edge not in possible edges')
                        # TODO: avoid the choice of ring
                    else:
                        the_edge_id = random.choice(tuple(possible_edges))
                        # TODO: avoid the choice of ring
                    the_edge = Edge.from_id(the_edge_id)
                    edges.add(the_edge)

                    #print('the edge is %s' % (str(the_edge)))
                    dep_node = the_edge.from_node
                    if dep_node not in traversed_nodes:
                        stack.add(dep_node)
        
        return edges

    def gen_slice_from_core_func(self, core_func, tracing=False, label=''):
        get_key = lambda x: x.id

        seq = self.get_func_node(core_func)
        if seq == None:
            #print('core func %s has not found in forest' % (core_func))
            return None
        edges = self.find_deps_of_node(seq, must_table={})
        if edges == None:
            return None
        return Slice(core_seq=seq, edges=edges, add_val_node=False, tracing=tracing, label=label)

    def gen_slice_from_one_edge_gaid(self, edge_gaid, tracing=False, label=''):
        get_key = lambda x: x.id

        edge = self.eidxs.get(edge_gaid, None)
        if edge == None:
            #print('MOREREASON: 1111111')
            #print('edge gaid %s has not found in forest' % (str(edge_gaid)))
            return None, None
        to_node, to_tag = edge.to_node, edge.to_tag
        must_table = { to_node.id : { to_tag : edge.id } }

        edges = self.find_deps_of_node(to_node, must_table=must_table)
        if edges == None:
            #print('MOREREASON: 2222222')
            return None, None

        sli = Slice(core_seq=None, edges=edges, add_val_node=False, tracing=tracing, label=label)
        #if not sli.can_be_harness:
        #    return None, None
        #else:
        #    return sli.map_init_edges[edge.id].id, sli
        return sli.map_init_edges[edge.id].id, sli


class EdgeChange(object):
    '''
    this declares the change of a slice from edge A to edge B
    '''
    ReplaceIn = "RI"
    ReplaceOut = "RO"
    AddOut = "AO"
    DeleteOut = "DO"

    def __init__(self, easid, eaid, ebsid, ebid, op):
        self.eaid = eaid
        self.easid = easid
        self.ebid = ebid
        self.ebsid = ebsid
        self.op = op


# operator is the operations forming mutation or crossover
class EdgeOperator(object):
    def __init__(self):
        pass

    @staticmethod
    def ix_gen(choosen_slice, ins, outs):
        raise Exception('has not implemented')

    @staticmethod
    def ex_gen(forest, choosen_slice, ins, outs):
        raise Exception('has not implemented')


class ReplaceInEdge(EdgeOperator):
    def __init__(self):
        super(ReplaceInEdge, self).__init__()
        self.abbr = 'RI'

    @staticmethod
    def ix_gen(choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for replace In
        edges = []
        for edge in choosen_slice.edges:
            key = (edge.to_node.gaid, edge.to_tag)
            for slice_id, edge_id in ins.get(key, []):
                if slice_id != choosen_slice.id:
                    edges.append(edge)
                    break
        if len(edges) == 0:
            # no candidates
            return None

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable in
        candidates = []
        key = (edge.to_node.gaid, edge.to_tag)
        for slice_id, edge_id in ins[key]:
            if slice_id != choosen_slice.id:
                candidates.append((slice_id, edge_id))
        ebsid, ebid = random.choice(candidates)

        # make EdgeChange
        #return EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceIn)
        return ( easid, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceIn) ), ( ebsid, EdgeChange(ebsid, ebid, easid, eaid, EdgeChange.ReplaceIn) )

    @staticmethod
    def ex_gen(forest, choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for replace In
        edges = []
        for edge in choosen_slice.edges:
            key = (edge.to_node.gaid, edge.to_tag)
            possible_edge_ids = ins.get(key, set([]))
            if len(possible_edge_ids) > 1:
                edges.append(edge)
        if len(edges) == 0:
            # no candidates
            return None, None

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable in
        candidates = []
        key = (edge.to_node.gaid, edge.to_tag)
        for possible_edge_id in ins[key]:
            possible_edge = Edge.from_id(possible_edge_id)
            if possible_edge.gaid != edge.gaid:
                candidates.append(possible_edge)
        chosen_edge = random.choice(candidates)
        edge_id, tmp_slice = forest.gen_slice_from_one_edge_gaid(chosen_edge.gaid, tracing=True, label='RI_apply_tmp')
        if tmp_slice == None:
            # failed to gen a slice from forest
            return None, None
        elif not tmp_slice.can_be_harness:
            # failed to gen a slice from forest
            tmp_slice.deregister_slice()
            return None, None
        ebsid, ebid = tmp_slice.id, edge_id

        # make EdgeChange
        return tmp_slice, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceIn)

class ReplaceOutEdge(EdgeOperator):
    def __init__(self):
        super(ReplaceOutEdge, self).__init__()
        self.abbr = 'RO'

    @staticmethod
    def ix_gen(choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for replace Out
        edges = []
        for edge in choosen_slice.edges:
            key = (edge.from_node.gaid, edge.from_tag)
            for slice_id, edge_id in outs.get(key, []):
                if slice_id != choosen_slice.id:
                    edges.append(edge)
                    break
        if len(edges) == 0:
            # no candidates
            return None

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable out
        candidates = []
        key = (edge.from_node.gaid, edge.from_tag)
        for slice_id, edge_id in outs[key]:
            if slice_id != choosen_slice.id:
                candidates.append((slice_id, edge_id))
        ebsid, ebid = random.choice(candidates)

        # make EdgeChange
        #return EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceOut)
        return ( easid, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceOut) ), ( ebsid, EdgeChange(ebsid, ebid, easid, eaid, EdgeChange.ReplaceOut) )

    @staticmethod
    def ex_gen(forest, choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for replace Out
        edges = []
        for edge in choosen_slice.edges:
            key = (edge.from_node.gaid, edge.from_tag)
            possible_edge_ids = outs.get(key, [])
            if len(possible_edge_ids) > 1:
                edges.append(edge)
        if len(edges) == 0:
            # no candidates
            return None, None

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable out
        candidates = []
        key = (edge.from_node.gaid, edge.from_tag)
        for possible_edge_id in outs[key]:
            possible_edge = Edge.from_id(possible_edge_id)
            if possible_edge.gaid != edge.gaid:
                candidates.append(possible_edge)
        chosen_edge = random.choice(candidates)
        edge_id, tmp_slice = forest.gen_slice_from_one_edge_gaid(chosen_edge.gaid, tracing=True, label='RO_apply_tmp')
        if tmp_slice == None:
            # failed to gen a slice from forest
            return None, None
        elif not tmp_slice.can_be_harness:
            # failed to gen a slice from forest
            tmp_slice.deregister_slice()
            return None, None
        ebsid, ebid = tmp_slice.id, edge_id

        # make EdgeChange
        return tmp_slice, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.ReplaceOut)


# no add in operator
#class AddInEdge(EdgeOperator):
#    def __init__(self):
#        super(AddInEdge, self).__init__()
#        self.abbr = 'AI'


class AddOutEdge(EdgeOperator):
    def __init__(self):
        super(AddOutEdge, self).__init__()
        self.abbr = 'AO'

    @staticmethod
    def ix_gen(choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for add Out
        edges = []
        for seq in choosen_slice.seqs:
            tags = []
            if seq.is_func():
                tags = seq.ftref.outargs.keys()
            elif seq.is_value():
                tags.append('.')
            for tag in tags:
                key = (seq.gaid, tag)
                for slice_id, edge_id in outs.get(key, []):
                    if slice_id != choosen_slice.id:
                        has_edge = False
                        for edge in choosen_slice.edges:
                            if edge.from_node.id == seq.id and edge.from_tag == tag:
                                edges.append(edge)
                                has_edge = True
                        if not has_edge:
                            edges.append(Edge(seq, tag, Node(None, None, None), None))
                        break
        if len(edges) == 0:
            # no candidates
            return None
        
        edges = [ edge for edge in KeyedSet(edges, key=lambda x: x.id) ]

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable out
        candidates = []
        key = (edge.from_node.gaid, edge.from_tag)
        for slice_id, edge_id in outs[key]:
            if slice_id != choosen_slice.id:
                candidates.append((slice_id, edge_id))
        ebsid, ebid = random.choice(candidates)

        # make EdgeChange
        #return EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.AddOut)
        if edge.to_tag == None:
            return ( ( easid, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.AddOut) ), )
        else:
            return ( easid, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.AddOut) ), ( ebsid, EdgeChange(ebsid, ebid, easid, eaid, EdgeChange.AddOut) )

    @staticmethod
    def ex_gen(forest, choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for add Out
        edges = []
        for seq in choosen_slice.seqs:
            tags = []
            if seq.is_func():
                tags = seq.ftref.outargs.keys()
            elif seq.is_value():
                tags.append('.')
            for tag in tags:
                key = (seq.gaid, tag)
                possible_edge_ids = outs.get(key, [])
                if len(possible_edge_ids) > 0:
                    edges.append(Edge(seq, tag, Node(None, None, None), None))
        if len(edges) == 0:
            # no candidates
            return None, None

        # randomly choose an edge
        edge = random.choice(edges)
        easid, eaid = choosen_slice.id, edge.id

        # randomly choose a suitable out
        key = (edge.from_node.gaid, edge.from_tag)
        chosen_edge_id = random.choice(list(outs[key]))
        chosen_edge = Edge.from_id(chosen_edge_id)
        edge_id, tmp_slice = forest.gen_slice_from_one_edge_gaid(chosen_edge.gaid, tracing=True, label='AO_apply_tmp')
        if tmp_slice == None:
            # failed to gen a slice from forest
            return None, None
        elif not tmp_slice.can_be_harness:
            # failed to gen a slice from forest
            tmp_slice.deregister_slice()
            return None, None
        ebsid, ebid = tmp_slice.id, edge_id

        # make EdgeChange
        return tmp_slice, EdgeChange(easid, eaid, ebsid, ebid, EdgeChange.AddOut)


# no delete in operator
#class DeleteInEdge(EdgeOperator):
#    def __init__(self):
#        super(DeleteInEdge, self).__init__()
#        self.abbr = 'DI'


class DeleteOutEdge(EdgeOperator):
    def __init__(self):
        super(DeleteOutEdge, self).__init__()
        self.abbr = 'DO'

    @staticmethod
    def real_gen(choosen_slice, ins, outs):
        '''
        return None means failed about the the mutation (may not have good candidate)
        '''
        # prepare possible edges for delete Out
        edges = choosen_slice.edges
        #edges = []
        #for edge in choosen_slice.edges:
        #    key = (edge.from_node.gaid, edge.from_tag)
        #    for slice_id, edge_id in outs.get(key, []):
        #        if slice_id != choosen_slice.id:
        #            edges.append(edge)
        #            break
        if len(edges) == 0:
            # no candidates
            return None

        # randomly choose an edge
        edge = random.choice(tuple(edges))
        easid, eaid = choosen_slice.id, edge.id

        # make EdgeChange
        return EdgeChange(easid, eaid, None, None, EdgeChange.DeleteOut)

    @staticmethod
    def ix_gen(choosen_slice, ins, outs):
        return DeleteOutEdge.real_gen(choosen_slice, ins, outs)

    @staticmethod
    def ex_gen(forest, choosen_slice, ins, outs):
        return None, DeleteOutEdge.real_gen(choosen_slice, ins, outs)


class HarnessGenerator(object):
    AS_IT_IS = 'as_it_is'
    RANDOM_ONCE = 'random_once'
    RANDOM_MAX = 'random_max'
    GRADUALLY = 'gradually'

    MAX_TRY = 50

    def __init__(self, work_dir, harness_cfg):
        self.work_dir = work_dir
        # keys: funcargs, types, wrapper
        self.funcargs = harness_cfg['funcargs']
        self.types = harness_cfg['types']
        self.wrapper = harness_cfg['wrapper']
        self.dynamic = harness_cfg['dynamic']
        self.reset_stats()

    def reset_stats(self, excepts=[]):
        _stats = {}
        for k in excepts:
            if k in self.stats:
                _stats[k] = self.stats[k]
        self.stats = _stats

    #def add_stat(self, sli, key, val):
    #    if sli.name not in self.stats:
    #        self.stats[sli.name]

    def update_stats(self, stats):
        self.stats.update(stats)

    def dump_stats(self, work_dir):
        temp = "%-40s%-10s%-10s%-12s%-7s%-7s%-7s\n"
        title = temp % ('Slice', 'Succ', 'Tries', 'Strategy', 'T_all', 'T_dyn', 'T_sco')
        with open(work_dir + 'gen_stat.log', 'a') as f:
            f.write(title)
            for sname, info in self.stats.items():
                f.write(temp % (sname, info['succ'], info['tries'], info['strategy'], int(info['dtime'] + info['stime']), int(info['dtime']), int(info['stime'])))

    def write_to_file(self, path_prefix, name, code, test):
        filename = None
        if test != None:
            filename = path_prefix + 'test' + test + '.mm'
        else:
            filename = path_prefix + name + '.mm'

        with open(filename, 'w') as f:
            f.write(code)
        
        return filename

    def dynamic_probing(self, codefile, test):
        code = codefile
        binary = code + ".bin"
        covjson = None
        if test != None:
            covjson = self.work_dir + 'cov' + test + '.json'
        else:
            covjson = self.work_dir + 'cov.json'
        #print('covjson is %s' % (covjson))

        shellcnt = self.dynamic['shell'] % (code, binary, covjson, test)
        shellfile = None
        if test != None:
            shellfile = self.work_dir + 'dyn_probe' + test + '.sh'
        else:
            shellfile = self.work_dir + 'dyn_probe' + '.sh'
        with open(shellfile, 'w') as f:
            f.write(shellcnt)

        # 1. compile
        ret = os.system('bash %s compile' % (shellfile))
        if ret != 0:
            # WARN: we think this is a harness generator's bug
            #       possibly an incomplete knowledge base
            #raise Exception('shell %s failed to compile the harness' % (shellfile))
            return None

        # 2. get dyninfo
        ret = os.system('bash %s dyninfo' % (shellfile))
        if ret != 0:
            # WARN: we think this is due to bad harness (cannot finish execution normally)
            #raise Exception('shell %s failed to get dyninfo normally' % (shellfile))
            return None
        else:
            return libdyn.call_as_lib(covjson)
    
    def gen_and_run(self, sli, func_orders, get_dyninfo, test):
        code = sli.to_harness(self.wrapper, func_orders)
        codefile = self.write_to_file(self.work_dir, sli.name, code, test)

        dyninfo = None
        if get_dyninfo:
            dyninfo = self.dynamic_probing(codefile, test)

        return codefile, dyninfo

    def choose_as_it_is(self, l):
        return 0
    
    def choose_randomly(self, l):
        return random.randint(0, len(l) - 1)

    def gen_func_orders(self, sli, selector):
        func_orders = []

        indegrees = copy.deepcopy(sli.indegrees)
        zero_ins = [ seqid for seqid, indeg in indegrees.items() if indeg == 0 ]
        while len(zero_ins) != 0:

            # as it is means always choose the first one of the list
            choosen_idx = selector(zero_ins)
            _0in = zero_ins[choosen_idx]
            zero_ins.pop(choosen_idx)

            del indegrees[_0in]
            for _to in sli.top_table[_0in]:
                indegrees[ _to ] -= 1
                if indegrees[ _to ] == 0:
                    zero_ins.append(_to)

            if Node.from_id(_0in).is_func():
                func_orders.append(_0in)

        if (len(zero_ins) == 0) and (len(indegrees) != 0):
            # here should not has a ring!
            raise Exception('still has a ring during the to_harness stage')
        
        return func_orders

    def gen_as_it_is(self, sli, get_dyninfo, test):
        func_orders = self.gen_func_orders(sli, self.choose_as_it_is)

        codefile, dyninfo = self.gen_and_run(sli, func_orders, get_dyninfo, test)
        if dyninfo != None:
            self.stats[sli.name] = { 'succ': True, 'tries': 1, 'strategy': 'as_it_is', 'succ_order': func_orders }
        else:
            self.stats[sli.name] = { 'succ': False, 'tries': 1, 'strategy': 'as_it_is', 'succ_order': None }
        return codefile, dyninfo

    def gen_random_once(self, sli, get_dyninfo, test):
        func_orders = self.gen_func_orders(sli, self.choose_randomly)

        codefile, dyninfo = self.gen_and_run(sli, func_orders, get_dyninfo, test)
        if dyninfo != None:
            # succ
            sli.last_succ_order = func_orders

        sli.gen_tries = sli.gen_tries + 1

        return codefile, dyninfo

    def gen_random_max(self, sli, get_dyninfo, test):
        codefile, dyninfo = None, None

        if sli.name in self.stats:
            # check whether already tried
            if not self.stats[sli.name]['succ']:
                #print('111111 sli %s reuse fail with %s' % (sli.name, self.stats[sli.name]['tries']))
                return None, None
            else:
                #print('222222 sli %s reuse succ with %s' % (sli.name, self.stats[sli.name]['tries']))
                self.gen_and_run(sli, self.stats[sli.name]['succ_order'], get_dyninfo, test)
        else:
            for i in range(0, HarnessGenerator.MAX_TRY):
                codefile, dyninfo = self.gen_random_once(sli, get_dyninfo, test)

                if dyninfo != None:
                    # succ
                    #print('333333 sli %s succ with %s' % (sli.name, sli.gen_tries))
                    self.stats[sli.name] = { 'succ': True, 'tries': sli.gen_tries, 'strategy': 'random_max', 'succ_order': sli.last_succ_order }
                    return codefile, dyninfo
        
            #print('444444 sli %s fail with %s' % (sli.name, sli.gen_tries))
            self.stats[sli.name] = { 'succ': False, 'tries': sli.gen_tries, 'strategy': 'random_max', 'succ_order': None }
            return codefile, dyninfo
        
    def gen_gradually(self, sli, get_dyninfo, test):
        raise Exception('has not be implemented')

    def gen(self, strategy, sli, get_dyninfo=False, test=None):
        #print('\n>>> generating harness of slice %s using strategy %s <<<' % (sli.name, strategy))

        # different strategy means different generation orders of the funcs (this might gotten from multiple real execution)
        # for now, we fix it or use kb, possibly we could do better using more heuristics
        if strategy == HarnessGenerator.AS_IT_IS:
            return self.gen_as_it_is(sli, get_dyninfo, test)
        elif strategy == HarnessGenerator.RANDOM_ONCE:
            return self.gen_random_once(sli, get_dyninfo, test)
        elif strategy == HarnessGenerator.RANDOM_MAX:
            return self.gen_random_max(sli, get_dyninfo, test)
        elif strategy == HarnessGenerator.GRADUALLY:
            return self.gen_gradually(sli, get_dyninfo, test)
        else:
            raise Exception("unknown harness generation strategy")


# compute fitness in parallel
def fitness_do_func(idx, args):
    global all_slices
    global ga

    sli_id = args

    #return (0, sli_id, 0)

    # TODO: calculate the fitness, need to use real run for coverage
    sli = all_slices[sli_id]

    #sli.dotize(ga.work_dir, func_only=False, test=str(idx))
    #sli.dotize(ga.work_dir, func_only=False, test=sli.name, draw=False)
    #print('the slice name is %s' % (sli.name))

    dstart = datetime.datetime.now()

    ga.hg.reset_stats(excepts=[sli.name])

    _, raw_dyninfo = ga.hg.gen(ga.hg_strategy, sli, get_dyninfo=True, test=str(idx))
    #_, raw_dyninfo = ga.hg.gen(ga.hg_strategy, sli, get_dyninfo=True, test=sli.name)

    dend = datetime.datetime.now()
    dtime = (dend - dstart).total_seconds()

    #sli.dotize(ga.work_dir, func_only=False, test=sli.name)

    sstart = datetime.datetime.now()

    score, dyninfo = ga.fitness_score(sli, raw_dyninfo)
    #print('slice %s score is %s' % (sli.name, score))
    
    send = datetime.datetime.now()
    stime = (send - sstart).total_seconds()

    #print('ga.hg.stats %s', str(ga.hg.stats.keys()))
    ga.hg.stats[sli.name]['dtime'] = dtime
    ga.hg.stats[sli.name]['stime'] = stime

    # WARN: just use None for dyninfo to avoid unnecessary data transfer
    # we don't actually use dyninfo in main process now
    return (score, sli_id, dyninfo, ga.hg.stats)
    #return (score, sli_id, None, ga.hg.stats)


def show_slice_do_func(idx, args):
    global all_slices
    global ga

    sli_id = args

    # TODO: calculate the fitness, need to use real run for coverage
    sli = all_slices[sli_id]
    ga.hg.gen(ga.hg_strategy, sli, get_dyninfo=False, test=sli.name)
    sli.dotize(ga.work_dir, func_only=False, test=sli.name, draw=False)
    sli.dotize(ga.work_dir, func_only=True, test=sli.name+'_func_only', draw=False)


def dump_slice_do_func(idx, args):
    global all_slices
    global ga

    sli_id = args

    # TODO: calculate the fitness, need to use real run for coverage
    sli = all_slices[sli_id]
    #ga.hg.gen(ga.hg_strategy, sli, get_dyninfo=False, test=sli.name)
    with open(ga.work_dir + '%s.json' % (sli.name), 'w') as f:
        json.dump(sli.to_json(), f)

unreturned_slices = []

def mutation_do_func(idx, args):
    global ga
    global unreturned_slices

    # possibility for choosing mutate in (mutate, crossover)
    #mutated_number = args

    serial_slices = []

    if len(unreturned_slices) == 0:
        new_slices = ga._mutation_loop(1, strict=False)
        #new_slices = ga._mutation_loop(mutated_number, strict=False)
        unreturned_slices.extend(new_slices)

    new_slice = unreturned_slices.pop(0)

    #print('before %s has %d nodes, can be harness %s' % (new_slice.name, len(new_slice.seqs), new_slice.can_be_harness))

    # use no_id to wipe the slice id info to correct serialize/deserialize slice's nodes/edges
    tmp_slice = Slice(core_seq=new_slice.core_seq, seqs=new_slice.seqs, edges=new_slice.edges, tracing=False, label=new_slice.label, no_id=True)
    serial_slices.append( (tmp_slice.name, 'p' + str(idx) + '_' + tmp_slice.label, [ seq.id for seq in tmp_slice.seqs ], [ edge.id for edge in tmp_slice.edges ]) )

    #label = 'p%s_%s' % (idx, new_slice.label)
    #new_slice.dotize(ga.work_dir, func_only=False, test=label, draw=False)
    #serial_slices.append( (new_slice.name, 'p' + str(idx) + '_' + new_slice.label, [ seq.id for seq in new_slice.seqs ], [ edge.id for edge in new_slice.edges ]) )

    new_slice.deregister_slice()

    return serial_slices


class GA_Harness(object):
    def __init__(self, slices, work_dir, core_funcs, forest):
        global harness_cfg

        self.work_dir = work_dir
        self.core_funcs = core_funcs

        # build tables from N
        self.N = [ sli for sli in slices if sli.can_be_harness ]
        print("init N filtered from %d to %d" % (len(slices), len(self.N)))

        #self.ex_ins, self.ex_outs = {}, {}
        #for sli in self.N:
        #    sli.build_up_relation(self.ex_ins, self.ex_outs)
        self.forest = forest
        self.ex_ins, self.ex_outs = forest.ins, forest.outs

        # self.residents is M
        self.residents = None
        self.fitnesses, self.last_fitnesses = None, None

        # harness generator
        self.hg = HarnessGenerator(self.work_dir, harness_cfg)
        self.hg_strategy = HarnessGenerator.AS_IT_IS
        #self.hg_strategy = HarnessGenerator.RANDOM_MAX

        # switches
        self.max_rounds = 200
        self.mutated_number = 200
        self.popu_limit = 50
        #self.selection = 'MULTI_ROUND_WITH_SCORE'
        #self.selection = 'TOP_SCORE'
        self.selection = 'NSGA2_PARETO'
        self.in_mutators = [ ReplaceInEdge(), ReplaceOutEdge(), AddOutEdge() ]
        self.out_mutators = [ ReplaceInEdge(), ReplaceOutEdge(), AddOutEdge(), DeleteOutEdge() ]
        #self.flows = [ 'CM2P' ]
        self.flows = [ 'CM' ]
        #self.flows = [ 'CO', 'MO', 'CM', 'CM2P' ]
        self.p_cross = 0.5

        self.log = self.work_dir + 'ga.log'
        if self.selection == 'NSGA2_PARETO':
            self.log_table_temp = '%-25s | %-8s | %-10s | %-6s | %-6s | %-7s | %-15s\n'
        else:
            self.log_table_temp = '%-25s | %-8s | %-3s | %-14s | %-3s | %-7s | %-15s\n'
        with open(self.log, 'w') as f:
            #f.write('SUMMARY: # round %d, # of mutation %d, popu limit %d, selection %s, mutators %s, p_cross %.2f, hg_method %s\n' % (self.max_rounds, self.mutated_number, self.popu_limit, self.selection, '[' + ' '.join([ m.abbr for m in self.mutators ]) + ']', self.p_cross, self.hg_strategy))
            f.write('SUMMARY: # round %d, # of mutation %d, popu limit %d, selection %s, in/out mutators %s/%s, flows %s, hg_method %s\n' % (self.max_rounds, self.mutated_number, self.popu_limit, self.selection, '[' + ' '.join([ m.abbr for m in self.in_mutators ]) + ']', '[' + ' '.join([ m.abbr for m in self.out_mutators ]) + ']',  ' '.join(self.flows), self.hg_strategy))
            f.write('\n')
            if self.selection == 'NSGA2_PARETO':
                f.write(self.log_table_temp % ('        TITLE', '   F/E', '    EFF', 'DIV', 'COMP', 'CROWD', "Chosen Info"))
            else:
                f.write(self.log_table_temp % ('        TITLE', ' Score', 'F', '     P_cov', 'mCC', 'iUN/oUN', "Chosen Info"))
            f.write('\n')
        
        self.rounds_info = []
        self.shown = set([])
        self.dumped = set([])

    # draw residents graph
    def show_residents(self):
        all_args = []
        for sli in self.residents:
            all_args = [ sli.id for sli in self.residents if sli.id not in self.shown ]

        def rslt_handle(anyway):
            pass

        utils.do_in_parallel_with_idx(show_slice_do_func, all_args, rslt_handle, debug=False)
        self.shown.update(set(all_args))

    # dump residents' json
    def dump_residents(self):
        all_args = []
        for sli in self.residents:
            all_args = [ sli.id for sli in self.residents if sli.id not in self.dumped ]

        def rslt_handle(anyway):
            pass

        utils.do_in_parallel_with_idx(dump_slice_do_func, all_args, rslt_handle, debug=False)
        self.dumped.update(set(all_args))

    def generate_initial_population(self):
        # TODO: choose M from N using fitness function or randomly select
        self.residents = [ sli for sli in self.N ]

        self.ix_ins, self.ix_outs = {}, {}
        for sli in self.residents:
            sli.build_up_relation(self.ix_ins, self.ix_outs)

    # this function is called in multi-processing context
    # dyninfo is not set to sli yet
    def fitness_score(self, sli, raw_dyninfo):
        #return raw_dyninfo['bb_count'] if raw_dyninfo != None else 0, raw_dyninfo

        if raw_dyninfo == None:
            raw_dyninfo = { 'trace_bbs': [], 'bb_count': 0 }

        def get_core_data_flow(sli):
            # get the input-related edges & nodes, others are oUNs
            key_func = lambda x: x.id
            core_seqs, core_edges = KeyedSet([], key=key_func), KeyedSet([], key=key_func)
            step = Slice.get_steps_to_skeletion()
            if step >= 0:
                # 1. find input related
                init_funcs = Slice.get_init_funcs()
                for seq in sli.seqs:
                    if seq.is_func() and (seq.ftref.ori_func_name in init_funcs):
                        if Slice.skeleton_backward():
                            core_edges.update( sli.get_backward_deps(seq) )
                        core_edges.update( sli.get_forward_deps(seq) )

                # 2. find the nodes & edges in 3 steps
                for edge in core_edges:
                    core_seqs.add(edge.from_node)
                    core_seqs.add(edge.to_node)
                for seq in core_seqs:
                    core_edges.update( sli.traverse_from_node(seq, step=step) )
                for edge in core_edges:
                    core_seqs.add(edge.from_node)
                    core_seqs.add(edge.to_node)
            else:
                core_edges = sli.edges
                core_seqs = sli.seqs

            return core_edges, core_seqs

        def calc_nsga2_scores(sli, raw_dyninfo):
            global ida_cov

            dyninfo = { 'bbs': set(), 'funcs': {}, 'scores': {} }

            # 1. effectiveness, sigma (bb with scores)
            effectiveness = 0
            for libname, offset in raw_dyninfo['trace_bbs']:
                if libname not in dyninfo['funcs']:
                    dyninfo['funcs'][libname] = {}

                # get the func it belongs to
                funcname, _, has_call, in_loop = ida_cov['covs'].get((libname, offset), (None, None, False, False))
                if funcname == None:
                    #raise Exception("Traced library %s offset 0x%x not in any known functions" % (libname, offset))
                    #print("WARN: Traced library %s offset 0x%x not in any known functions" % (libname, offset))
                    continue
                else:
                    effectiveness = effectiveness + 1 + has_call + in_loop

                #print('match a %s %s bb %x' % (libname, funcname, ida_offset))

            key_func = lambda x: x.id
            core_edges, core_seqs = get_core_data_flow(sli)

            # 2. diversity, edge num
            unique_funcs = set([ seq.ftref.ori_func_name for seq in core_seqs if seq.is_func() ])
            func_edges = KeyedSet([ edge for edge in core_edges if (edge.from_node.is_func() and edge.to_node.is_func()) ], key=key_func)
            get_feature = lambda edge: (edge.from_node.ftref.ori_func_name, edge.from_tag, edge.to_node.ftref.ori_func_name, edge.to_tag)
            refined_func_edges = KeyedSet(func_edges, key=get_feature)

            # modified cyclomatic complexity
            F = len(unique_funcs)
            E = len(refined_func_edges)
            CC = (E - F + 2) if F > 0 else 0

            diversity = E + CC

            # 3. compactness
            # high compactness <=> low duplication, low unnecessary function calls, high data flow interaction 
            touch_edge, duped_seqs = set(), KeyedSet([], key=key_func)
            for edge in func_edges:
                key = get_feature(edge)
                if key not in touch_edge:
                    touch_edge.add(key)
                else:
                    # a duped edge
                    duped_seqs.add( edge.to_node )

            incom_dict = { 'duplicate': {}, 'unique': [] }
            for seq in core_seqs:
                if seq.is_func():
                    funcname = seq.ftref.ori_func_name

                    base, interaction, unne = 0, 0, 0.
                    # for each in arg, calc now & best
                    for arg_tag in seq.ftref.inargs:
                        the_edges = sli.to_edges.get(seq.id, {}).get(arg_tag, set([]))
                        if len(the_edges) != 1:
                            raise Exception('why find %d the_edge' % (len(the_edges)))

                        the_edge = list(the_edges)[0]

                        base += 1
                        if the_edge in func_edges:
                            # if arg is in Dataflow func edges, interaction +2
                            if interaction == 0:
                                interaction = 1
                            else:
                                interaction += 2
                        else:
                            if the_edge.from_node.is_func():
                                un_seqs_set = KeyedSet([], key=key_func)
                                excludes = KeyedSet(core_edges, key=key_func)
                                excludes.add( the_edge )
                                edges_subset = sli.traverse_from_node(the_edge.from_node, exclude_edges=excludes)
                                for edge in edges_subset:
                                    if edge.from_node.is_func() and (edge.from_node not in core_seqs):
                                        un_seqs_set.add(edge.from_node)
                                    if edge.to_node.is_func() and (edge.to_node not in core_seqs):
                                        un_seqs_set.add(edge.to_node)
                                un_func_num = len(un_seqs_set)

                                # if arg is not in Dataflow and is a func relation, unne +1/func?
                                if un_func_num >= 5:
                                    unne += 1
                                else:
                                    unne += (un_func_num / 5.)
                            else:
                                # if arg is not in Dataflow and is dump/kb, nothing
                                interaction += 1
                    
                    if seq in duped_seqs:
                        if funcname not in incom_dict['duplicate']:
                            incom_dict['duplicate'][funcname] = []
                        incom_dict['duplicate'][funcname].append( { 'base': base, 'inter': interaction, 'unne': unne } )
                    else:
                        incom_dict['unique'].append( { 'base': base, 'inter': interaction, 'unne': unne } )

            all_com, all_base = 0., 0
            calc_base = lambda info: info['base']
            calc_com = lambda info: info['inter'] - info['unne']
            for info in incom_dict['unique']:
                all_com = all_com + calc_com(info)
                all_base = all_base + calc_base(info)
            for _, info_list in incom_dict['duplicate'].items():
                all_com = all_com + max([ calc_com(info) for info in info_list ])
                all_base = all_base + sum([ calc_base(info) for info in info_list ])

            compactness = all_com / float(all_base) if all_base > 0 else 0

            dyninfo['scores']['score'] = 0
            dyninfo['scores']['nsga2'] = {}
            dyninfo['scores']['nsga2']['EFF'] = effectiveness
            dyninfo['scores']['nsga2']['DIV'] = diversity
            dyninfo['scores']['nsga2']['COMP'] = compactness
            dyninfo['scores']['nsga2']['objectives'] = (diversity, effectiveness, compactness)

            dyninfo['scores']['F'] = F
            dyninfo['scores']['E'] = E
            dyninfo['scores']['mCC'] = 0
            dyninfo['scores']['P_cov'] = 0
            dyninfo['scores']['bb_num'] = raw_dyninfo['bb_count']
            dyninfo['scores']['iUN'] = 0
            dyninfo['scores']['oUN'] = 0

            return 0, dyninfo
        
        def calc_ga_scores(sli, raw_dyninfo):
            global ida_cov

            key_func = lambda x: x.id

            # build dyninfo
            # lib => func => set of offsets
            dyninfo = { 'bbs': set(), 'funcs': {}, 'scores': {} }
            if self.selection != 'TOP_SCORE':
                dyninfo = { 'bbs': set(raw_dyninfo['trace_bbs']), 'funcs': {}, 'scores': {} }
            #dyninfo = { 'bbs': set(), 'funcs': {}, 'scores': {} }
            #for libname, offset in raw_dyninfo['trace_bbs']:
            #    if libname not in dyninfo['funcs']:
            #        dyninfo['funcs'][libname] = {}

            #    # get the func it belongs to
            #    funcname, ida_offset, _, _ = ida_cov['covs'].get((libname, offset), (None, None, False, False))
            #    if funcname == None:
            #        #raise Exception("Traced library %s offset 0x%x not in any known functions" % (libname, offset))
            #        #print("WARN: Traced library %s offset 0x%x not in any known functions" % (libname, offset))
            #        continue

            #    #print('match a %s %s bb %x' % (libname, funcname, ida_offset))

            #    # add to dyninfo
            #    if funcname not in dyninfo['funcs'][libname]:
            #        dyninfo['funcs'][libname][funcname] = set([])
            #    dyninfo['funcs'][libname][funcname].add(ida_offset)

            #    #for libname, info in dyninfo['funcs'].items():
            #    #    print('dyninfo lib %s has %d funcs' % (libname, len(info)))

            #    dyninfo['bbs'].add((libname, ida_offset))
        
            ## use dyninfo to calculate fitness score
            #func_covs = {}
            #for libname, libinfo in dyninfo['funcs'].items():
            #    for funcname, offsets in libinfo.items():
            #        all_num = ida_cov['funcs'][libname][funcname]
            #        traced_num = len(offsets)
            #        #print('sli %s lib %s func %s all_num %d' % (sli.name, libname, funcname, all_num))
            #        func_covs[(libname, funcname)] = float(traced_num) / float(all_num)

            # TODO: now we use mathmatical average, and we use all functions in all traced modules
            #print('sli %s func_covs len %d' % (sli.name, len(func_covs)))
            avg_pcov = float(raw_dyninfo['bb_count']) / len(ida_cov['covs'])
            #avg_pcov = 0.
            #if len(func_covs) != 0:
            #    for _, p in func_covs.items():
            #        avg_pcov += p 
            #    avg_pcov /= len(func_covs)

            # get the input-related edges & nodes, others are oUNs
            core_edges, core_seqs = get_core_data_flow(sli)

            # 3. use them to calculate score
            unique_seqs = KeyedSet([ seq for seq in core_seqs if seq.is_func() ], key=key_func)
            unique_funcs = set([ seq.ftref.ori_func_name for seq in core_seqs if seq.is_func() ])
            func_edges = [ edge for edge in core_edges if (edge.from_node.is_func() and edge.to_node.is_func()) ]
            all_func_edges = [ edge for edge in sli.edges if (edge.from_node.is_func() and edge.to_node.is_func()) ]

            get_feature = lambda edge: (edge.from_node.ftref.ori_func_name, edge.from_tag, edge.to_node.ftref.ori_func_name, edge.to_tag)
            refined_func_edges = KeyedSet(func_edges, key=get_feature)

            kf, kc, ku, kou = 1., 1., 3., 3.

            P_cov = avg_pcov
            iUN = len(func_edges) - len(refined_func_edges)
            oUN = len(all_func_edges) - len(func_edges)

            # modified cyclomatic complexity
            F = len(unique_funcs)
            E = len(refined_func_edges)
            cUN = len(unique_seqs) - len(unique_funcs) - iUN
            mCC = ( E - F + 2 * 1 - (cUN/2.) ) if F > 0 else 0
            #print('%s E %d F %d minus %f mCC %f (seqs %d, funcs %d)' % (sli.name, E, F, (len(unique_seqs) - len(unique_funcs))/2., mCC, len(unique_seqs), len(unique_funcs)))

            if iUN < 0:
                raise Exception("%s iUN is lower than 0, %d - %d = %d" % (sli.name, len(func_edges), len(refined_func_edges), iUN))
            if oUN < 0:
                raise Exception("%s oUN is lower than 0, %d - %d = %d" % (sli.name, len(all_func_edges), len(func_edges), oUN))

            score = 0
            if P_cov != 0:
                #score = F * (kf + kp * P_cov) + kc * mCC - ku * iUN - kou * oUN
                score = (kf * F + kc * mCC - ku * iUN - kou * oUN) * P_cov

            print('%-30s score %.4f F %2d P_cov %.4f(%d/%d) mCC %f iUN %2d oUN %2d' % (sli.name, score, F, P_cov, raw_dyninfo['bb_count'], len(ida_cov['covs']), mCC, iUN, oUN))

            dyninfo['scores']['score'] = score
            dyninfo['scores']['F'] = F
            dyninfo['scores']['E'] = E
            dyninfo['scores']['mCC'] = mCC
            dyninfo['scores']['P_cov'] = P_cov
            dyninfo['scores']['bb_num'] = raw_dyninfo['bb_count']
            dyninfo['scores']['iUN'] = iUN
            dyninfo['scores']['oUN'] = oUN

            return score, dyninfo

        if self.selection == 'NSGA2_PARETO':
            return calc_nsga2_scores(sli, raw_dyninfo)
        else:
            return calc_ga_scores(sli, raw_dyninfo)


    def compute_fitness_and_weed(self):
        all_args = []
        for sli in self.residents:
            all_args = [ sli.id for sli in self.residents if not sli.fitness_is_set() ]

        #print('fitness compute all_args len: %d' % (len(all_args)))

        def keep_high_score(_ga, no_zero_fitness=True):
            # weed low score residents
            # TODO: multiple metrics & survivor selection
            all_fitnesses = [ (sli.score, None, sli) for sli in _ga.residents ]
            all_fitnesses.sort(key=lambda x : x[0], reverse=True)

            weeded_targets = []
            for i in range(0, len(all_fitnesses)):
                if i >= _ga.popu_limit:
                    weeded_targets.append(all_fitnesses[i])
                elif no_zero_fitness and (all_fitnesses[i][0] <= 0):
                    weeded_targets.append(all_fitnesses[i])

            fitnesses = [ x for x in all_fitnesses[:_ga.popu_limit] if (not no_zero_fitness) or (x[0] > 0) ]

            return fitnesses, weeded_targets

        def multi_round_with_score(_ga, max_rounds=3):
            # WARN: now selection strategy add info into dyninfo['selection'] for better debugging & logging
            candidates = [ (sli.score, sli) for sli in _ga.residents if sli.score > 0 ]
            weeded_targets = [ (sli.score, None, sli) for sli in _ga.residents if sli.score <= 0 ]
            chosen = []
            round = 1

            #_ga.log_str('STEP1: candidates %d, weeded %d, residents %d\n' % (len(candidates), len(weeded_targets), len(_ga.residents)))
            if len(candidates) + len(weeded_targets) != len(_ga.residents):
                raise Exception('error: len(candidates) + len(weeded_targets) != len(_ga.residents)')

            #while (len(candidates) > 0) and ( (round <= max_rounds) or (len(chosen) <= _ga.popu_limit) ):
            #while (len(candidates) > 0) and ( (len(chosen) <= _ga.popu_limit) or (len(chosen) > _ga.popu_limit and round == 1 ) ):
            while (len(candidates) > 0):
                if len(chosen) > _ga.popu_limit and round != 1:
                    break
                if round > max_rounds:
                    break
                all_bbs = set([])
                new_choosen = []
                candidates.sort(key=lambda x: x[0], reverse=True)

                for cand_score, cand in candidates:
                    cand_set = cand.dyninfo['bbs']
                    new_bb_num = len(cand_set - all_bbs)
                    if new_bb_num > 0:
                        candidates.remove( (cand_score, cand) )
                        all_bbs.update(cand_set)
                        new_choosen.append( (cand_score, new_bb_num, cand) )

                all_bb_num = len(all_bbs)
                for one in new_choosen:
                    choose_info = { 'round': round, 'new_bb_num': one[1], 'all_bb_num': all_bb_num }
                    chosen.append( (one[0], choose_info, one[2]) )
                    #print('chosen %s with info %s' % (one[2].name, choose_info))

                round += 1
            
            #_ga.log_str('STEP2: candidates %d, chosen %d, weeded %d, residents %d\n' % (len(candidates), len(chosen), len(weeded_targets), len(_ga.residents)))
            weeded_targets.extend( [ (x[0], None, x[1]) for x in candidates] )
            #_ga.log_str('STEP3: chosen %d, weeded %d, residents %d\n' % (len(chosen), len(weeded_targets), len(_ga.residents)))
            return chosen, weeded_targets

        def fast_nondominated_sort(residents):
            fronts = [[]]
            for p in residents:
                p.ind.domination_count = 0
                p.ind.dominated_solutions = []
                for q in residents:
                    if p.ind.dominates(q.ind):
                        p.ind.dominated_solutions.append(q)
                    elif q.ind.dominates(p.ind):
                        p.ind.domination_count += 1
                if p.ind.domination_count == 0:
                    p.ind.rank = 0
                    fronts[0].append(p)
            i = 0
            while len(fronts[i]) > 0:
                temp = []
                for p in fronts[i]:
                    for q in p.ind.dominated_solutions:
                        q.ind.domination_count -= 1
                        if q.ind.domination_count == 0:
                            q.ind.rank = i+1
                            temp.append(q)
                i = i+1
                fronts.append(temp)
            
            return fronts

        def calc_crowding_distance(front):
            if len(front) > 0:
                solutions_num = len(front)
                for s in front:
                    s.ind.crowding_distance = 0.

                for m in range(len(front[0].ind.objectives)):
                    front.sort(key=lambda s: s.ind.objectives[m])
                    front[0].ind.crowding_distance = 10**9.
                    front[solutions_num-1].ind.crowding_distance = 10**9.
                    m_values = [s.ind.objectives[m] for s in front]
                    scale = max(m_values) - min(m_values)
                    if scale == 0:
                        scale = 1.
                    for i in range(1, solutions_num-1):
                        front[i].ind.crowding_distance += (front[i+1].ind.objectives[m] - front[i-1].ind.objectives[m])/float(scale)

        def nsga2_selection(_ga):
            candidates, chosen, weeded_targets = [], [], []

            for sli in _ga.residents:
                if sli.dyninfo['scores']['nsga2']['EFF'] == 0:
                    weeded_targets.append( (0, None, sli) )
                else:
                    candidates.append( sli )

            fronts = fast_nondominated_sort(candidates)
            for front in fronts:
                calc_crowding_distance(front)
                front.sort(key=lambda sli: sli.ind.crowding_distance, reverse=True)
            
            front_num = 0
            while (front_num < len(fronts)) and (len(chosen) + len(fronts[front_num]) <= _ga.popu_limit):
                chosen.extend( [ (0, { 'front_num': front_num, 'crowd_dist': sli.ind.crowding_distance, 'crowd_rank': fronts[front_num].index(sli)}, sli) for sli in fronts[front_num] ] )
                front_num += 1

            still_need = _ga.popu_limit - len(chosen)
            if (front_num < len(fronts)):
                #fronts[front_num].sort(key=lambda sli: sli.ind.crowding_distance, reverse=True)
                chosen.extend( [ (0, { 'front_num': front_num, 'crowd_dist': sli.ind.crowding_distance, 'crowd_rank': fronts[front_num].index(sli)}, sli) for sli in fronts[front_num][0:still_need] ] )
                weeded_targets.extend( [ (0, None, sli) for sli in fronts[front_num][still_need:] ] )
                front_num += 1
            
            while front_num < len(fronts):
                weeded_targets.extend( [ (0, None, sli) for sli in fronts[front_num] ] )
                front_num += 1
            
            # this chosen list is already sort by (front_level (ascending), crowd_level (descending))
            return chosen, weeded_targets

        def rslt_handle(new_calced_fitnesses):
            global all_slices

            print('come into per round result handling')
            rstart = datetime.datetime.now()

            # fitnesses: [ (score, sli_id, dyninfo) ]
            # set fitness
            for score, sli_id, dyninfo, hg_stats in new_calced_fitnesses:
                sli = all_slices[sli_id]
                sli.set_fitness(score, dyninfo)
                if 'nsga2' in dyninfo['scores']:
                    sli.set_nsga2_score(dyninfo)
                self.hg.update_stats(hg_stats)

            fitnesses, weeded_targets = [], []
            if self.selection == 'TOP_SCORE':
                fitnesses, weeded_targets = keep_high_score(self, no_zero_fitness=True)
            elif self.selection == 'MULTI_ROUND_WITH_SCORE':
                fitnesses, weeded_targets = multi_round_with_score(self, max_rounds=3)
            elif self.selection == 'NSGA2_PARETO':
                fitnesses, weeded_targets = nsga2_selection(self)
            else:
                raise Exception('unknown ga selection strategy %s' % (self.selection))

            #print("before weed residents num is %d" % (len(self.residents)))
            #print('before the residents is %s' % (' '.join([ x.name for x in self.residents ])))
            #print('before the fitnesses is %s' % (' '.join([ x[1].name for x in fitnesses ])))
            #print('before the weeded_targets is %s' % (' '.join([ x[1].name for x in weeded_targets ])))
            for score, chosen_info, weeded_sli in weeded_targets:
                #print('weeded_sli is %s with score %s and chosen info %s' % (weeded_sli.name, score, chosen_info))
                self.residents.remove(weeded_sli)
                weeded_sli.relieve_relation(self.ix_ins, self.ix_outs)
                # we only totally weed NON-initial slices
                # as initial residents form the relation of ex_in/ex_outs
                #if not (weeded_sli in self.N):
                #    #print('deregister slice is %s' % (weeded_sli.name))
                #    weeded_sli.deregister_slice()
                weeded_sli.deregister_slice()
            #print("after weed residents num is %d" % (len(self.residents)))

            self.fitnesses = fitnesses

            # check and pass the fitness order to residents
            fitness_list = [ sli for _, _, sli in self.fitnesses ]
            fitness_set = set(fitness_list)
            resident_set = set([ sli for sli in self.residents ])
            if fitness_set != resident_set:
                raise Exception('fitnesses not equal to residents after weeding')
            self.residents = fitness_list

            rend = datetime.datetime.now()
            rtime = (rend - rstart).total_seconds()
            print('this round result handling takes %d seconds' % (rtime))
        
        if self.cur_round <= 1000:
            utils.do_in_parallel_with_idx(fitness_do_func, all_args, rslt_handle, debug=False)
            #utils.do_in_parallel_with_idx(fitness_do_func, all_args, rslt_handle, para=22, debug=False)
        else:
            utils.do_in_parallel_with_idx(fitness_do_func, all_args, rslt_handle, debug=True)

    def population_converged(self):
        if self.last_fitnesses == None:
            # first round
            return False
        else:
            # TODO: use self.fitnesses & self.last_fitnesses to calculate
            pass

    def do_crossover_fix_one_parent(self, _ga, parent):
        global debug_info
        global all_slices

        ix_ops = [ m.ix_gen for m in _ga.in_mutators ]

        # use internal dataset: crossover
        op = random.choice(ix_ops)

        new_slices = []

        for pair in op(parent, _ga.ix_ins, _ga.ix_outs):
            sid, edge_change = pair
            if edge_change == None:
                # no possible mutation
                continue

            chosen = all_slices[sid]

            new_slice = chosen.apply_edge_change(edge_change)
            if new_slice == None:
                # the synthesize of new_slice failed
                # currently the only reason is can_be_harness == False (the ring issue)
                continue
            if not new_slice.can_be_harness:
                # here abandon the slice containing the ring
                raise Exception('crossover_fix_one_parent new_slice which cannot be harness should be dropped eariler')
                #new_slice.deregister_slice()
                #continue

            new_slices.append( new_slice )

        return new_slices

    def do_crossover_two_parents(self, _ga, parent1_idx, selection, idx_ins, idx_outs):
        global debug_info
        global all_slices

        ixs = [ m for m in _ga.in_mutators ]

        # use internal dataset: crossover
        m = random.choice(ixs)
        op = m.ix_gen

        parent1 = _ga.residents[parent1_idx]

        # select parent2
        parent2_idx = None
        if m.abbr == 'RI':
            parent2_idx = selection( idx_ins[parent1_idx] )
        else:
            parent2_idx = selection( idx_outs[parent1_idx] )

        if parent2_idx == None:
            return []
        parent2 = _ga.residents[parent2_idx]

        #_ins, _outs = parent2.get_relation_tables()
        _ins, _outs = {}, {}
        parent1.build_up_relation(_ins, _outs)
        parent2.build_up_relation(_ins, _outs)

        new_slices = []

        #print('op is %s' % (m.abbr))

        for pair in op(parent1, _ins, _outs):
            sid, edge_change = pair
            if edge_change == None:
                # no possible mutation
                continue

            chosen = all_slices[sid]

            new_slice = chosen.apply_edge_change(edge_change)
            if new_slice == None:
                # the synthesize of new_slice failed
                # currently the only reason is can_be_harness == False (the ring issue)
                continue
            if not new_slice.can_be_harness:
                # here abandon the slice containing the ring
                raise Exception('crossover_fix_one_parent new_slice which cannot be harness should be dropped eariler')
                #new_slice.deregister_slice()
                #continue

            new_slices.append( new_slice )

        return new_slices

    def do_mutation(self, _ga, chosen):
        global debug_info

        ex_ops = [ m.ex_gen for m in _ga.out_mutators ]

        # use external dataset: mutation
        op = random.choice(ex_ops)
        tmp_slice, edge_change = op(_ga.forest, chosen, _ga.ex_ins, _ga.ex_outs)
        if edge_change == None:
            # no possible mutation
            return None

        #print("OPERATOR: MUTATION %s" % (edge_change.op))
        # apply the mutation to the slice, this generates a new slice
        #print("before operation slice %s", (chosen))
        #print("operation MUTATION %s ea %s eb %s" % (edge_change.op, edge_change.easid, edge_change.ebsid))
        debug_info.append( (chosen, edge_change) )

        new_slice = chosen.apply_edge_change(edge_change)
        if tmp_slice != None:
            #tmp_slice.dotize(self.work_dir, func_only=False, test=tmp_slice.name)
            tmp_slice.deregister_slice()
        if new_slice == None:
            # the synthesize of new_slice failed
            # currently the only reason is can_be_harness == False (the ring issue)
            return None
        if not new_slice.can_be_harness:
            # here abandon the slice containing the ring
            raise Exception('mutation new_slice which cannot be harness should be dropped eariler')
            #new_slice.deregister_slice()
            #continue
        
        return new_slice

    def _mutation_loop(self, mutated_number, strict=True):
        global debug_info

        def random_selection(idxs):
            # if selection fails, return None
            if len(idxs) > 0:
                return random.choice(idxs)
            else:
                return None

        def tournament_selection(idxs, num, prob):
            # if selection fails, return None
            # the idxs is the order by (front (ascending), crowd(descending))
            # for idx, the lower the better
            num = min(len(idxs), num)
            participants = random.sample(idxs, num)
            best = None
            for participant in participants:
                if best == None or ( (participant < best) and (random.uniform(0, 1) <= prob) ):
                    best = participant
            return best

        def build_idxtable(idxs, residents, _ins, _outs):
            idx_ins = { idx: set([]) for idx in idxs }
            idx_outs = { idx: set([]) for idx in idxs }

            r2idx = { residents[idx].id: idx for idx in idxs }

            for idx in idxs:
                r_ins, r_outs = residents[idx].get_relation_tables()

                for r_in_key in r_ins:
                    idx_ins[idx].update( [ r2idx[_r] for _r, _ in _ins[r_in_key] ] )

                for r_out_key in r_outs:
                    idx_outs[idx].update( [ r2idx[_r] for _r, _ in _outs[r_out_key] ] )

            for idx in idx_ins:
                idx_ins[idx].discard(idx)

            for idx in idx_outs:
                idx_outs[idx].discard(idx)

            return idx_ins, idx_outs

        # possibility for choosing mutate in (mutate, crossover)
        use_ex_poss = 1 - self.p_cross

        new_slices = []
        # renew debug_info
        debug_info = []

        has_mutated = 0
        idxs = list(range(len(self.residents)))
        idx_ins, idx_outs = build_idxtable(idxs, self.residents, self.ix_ins, self.ix_outs)

        #random.shuffle(idxs)
        #for idx in idxs:
        while True:
            if has_mutated >= mutated_number:
                break

            #selection = lambda l: random_selection(l)
            selection = lambda l: tournament_selection(l, num=2, prob=0.9)

            flow = random.choice(self.flows)

            idx = selection(idxs)
            parent_slice = self.residents[idx]

            if flow == 'CO':
                # crossover
                if len(idxs) < 2:
                    raise Exception('cannot crossover on %d residents' % (len(idxs)))
                child_slices = self.do_crossover_fix_one_parent(self, parent_slice)
                for child_slice in child_slices:
                    new_slices.append(child_slice)
                    has_mutated += 1
                    if strict and has_mutated >= mutated_number:
                        break

                continue
            elif flow == 'MO':
                new_slice = self.do_mutation(self, parent_slice)
                if new_slice != None:
                    new_slices.append(new_slice)
                    has_mutated += 1

                continue
            elif flow == 'CM':
                # crossover
                child_slices = []
                if len(idxs) > 1:
                    child_slices = self.do_crossover_fix_one_parent(self, parent_slice)
                else:
                    child_slices = [ Slice(seqs=parent_slice.seqs, edges=parent_slice.edges, tracing=True) ]
                for child_slice in child_slices:
                    new_slice = self.do_mutation(self, child_slice)
                    child_slice.deregister_slice()
                    if new_slice == None:
                        continue
                    new_slices.append(new_slice)
                    has_mutated += 1
                    if strict and has_mutated >= mutated_number:
                        break

                continue
            elif flow == 'CM2P':
                # crossover with 2 parents
                parent1_idx = idx
                child_slices = []
                if len(idxs) > 1:
                    child_slices = self.do_crossover_two_parents(self, parent1_idx, selection, idx_ins, idx_outs)
                else:
                    parent1 = self.residents[parent1_idx] 
                    child_slices = [ Slice(seqs=parent1.seqs, edges=parent1.edges, tracing=True) ]
                for child_slice in child_slices:
                    new_slice = self.do_mutation(self, child_slice)
                    child_slice.deregister_slice()
                    if new_slice == None:
                        continue
                    new_slices.append(new_slice)
                    has_mutated += 1
                    if strict and has_mutated >= mutated_number:
                        break

                continue
            else:
                raise Exception('this flow %s cannot happen' % (flow))
            
            raise Exception('should not reach here')

        return new_slices

    def mutation_single(self, mutated_number):
        new_slices = self._mutation_loop(mutated_number)
        for new_slice in new_slices:
            new_slice.build_up_relation(self.ix_ins, self.ix_outs)
            self.residents.append(new_slice)

    def mutation_para(self, mutated_number):
        # TODO: here should use a more event workload distribution to remove the performance glitch for the parallel mutation
        para = utils.cpunum()
        # whole success mutation times for this round
        #all_args = [ min(s + para, mutated_number) - s for s in range(0, mutated_number, para) ]
        all_args = [ 1 for _ in range(0, mutated_number) ]

        def rslt_handle(list_of_serial_slices):
            rslt_num = 0
            for serial_slices in list_of_serial_slices:
                for name, label, seqs, edges in serial_slices:
                    new_slice = Slice(seqs=[ Node.from_id(seq) for seq in seqs ], edges=[ Edge.from_id(edge) for edge in edges ], tracing=True, label=label)
                    #print('after %s has %d nodes, can harness %s' % (name, len(new_slice.seqs), new_slice.can_be_harness))
                    if not new_slice.can_be_harness:
                        raise Exception('WHY')

                    new_slice.build_up_relation(self.ix_ins, self.ix_outs)
                    self.residents.append(new_slice)
                    rslt_num += 1
            print('result num of mutation_para is %d' % (rslt_num))

        #utils.do_in_parallel_with_idx(mutation_do_func, all_args, rslt_handle, debug=True)
        utils.do_in_parallel_with_idx(mutation_do_func, all_args, rslt_handle, debug=False)

    def log_str(self, str):
        with open(self.log, 'a') as f:
            f.write(str)

    def log_rounds(self):
        with open(self.work_dir + 'rounds.txt', 'w') as f:
            json.dump(self.rounds_info, f)

    def log_residents(self, cur_round, mtime, ftime):
        self.rounds_info.append( {'round': cur_round, 'mtime': mtime, 'ftime': ftime, 'residents': [ (sli.name, sli.dyninfo['scores'], choose_info) for _, choose_info, sli in self.fitnesses ]} )
        #if cur_round % 10 == 0:
        self.log_rounds()

        with open(self.log, 'a') as f:
            round_label = "ROUND %s" % (cur_round)

            if self.selection == 'NSGA2_PARETO':
                f.write(self.log_table_temp % ('        ' + round_label, '   F/E', '    EFF', 'DIV', 'COMP', 'CROWD', "Chosen Info"))
                f.write(self.log_table_temp % ("        ---", "   ---", "   ---", " ---", " ---", " ---", "     "))
            else:
                f.write(self.log_table_temp % ('        ' + round_label, ' Score', 'F', '     P_cov', 'mCC', 'iUN/oUN', "Chosen Info"))
                f.write(self.log_table_temp % ("        ---", "  ---", "---", "     ---", "---", "  ---", "     "))

            avg_score = 0.
            front0_avg = { 'F': 0., 'E': 0., 'EFF': 0., 'DIV': 0., 'COMP': 0., 'CROWD': 0., 'num': 0.}

            for _, choose_info, sli in self.fitnesses:
                dyninfo = sli.dyninfo
                if self.selection == 'NSGA2_PARETO':
                    F = '%-3d' % (dyninfo['scores']['F']) 
                    E = '%-3d' % (dyninfo['scores']['E'])
                    F_E = '%s/%s' % (F, E)
                    EFF = '%-6d' % (dyninfo['scores']['nsga2']['EFF'])
                    DIV = '%-3d' % (dyninfo['scores']['nsga2']['DIV'])
                    COMP = '%-.4f' % (dyninfo['scores']['nsga2']['COMP'])
                    CROWD = '%-.4e' % (choose_info['crowd_dist'])
                    Chosen_reason = 'Rank: Fr %d/ Cr %d' % (choose_info['front_num'], choose_info['crowd_rank'])
                    f.write(self.log_table_temp % (sli.simple_name, F_E, EFF, DIV, COMP, CROWD, Chosen_reason))

                    if choose_info['front_num'] == 0:
                        front0_avg['num'] += 1
                        front0_avg['F'] += float(F)
                        front0_avg['E'] += float(E)
                        front0_avg['EFF'] += float(EFF)
                        front0_avg['DIV'] += float(DIV)
                        front0_avg['COMP'] += float(COMP)
                        front0_avg['CROWD'] += float(CROWD)
                else:
                    score = '%-.4f' % (dyninfo['scores']['score'])
                    F = '%-3d' % (dyninfo['scores']['F']) 
                    #E = '%-3d' % (dyninfo['scores']['E'])
                    P_cov = '%-.4f (%-3d)' % (dyninfo['scores']['P_cov'], dyninfo['scores']['bb_num'])
                    mCC = '%-2.1f' % (dyninfo['scores']['mCC']) 
                    UNs = '%-3d/%-3d' % (dyninfo['scores']['iUN'], dyninfo['scores']['oUN'])

                    Chosen_reason = 'None'
                    if self.selection == 'TOP_SCORE':
                        Chosen_reason = 'initial'
                        if cur_round != 0:
                            Chosen_reason = 'best score'
                    elif self.selection == 'MULTI_ROUND_WITH_SCORE':
                        Chosen_reason = 'initial'
                        if cur_round != 0:
                            #print('slice %s has choosen_info %s' % (sli.name, choose_info))
                            c_round = choose_info['round']
                            new_bb_num = choose_info['new_bb_num']
                            all_bb_num = choose_info['all_bb_num']
                            ratio = float(new_bb_num)/float(all_bb_num)
                            if ratio < 0.01:
                                Chosen_reason = '%d:%d(%.0e)' % (c_round, new_bb_num, ratio)
                            else:
                                Chosen_reason = '%d:%d(%.2f)' % (c_round, new_bb_num, ratio)
                    else:
                        raise Exception("unknown ga selection %s for log_residents" % (self.selection))

                    f.write(self.log_table_temp % (sli.simple_name, score, F, P_cov, mCC, UNs, Chosen_reason))

                    avg_score += dyninfo['scores']['score']

            if len(self.residents) == 0:
                avg_score = 0.0
            else:
                avg_score /= len(self.residents)
            avg_score = '%-.4f' % (avg_score)

            if self.selection == 'NSGA2_PARETO':
                avg_F, avg_E, avg_EFF, avg_DIV, avg_COMP, avg_CROWD = front0_avg['F'], front0_avg['E'], front0_avg['EFF'], front0_avg['DIV'], front0_avg['COMP'], front0_avg['CROWD']
                if front0_avg['num'] != 0:
                    num = front0_avg['num']
                    avg_F = avg_F / num
                    avg_E = avg_E / num
                    avg_EFF = avg_EFF / num
                    avg_DIV = avg_DIV / num
                    avg_COMP = avg_COMP / num
                    avg_CROWD = avg_CROWD / num
                f.write(self.log_table_temp % ("        ---", "   ---", "   ---", " ---", " ---", " ---", "     "))
                f.write(self.log_table_temp % (round_label + " AVERAGE", '%-.1f/%-.1f' % (avg_F, avg_E), '%-.1f' % (avg_EFF), '%-.1f' % (avg_DIV), '%-.4f' % (avg_COMP), '%-.4e' % (avg_CROWD), '-'))
            else:
                f.write(self.log_table_temp % ("        ---", "  ---", "---", "     ---", "---", "  ---", "     "))
                f.write(self.log_table_temp % (round_label + " AVERAGE (Front 0)", avg_score, '-', '-', '-', '-', '-'))
            #f.write('avg score %s, length of residents %d, length of fitnesses %d' % (avg_score, len(self.residents), len(self.fitnesses)))

            f.write('\n')

        #if cur_round % 10 == 0:
        self.hg.dump_stats(self.work_dir)
        self.hg.reset_stats()

    def evolve(self):
        self.cur_round = 0
        self.generate_initial_population()
        print("### Initial fitness computing ###")
        istart = datetime.datetime.now()
        self.compute_fitness_and_weed()
        iend = datetime.datetime.now()
        ftime = (iend - istart).total_seconds()
        print("initial fitness %.4fs" % (ftime))

        self.show_residents()
        self.log_residents(self.cur_round, 0, ftime)

        while True:
            self.cur_round += 1
            if self.cur_round > self.max_rounds:
                print("### Reaches the max rounds of evolvtion ###")
                break

            if len(self.residents) == 0:
                print("### Residents has died out ###")
                break

            #if self.cur_round % 100 == 1:
            if self.cur_round >= 1:
                print("### Evolution Round %d ###" % (self.cur_round))

            self.last_fitnesses = self.fitnesses
            self.fitnesses = []

            mstart = datetime.datetime.now()
            # due to arg & result serialization issue, this is always much faster than para version
            #self.mutation_single(self.mutated_number)
            self.mutation_para(self.mutated_number)
            mend = datetime.datetime.now()
            mtime = (mend - mstart).total_seconds()
            print("[1] mutation %.4fs" % (mtime))

            self.compute_fitness_and_weed()
            fend = datetime.datetime.now()
            ftime = (fend - mend).total_seconds()
            print("[2] fitness %.4fs" % (ftime))

            self.show_residents()
            self.log_residents(self.cur_round, mtime, ftime)

            #converged = self.population_converged()
            #if converged:
            #    print("### Evolvtion converged ###")
            #    break

            #break

        print('### Evolution Ended ###')

        self.show_residents()
        self.dump_residents()

        #global all_slices

        ##for _, sli in all_slices.items():
        ##    #sli.dotize(self.work_dir, func_only=False, test='0')
        ##    sli.to_harness(self.work_dir, test='0')

        ##last_100 = all_slices.keys()
        ##last_100.sort()
        ##for idx in last_100[-100:]:
        ##    sli = all_slices[idx]
        ##    sli.dotize(self.work_dir, func_only=False, test=None)
        ##    self.hg.gen(HarnessGenerator.AS_IT_IS, sli, get_dyninfo=False, test=None)

        ## all survivors
        #for sli in self.residents:
        #    sli.dotize(self.work_dir, func_only=False, test=None)
        #    self.hg.gen(HarnessGenerator.AS_IT_IS, sli, get_dyninfo=False, test=None)
