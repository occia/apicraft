# -*- coding: utf-8 -*-

import sys
import json
import toml
import copy

import utils

import libdump
from libdump import FuncTrace
import libharness
from libharness import Node, FuncNode, DumpNode, KBNode, Edge, Slice, Forest

#from ipdb import launch_ipdb_on_exception
#import line_profiler

import gc

work_dir = "../workdir/harness_gen/"
parallel_tmp_traces = {}


def parse_n_set_globals(ty_json, _harness_cfg, func_traces):
    global work_dir

    _tmap, _fmap, _ftraces = None, None, {}

    # parse json
    with open(ty_json, 'r') as f:
        ty_info = json.load(f)
        _tmap = ty_info['tmap']
        _fmap = ty_info['fmap']
    
    # parse csv or json of func trace
    for func_trace in func_traces:
        _ftrace = []
        with open(func_trace, 'r') as f:
            trace_json = json.load(f)
            for i in range(len(trace_json['traces'])):
                one_ft = FuncTrace(False, i, trace_json['traces'][i], _fmap)
                _ftrace.append(one_ft)

        _ftraces[func_trace] = _ftrace
    
    harness_cfg = { 'funcargs': {}, 'types': {}, 'input': {}, 'must_used': {'funcargs':set(), 'types':set()} }
    for _, funcarg in _harness_cfg['knowledge_base']['funcargs'].items():
        funcname, tag = funcarg['func'], funcarg['tag']
        # gen is a dict
        harness_cfg['funcargs'][(funcname, tag)] = funcarg['gen']
        if funcarg.get('must_used', False):
            harness_cfg['must_used']['funcargs'].add( (funcname, tag) )
    for _, tyinfo in _harness_cfg['knowledge_base']['types'].items():
        ty = tyinfo['type']
        # gen is a dict
        harness_cfg['types'][ty] = tyinfo['gen']
        if tyinfo.get('must_used', False):
            harness_cfg['must_used']['types'].add( ty )
    
    if 'skeleton_backward' in _harness_cfg['knowledge_base']['input']:
        harness_cfg['input']['skeleton_backward'] = _harness_cfg['knowledge_base']['input']['skeleton_backward']
    else:
        harness_cfg['input']['skeleton_backward'] = False
    harness_cfg['input']['init_funcs'] = set(_harness_cfg['knowledge_base']['input']['init_funcs'])
    harness_cfg['input']['must_contain'] = _harness_cfg['knowledge_base']['input']['must_contain']
    harness_cfg['input']['k_steps_to_core'] = int(_harness_cfg['knowledge_base']['input']['k_steps_to_core'])
    harness_cfg['input']['uniq_funcs'] = _harness_cfg['knowledge_base']['input']['uniq_funcs']

    harness_cfg['wrapper'] = _harness_cfg['harness_wrapper']

    harness_cfg['dynamic'] = _harness_cfg['dynamic']

    # set globals
    libharness.set_globals(_ftraces, _tmap, _fmap, harness_cfg, None)


def get_type(seq, tag):
    return seq.ftref.get_arg_type(tag)


def get_value(seq, tag, is_in):
    if is_in:
        return seq.ftref.inargs[tag].val
    else:
        return seq.ftref.outargs[tag].val


def should_store(seq, outtag):
    ty = get_type(seq, outtag)
    if not ty['need_cmp']:
        return False

    if not seq.ftref.outargs[outtag].succ:
        return False
    #print('seq %s, outtag %s, value %s' % (seq, outtag, get_value(seq, outtag, False)))

    val = get_value(seq, outtag, False)
    if int(val, base=16) == 0:
        return False

    return True


def is_equal_ty(tya, tyb):
    remove_const = lambda x: x.replace('const', '').strip()
    if tya['cmp_type'] == tyb['cmp_type']:
        return True

    if tya['ct_type'] == tyb['ct_type']:
        return True

    if remove_const(tya['ct_type']) == remove_const(tyb['ct_type']):
        return True

    if tya['is_pointer'] and tyb['is_pointer']:
        # both are pointers
        if ('void *' in tya['ct_type']) or ('void *' in tyb['ct_type']):
            return True

    if tya['is_pointer'] or tyb['is_pointer']:
        # one is pointer another is integer
        if tya['is_int'] or tyb['is_int']:
            return True

    return False


def get_equal_ty_list(ty, get_converted):
    remove_const = lambda x: x.replace('const', '').strip()
    if ty['need_cmp']:
        cmpt = ty['cmp_type']
        ctt = ty['ct_type']
        rcctt = remove_const(ctt)
        l = [cmpt]
        if ctt not in l:
            l.append(cmpt)
        if rcctt not in l:
            l.append(rcctt)
        if not get_converted:
            if ty['is_pointer']:
                l.append('::POINTER::')
                if 'void *' in ctt:
                    l.append('::POINTER_VOID::')
            elif ty['is_int']:
                l.append('::INT::')
            return l
        else:
            if ty['is_pointer']:
                if 'void *' in ctt:
                    l.append('::POINTER::')
                else:
                    l.append('::POINTER_VOID::')
                l.append('::INT::')
            elif ty['is_int']:
                l.append('::POINTER::')
            return l
    else:
        return []


def get_data_dep(seq, intag, previous):
    has_val = seq.ftref.inargs[intag].succ
    #print('=====> check dep %s %s => %s' % (seq.ftref.ori_func_name, intag, val))
    if not has_val:
        #print('not has a val')
        return []

    val = get_value(seq, intag, True)
    if int(val, base=16) == 0:
        #print('dumped value is null, val: %s' % (val))
        return []

    ty = get_type(seq, intag)
    if not ty['need_cmp']:
        #print('type not need cmp')
        return []

    if val in previous:
        for tt in get_equal_ty_list(ty, get_converted=True):
            if tt in previous[val]:
                return previous[val][tt]

    return []


def add_nodes_and_edges_uniquely(e, nodes, edges):
    if e.gaid not in edges:
        #print('+++ add edge gaid: %s' % (str(e.gaid)))
        from_node, outtag, to_node, intag = e.from_node, e.from_tag, e.to_node, e.to_tag
        if from_node.gaid in nodes:
            from_node = nodes[from_node.gaid]
        else:
            #print('+++ add from gaid is %s' % (str(from_node.gaid)))
            nodes[from_node.gaid] = from_node
        if to_node.gaid in nodes:
            to_node = nodes[to_node.gaid]
        else:
            #print('+++ add to gaid is %s' % (str(to_node.gaid)))
            nodes[to_node.gaid] = to_node
        edge = Edge(from_node, outtag, to_node, intag)
        edges[edge.gaid] = edge


def analyze_data_deps(tag, trace_seqs, nodes, edges):
    # key: dumped value => value: set( (seq, outtag) )
    previous = {}

    cur_idx, last_prog = 0, None
    whole_len = len(trace_seqs)

    print('Handling %s which has %d in total' % (tag, whole_len))

    for seq in trace_seqs:
        cur_idx += 1
        prog = int( (float(cur_idx) / whole_len) * 100 )
        if prog % 10 == 0 and prog != last_prog:
            last_prog = prog
            print('  %s progress %d%% (%d)' % (tag, prog, whole_len))

        # check the dict
        for intag in seq.ftref.inargs:
            deps = get_data_dep(seq, intag, previous)
            if len(deps) > 0:
                for dep_seq, outtag in deps:
                    # a new func => func edge 
                    from_gaid = ( dep_seq.ftref.ori_func_name, None, 'FUNC')
                    from_node = nodes[from_gaid] if from_gaid in nodes else FuncNode(dep_seq.tfile, dep_seq.tid, dep_seq.tidx)

                    to_gaid = ( seq.ftref.ori_func_name, None, 'FUNC')
                    to_node = nodes[to_gaid] if to_gaid in nodes else FuncNode(seq.tfile, seq.tid, seq.tidx)

                    e_gaid = (from_gaid, outtag, to_gaid, intag)
                    if e_gaid not in edges:
                        edges[e_gaid] = Edge(from_node, outtag, to_node, intag)
            else:
                _from_node = None
                if Slice.in_knowledge_base(seq, intag):
                    # kb => func
                    _from_node = KBNode(seq.tfile, seq.tid, seq.tidx, intag)
                elif seq.ftref.inargs[intag].succ:
                    # dump => func
                    _from_node = DumpNode(seq.tfile, seq.tid, seq.tidx, intag)
                else:
                    # ? => func, give up this
                    #_from_node = FakeNode(seq.tfile, seq.tid, seq.tidx, intag)
                    # give up this
                    continue
                from_node = nodes.get(_from_node.gaid, _from_node)

                to_gaid = ( seq.ftref.ori_func_name, None, 'FUNC')
                to_node = nodes[to_gaid] if to_gaid in nodes else FuncNode(seq.tfile, seq.tid, seq.tidx)

                edge = Edge(from_node, '.', to_node, intag)
                if edge.gaid not in edges:
                    edges[edge.gaid] = edge

        # cache the data info of this seq for quick match
        for outtag in seq.ftref.outargs:
            if should_store(seq, outtag):
                ty = get_type(seq, outtag)
                val = get_value(seq, outtag, False)

                if val == None:
                    raise Exception('val cannot be None')

                if val not in previous:
                    previous[val] = {}

                if outtag.startswith('arg'):
                    print('outtag', outtag)
                    raise Exception('start with arg')

                for tt in get_equal_ty_list(ty, get_converted=False):
                    if tt in previous[val]:
                        previous[val][tt].add( (seq, outtag) )
                    else:
                        previous[val][tt] = set([ (seq, outtag) ])


def parse_per_line_file(file_name):
    lines = []
    with open(file_name, 'r') as f:
        for line in f.readlines():
            cnt = line.strip()
            if cnt.startswith('#'):
                continue
            lines.append(cnt)

    return list(set(lines))


def split_traces(trace_file, ftrace):
    # filter & split by level & tid
    traces = {}
    in_trace_num = 0
    for i in range(len(ftrace)):
        ftref = ftrace[i]
        if ftref.level == 1:
            tid = ftref.tid
            key = (trace_file, tid)

            if key not in traces:
                traces[key] = []
            traces[key].append( Node(trace_file, tid, i) )
            in_trace_num += 1

    print('trace %s has %d threads, in total %d/%d items' % (trace_file, len(traces.keys()), in_trace_num, len(ftrace)))
    return traces


#@profile
def data_dep_do_func(idx, args, rslts):
    global parallel_tmp_traces

    trace_file, tid = args

    trace = parallel_tmp_traces[ (trace_file, tid) ]

    nodes, edges = {}, {}
    if len(rslts) == 0:
        # first time execution
        rslts.append( (nodes, edges) )
    else:
        nodes, edges = rslts[0]

    tag = 'File %s [%s]' % (trace_file, tid)
    analyze_data_deps(tag, trace, nodes, edges)

    gc.collect()


#@profile
def parallel_data_dependency_analysis(forest_nodes, forest_edges):
    global parallel_tmp_traces
    parallel_tmp_traces = {}

    for trace_file, ftrace in libharness.ftraces.items():
        parallel_tmp_traces.update( split_traces(trace_file, ftrace) )

    all_args = parallel_tmp_traces.keys()

    def rslt_handle(rslts):
        print('coming into result handling')
        for nodes, edges in rslts:
            for _, edge in edges.items():
                add_nodes_and_edges_uniquely(edge, forest_nodes, forest_edges)

    utils.do_in_parallel_with_idx(data_dep_do_func, all_args, rslt_handle, debug=False, para=4, share_rslt=True)
    #utils.do_in_parallel_with_idx(data_dep_do_func, all_args, rslt_handle, debug=True, para=4, share_rslt=True)
    return forest_nodes, forest_edges


#@profile
def collect_relations(core_funcs, dumpto):
    global work_dir

    print('collect relations')

    # collect DEF-USE relations
    forest_nodes, forest_edges = {}, {}
    parallel_data_dependency_analysis(forest_nodes, forest_edges)

    # dump DEF-USE relations
    def_use = {}
    saved_ftraces = {}
    saved_edges = [ v.id for _, v in forest_edges.items() ]

    for _, node in forest_nodes.items():
        if node.tfile not in saved_ftraces:
            saved_ftraces[node.tfile] = {}
        saved_ftraces[node.tfile][node.tidx] = libharness.ftraces[node.tfile][node.tidx].cnt

    def_use['edges'] = saved_edges
    def_use['ftraces'] = saved_ftraces

    # dump Temporal relations

    relations = {"def_use": def_use, "temporal":{}}
    with open(work_dir + dumpto, 'w') as f:
        json.dump(relations, f)


#@profile
def main():
    global work_dir

    ty_json = sys.argv[1]
    func_trace_file = sys.argv[2]
    core_func_file = sys.argv[3]
    harness_cfg_file = sys.argv[4]
    #time_ida = sys.argv[5]
    relation_file = sys.argv[5]

    func_traces = parse_per_line_file(func_trace_file)
    core_funcs = parse_per_line_file(core_func_file)
    harness_cfg = toml.load(harness_cfg_file)

    parse_n_set_globals(ty_json, harness_cfg, func_traces)

    collect_relations(core_funcs, relation_file)


if __name__ == '__main__':
    sys.setrecursionlimit(10000)
    #with launch_ipdb_on_exception():
    #    main()
    main()
