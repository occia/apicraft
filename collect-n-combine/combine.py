# -*- coding: utf-8 -*-

import sys
import json
import toml
import copy

import utils
from keyedset import KeyedSet
import libdump
from libdump import FuncTrace
import libharness
from libharness import Node, FuncNode, DumpNode, KBNode, Edge, Slice, Forest, HarnessGenerator, GA_Harness
import librelation

from graphviz import Digraph

from ipdb import launch_ipdb_on_exception
#import line_profiler


work_dir = "../workdir/harness_gen/"

relations = {}

def parse_n_set_globals(ty_json, relation_json, _harness_cfg, ida_json):
    global work_dir
    global relations

    _tmap, _fmap, _ftraces = None, None, {}

    # parse json
    with open(ty_json, 'r') as f:
        ty_info = json.load(f)
        _tmap = ty_info['tmap']
        _fmap = ty_info['fmap']
    
    # parse relation
    with open(relation_json, 'r') as f:
        relations = json.load(f)

        # rebuild ftraces
        _ftraces = {}
        for tfile, info in relations['def_use']['ftraces'].items():
            # seems json will convert int key to string for dict
            _ftraces[tfile] = { int(tidx): FuncTrace(False, -1, cnt, _fmap) for tidx, cnt in info.items() }
        
    # knowledge base
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

    # ida cov: (libname, offset) => (func, bb_num)
    ida_cov = { 'covs': {}, 'funcs': {} }
    with open(ida_json, 'r') as f:
        _ida_cov = json.load(f)
        for libname, libinfo in _ida_cov.items():
            #print('libname %s' % (libname))
            ida_cov['funcs'][libname] = {}

            if 'lib_info' in libinfo:
                # here to be compatible with windows ida json (has version key) & linux/mac json (no version key)
                libinfo = libinfo['lib_info']

            for funcname, funcinfo in libinfo.items():
                bbs_info = funcinfo['bbs_info']
                bb_num = len(bbs_info)
                ida_cov['funcs'][libname][funcname] = bb_num

                #print('func %s offsets len %d' % (funcname, bb_num))
                #print('offsets %s' % (offsets))
                for bb_info in bbs_info:
                    start, end = bb_info['range']
                    has_call, in_loop = bb_info['has_call_ins'], bb_info['bb_in_loop']
                    #print('start %s end %s' % (start ,end))
                    for offset in range(start, end):
                        k = (libname, offset)
                        v = (funcname, start, has_call, in_loop)
                        ida_cov['covs'][k] = v

    # set globals
    libharness.set_globals(_ftraces, _tmap, _fmap, harness_cfg, ida_cov)


def dotize_slices(slices):
    global work_dir

    for s in slices:
        #s.dotize(work_dir, func_only=False, test=None)
        s.dotize(work_dir, func_only=True, test=None, draw=False)


def check_completeness(sli):
    # Complete:
    # 1. matched
    # 2. in the knowledge base
    # 3. unmatched non-pointer type
    # Incomplete:
    # 1. unmatched pointer type
    # 2. what about the array with unknown size?
    pass


def minimal_harness_generation(slices):
    global work_dir
    #for sli in slices:
    #    check_completeness(sli)

    #
    # start from the first slice
    # check completeness
    # local search for incomplete parts
    #
    hg = HarnessGenerator(work_dir, libharness.harness_cfg)
    for sli in slices:
        #codefile, dyninfo = hg.gen(HarnessGenerator.AS_IT_IS, sli, get_dyninfo=True, test=None)
        codefile, dyninfo = hg.gen(HarnessGenerator.AS_IT_IS, sli, get_dyninfo=False, test=None)
        print(">>> harness %s info: %s <<<" % (codefile, dyninfo))


def contain_all_core_funcs(forest, core_funcs):
    core_funcs = set([ core_func for core_func in core_funcs ])
    slices = []
    failed_slices = []
    while len(core_funcs) != 0:
        core_func = core_funcs.pop()

        sli = None
        for i in range(50):
            sli = forest.gen_slice_from_core_func(core_func, tracing=True, label='forest-all-func-seed')
            if sli == None:
                #print('REASON: NOTFOUND')
                #print('core func %s has not found in traces' % (core_func))
                #raise Exception('core func %s has not found in traces' % (core_func))
                continue
            elif sli.can_be_harness:
                has_invalid_var = False
                for var_def in sli.get_var_defs():
                    if 'OPAQUE' in var_def or 'UNHANDLED' in var_def:
                        has_invalid_var = True
                if has_invalid_var:
                    sli = None
                    #print('REASON: INVAILDVAR')
                    #raise Exception('check invalid detail here')
                    continue
                else:
                    print('find the relation for %s in %d' % (core_func, i))
                    break
            else:
                #print('REASON: CANNOTBEHAR %s' % (sli.cannot_har_reason))
                #print("%s cannot be harness %s" % (sli.name, sli.cannot_har_reason))
                #raise Exception('check cannot be harness detail here')
                failed_slices.append(sli)
                sli.deregister_slice()
                sli = None

        if sli != None:
            print('SUCC: core func %s has found a valid slice' % (core_func))
            for seq in sli.seqs:
                if seq.is_func():
                    core_funcs.discard(seq.ftref.ori_func_name)

            slices.append(sli)
        else:
            #dotize_slices(failed_slices)
            print('FAIL: core func %s failed to find a valid slice' % (core_func))
            core_funcs.discard(core_func)

    return slices


def contain_all_core_edges(forest, core_funcs):
    core_funcs = set(core_funcs)
    # collect all abstract edge relations
    core_abs_edges = set([])
    for edge in forest.inner.edges:
        if edge.from_node.is_func() and (edge.from_node.ftref.ori_func_name in core_funcs):
            core_abs_edges.add( edge.gaid )
        elif edge.to_node.is_func() and (edge.to_node.ftref.ori_func_name in core_funcs):
            core_abs_edges.add( edge.gaid )
        else:
            continue
    # we need to build an initial slice set covering all relations
    slices = []
    while len(core_abs_edges) != 0:
        edge_gaid = core_abs_edges.pop()

        sli = None
        for i in range(50):
            _, sli = forest.gen_slice_from_one_edge_gaid(edge_gaid, tracing=True, label='forest-all-edge-seed')
            if sli == None:
                #print('MOREREASON: 3333333')
                #print('REASON: NOTFOUND')
                #raise Exception('edge gaid %s cannot be missing in forest' % (str(edge_gaid)))
                continue
            elif sli.can_be_harness:
                has_invalid_var = False
                for var_def in sli.get_var_defs():
                    if 'OPAQUE' in var_def or 'UNHANDLED' in var_def:
                        has_invalid_var = True
                if has_invalid_var:
                    sli = None
                    #print('REASON: INVAILDVAR')
                    continue
                else:
                    #print('REASON: CANNOTBEHAR %s' % (sli.cannot_har_reason))
                    print('find the relation for %s in %d' % (str(edge_gaid), i))
                    break
            else:
                sli.deregister_slice()
                sli = None

        if sli != None:
            print('SUCC: core edge %s has found a valid slice' % (str(edge_gaid)))
            for edge in sli.edges:
                core_abs_edges.discard(edge.gaid)

            slices.append(sli)
        else:
            the_edge = forest.eidxs.get(edge_gaid, None)
            if the_edge == None:
                raise Exception('edge gaid %s has not found in forest' % (str(edge_gaid)))

            print('FAIL: core edge %s failed to find a valid slice' % (str(edge_gaid)))
            core_abs_edges.discard(edge_gaid)
    
    return slices


def build_initial_slices(core_funcs, forest):
    # 1. contain all core funcs
    #return contain_all_core_funcs(forest, core_funcs)

    # 2. contain all core edges
    return contain_all_core_edges(forest, core_funcs)

    # 3. randomly, do we really need this?


#@profile
def genetic_algo_for_harness(core_funcs, forest):
    global work_dir

    N = build_initial_slices(core_funcs, forest)
    print('initial N member is %d' % (len(N)))

    #dotize_slices(N)
    #minimal_harness_generation(N)

    libharness.ga = GA_Harness(N, work_dir, core_funcs, forest)
    libharness.ga.evolve()


def parse_per_line_file(file_name):
    lines = []
    with open(file_name, 'r') as f:
        for line in f.readlines():
            cnt = line.strip()
            if cnt.startswith('#'):
                continue
            lines.append(cnt)

    return list(set(lines))


def relation_postprocess(relations):
    global work_dir

    nodes, edges = {}, {}

    # load
    librelation.merge_relations(relations, nodes, edges)
    # add
    librelation.add_kbs(nodes, edges)
    # refine
    librelation.refine_relations(nodes, edges, True, workdir=work_dir)

    forest_edges = edges.values()
    return forest_edges


def combine_relations(core_funcs, forest_edges):
    # TODO: here needs load the relation json from previous analyzed
    print('building forest')
    forest = Forest(forest_edges, label='base')
    #print('\n'.join([ str(edge) for edge in forest_edges ]))

    print('dotize forest inner trees')
    highlighted = {}
    for core_func in core_funcs:
        highlighted[core_func] = 'red'
    for init_func in Slice.get_init_funcs():
        highlighted[init_func] = 'blue'
    forest.inner.dotize(work_dir, func_only=True, highlighted=highlighted)
    #print(str(forest.inner))

    print('use GA for harness')
    genetic_algo_for_harness(core_funcs, forest)

    print('end of main')


#@profile
def main():
    global work_dir
    global relations

    ty_json = sys.argv[1]
    relation_file = sys.argv[2]
    core_func_file = sys.argv[3]
    harness_cfg_file = sys.argv[4]
    ida_json = sys.argv[5]

    core_funcs = parse_per_line_file(core_func_file)
    relation_json = parse_per_line_file(relation_file)[0]
    harness_cfg = toml.load(harness_cfg_file)

    parse_n_set_globals(ty_json, relation_json, harness_cfg, ida_json)

    # preprocess relations, rebuild nodes & edges
    forest_edges = relation_postprocess(relations)

    combine_relations(core_funcs, forest_edges)


if __name__ == '__main__':
    sys.setrecursionlimit(10000)
    with launch_ipdb_on_exception():
        main()
    #main()
