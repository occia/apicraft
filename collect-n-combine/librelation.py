# -*- coding: utf-8 -*-

import sys
import json
import toml

import libharness

from libdump import FuncTrace
from libharness import Node, Edge, DumpNode, KBNode, Slice

from ipdb import launch_ipdb_on_exception


def parse_relations_and_set_globals(ty_json, list_of_relations):
    # parse json
    with open(ty_json, 'r') as f:
        ty_info = json.load(f)
        _tmap = ty_info['tmap']
        _fmap = ty_info['fmap']

    # rebuild ftraces
    _ftraces = {}
    for relations in list_of_relations:
        for tfile, info in relations['def_use']['ftraces'].items():
            # seems json will convert int key to string for dict
            if tfile not in _ftraces:
                _ftraces[tfile] = {}
            _ftraces[tfile].update( { int(tidx): FuncTrace(False, -1, cnt, _fmap) for tidx, cnt in info.items() } )

    # set globals
    libharness.set_globals(_ftraces, _tmap, _fmap, None, None)


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


def merge_relations(relations, nodes, edges):
    new_edges = { Edge.from_id(eid) for eid in relations['def_use']['edges'] }
    for new_edge in new_edges:
        add_nodes_and_edges_uniquely(new_edge, nodes, edges)


def infer_1(nodes, edges):
    # infer based on aforeseen relation that a/b both could be passed to c
    from_table, to_table = {}, {}
    for gaid, edge in edges.items():
        if edge.from_node.is_func() and edge.to_node.is_func():
            from_gaid, from_tag, to_gaid, to_tag = gaid

            if (from_gaid, from_tag) not in from_table:
                from_table[(from_gaid, from_tag)] = set([])
            from_table[(from_gaid, from_tag)].add( (to_gaid, to_tag) )

            if (to_gaid, to_tag) not in to_table:
                to_table[(to_gaid, to_tag)] = set([])
            to_table[(to_gaid, to_tag)].add( (from_gaid, from_tag) )

    inferred_relations = set([])
    for _, from_keys in to_table.items():
        to_keys = set([])
        for from_key in from_keys:
            to_keys.update( from_table.get(from_key, set([])) )
        for from_key in from_keys:
            for to_key in to_keys:
                new_edge_gaid = (from_key[0], from_key[1], to_key[0], to_key[1])
                inferred_relations.add( new_edge_gaid )

    return inferred_relations


def infer_2(nodes, edges):
    # infer based on aforeseen relation that a outs a ty that accepted by b
    out_table, in_table = {}, {}
    for gaid, edge in edges.items():
        if edge.from_node.is_func() and edge.to_node.is_func():
            from_gaid, from_tag, to_gaid, to_tag = gaid

            out_tkey = edge.from_node.ftref.outty[edge.from_tag]['tkey']
            in_tkey = edge.to_node.ftref.inty[edge.to_tag]['tkey']

            if out_tkey not in out_table:
                out_table[out_tkey] = set([])
            out_table[out_tkey].add( (from_gaid, from_tag) )

            if in_tkey not in in_table:
                in_table[in_tkey] = set([])
            in_table[in_tkey].add( (to_gaid, to_tag) )

    inferred_relations = set([])
    for tkey, out_keys in out_table.items():
        for in_key in in_table.get(tkey, set([])):
            for out_key in out_keys:
                new_edge_gaid = (out_key[0], out_key[1], in_key[0], in_key[1])
                inferred_relations.add( new_edge_gaid )

    return inferred_relations


def dump_inferred_relations(tag, nodes, edges, inferred_relations, dump=True):
    # remove already has 
    new_inferred_relations = inferred_relations - set(edges.keys())
    existing_inferred_relations = inferred_relations & set(edges.keys())

    with open('inferred_%s.txt' % (tag), 'w') as f:
        f.write("### existing relations\n")
        for r in existing_inferred_relations:
            from_gaid, from_tag, to_gaid, to_tag = r
            f.write( '%-40s %-5s => %-40s %-5s\n' % (from_gaid[0], from_tag, to_gaid[0], to_tag) )

        f.write("### inferred relations\n")
        for r in new_inferred_relations:
            from_gaid, from_tag, to_gaid, to_tag = r
            f.write( '%-40s %-5s => %-40s %-5s\n' % (from_gaid[0], from_tag, to_gaid[0], to_tag) )

    print('relations %s are inferred, %d are inferred from %d' % (tag, len(new_inferred_relations), len(inferred_relations)))


def add_inferred_relations(nodes, edges, inferred_relations):
    for nr in ( inferred_relations - set(edges.keys()) ):
        from_node, to_node = nodes[nr[0]], nodes[nr[2]]
        new_edge = Edge(from_node, nr[1], to_node, nr[3])
        add_nodes_and_edges_uniquely(new_edge, nodes, edges)


def remove_kbs(nodes, edges):
    removed_kbs = set([])
    for gaid, edge in edges.items():
        if edge.from_node.is_value() and edge.from_node.is_KB():
            removed_kbs.add(gaid)
    
    # dump removed_kbs
    with open('removed_kbs.txt', 'w') as f:
        for gaid in removed_kbs:
            f.write( '%-40s %-5s => %-40s %-5s\n' % (gaid[0][0], gaid[1], gaid[2][0], gaid[3]) )

    print('remove %d kbs' % (len(removed_kbs)))

    for gaid in removed_kbs:
        del edges[gaid]


def add_kbs(nodes, edges):
    added_kbs = set([])
    for k in list(nodes):
        # this loop updates nodes
        node = nodes[k]
        if node.is_func():
            for intag in node.ftref.inargs:
                if Slice.in_knowledge_base(node, intag):
                    kbnode = KBNode(node.tfile, node.tid, node.tidx, intag)
                    new_edge = Edge(kbnode, '.', node, intag)
                    add_nodes_and_edges_uniquely(new_edge, nodes, edges)
                    added_kbs.add(new_edge.gaid)

    # dump added_kbs
    with open('added_kbs.txt', 'w') as f:
        for gaid in added_kbs:
            f.write( '%-40s %-5s => %-40s %-5s\n' % (gaid[0][0], gaid[1], gaid[2][0], gaid[3]) )

    print('add %d kbs' % (len(added_kbs)))

def refresh_kbs(nodes, edges):
    # remove kbs
    remove_kbs(nodes, edges)
    
    # update new kbs
    add_kbs(nodes, edges)
            
def remove_relations_with_func_name(funcnames, nodes, edges):
    removed_relations = set([])
    for gaid, edge in edges.items():
        if edge.to_node.is_func() and edge.to_node.ftref.ori_func_name in funcnames:
            removed_relations.add(gaid)

    for gaid in removed_relations:
        del edges[gaid]

    # dump added_kbs
    with open('removed_relations.txt', 'w') as f:
        for gaid in removed_relations:
            f.write( '%-40s %-5s => %-40s %-5s\n' % (gaid[0][0], gaid[1], gaid[2][0], gaid[3]) )

    print('removed %d relations that comes into %s' % (len(removed_relations), funcnames))

def refine_relations(nodes, edges, check, workdir='./'):
    # refine
    exist_func_args = set([])
    error_var_defs = {}
    warn_var_defs = {}
    for k in list(edges):
        # this loop changes edges
        edge = edges[k]
        # to_node cannot be dump node
        if edge.from_node.is_value() and edge.from_node.is_dump():
            failed = False
            var_def = libharness.MemDumpVar(-1, edge.from_node, True, edge.to_tag).gen_definition()
            for fail_reason in [ 'OPAQUE', 'UNHANDLED' ]:
                if fail_reason in var_def:
                    del edges[edge.gaid]
                    if var_def not in error_var_defs:
                        error_var_defs[var_def] = set()
                    error_var_defs[var_def].add(str(edge.gaid))
                    failed = True
                    break
            for warn_reason in [ 'ZERO_SIZE' ]:
                if warn_reason in var_def:
                    if var_def not in warn_var_defs:
                        warn_var_defs[var_def] = set()
                    warn_var_defs[var_def].add(str(edge.gaid))
                    break
            if (not failed) and edge.to_node.is_func():
                exist_func_args.add( (edge.to_node.gaid, edge.to_tag) )
        else:
            exist_func_args.add( (edge.to_node.gaid, edge.to_tag) )

    #nodes = {}
    #for _, edge in edges.items():
    #    nodes[edge.from_node.gaid] = edge.from_node
    #    nodes[edge.to_node.gaid] = edge.to_node

    print('relations are refined, there are %d kinds of errors, now has %d edges %d nodes' % (len(error_var_defs), len(edges), len(nodes)))
    with open(workdir + 'error_relations.txt', 'w') as f:
        for error_var_def, eids in error_var_defs.items():
            f.write(error_var_def)
            f.write('\n'.join(list(eids)))
            f.write('\n------ ERR -----\n\n')
        for warn_var_def, eids in warn_var_defs.items():
            f.write(warn_var_def)
            f.write('\n'.join(list(eids)))
            f.write('\n------ WARN -----\n\n')

    # check
    if check:
        all_func_args = set([])
        for _, node in nodes.items():
            if node.is_func():
                for intag in node.ftref.inargs:
                    all_func_args.add((node.gaid, intag))
        missing_func_args = all_func_args - exist_func_args

        with open(workdir + 'missing_func_args.txt', 'w') as f:
            f.write('relations are checked, there are %d missing func args:\n' % (len(missing_func_args)))
            for mfa in missing_func_args:
                f.write('\t' + str(mfa) + '\n')


def add_dump_relations(nodes, edges):
    # TODO: here we still misses lots of the dump value from original traces, fix this in some time of the future
    exist_func_args = set([])
    for _, edge in edges.items():
        # to_node cannot be dump node
        if edge.to_node.is_func():
            exist_func_args.add( (edge.to_node.gaid, edge.to_tag) )
    
    all_func_args = set([])
    for _, node in nodes.items():
        if node.is_func():
            for intag in node.ftref.inargs:
                all_func_args.add( (node.gaid, intag) )
    
    missing_func_args = all_func_args - exist_func_args

    added_dump_nodes = set([])

    for node_gaid, intag in missing_func_args:
        node = nodes[node_gaid]
        if node.ftref.inargs[intag].succ:
            from_node = DumpNode(node.tfile, node.tid, node.tidx, intag)
            new_edge = Edge(from_node, '.', node, intag)
            add_nodes_and_edges_uniquely(new_edge, nodes, edges)
            added_dump_nodes.add(from_node)
    
    print('add %s dump nodes' % (len(added_dump_nodes)))
    with open('added_dump_nodes.txt', 'w') as f:
        for dump_node in added_dump_nodes:
            f.write('%s\n' % (str(dump_node)))


def dump_relations(out_json, nodes, edges):
    def_use = {}
    saved_ftraces = {}
    saved_edges = [ v.id for _, v in edges.items() ]

    #for _, r in edges.items():
    #    from_gaid, from_tag, to_gaid, to_tag = r.gaid
    #    print( '%-40s %-5s => %-40s %-5s' % (from_gaid[0], from_tag, to_gaid[0], to_tag) )

    for _, node in nodes.items():
        if node.tfile not in saved_ftraces:
            saved_ftraces[node.tfile] = {}
        saved_ftraces[node.tfile][node.tidx] = libharness.ftraces[node.tfile][node.tidx].cnt

    def_use['edges'] = saved_edges
    def_use['ftraces'] = saved_ftraces
    print('relations are dumpped')

    base = {"def_use": def_use, "temporal":{}}
    with open(out_json, 'w') as f:
        json.dump(base, f)


def main():
    if len(sys.argv) < 4:
        print('python relation.py header_ty.json out.json in_jsons...')
        exit(1)

    ty_json = sys.argv[1]
    out_json = sys.argv[2]

    # prepare ftraces
    list_of_relations = []
    for in_json in sys.argv[3:]:
        with open(in_json, 'r') as f:
            relations = json.load(f)
            list_of_relations.append(relations)
    
    parse_relations_and_set_globals(ty_json, list_of_relations)

    print('[1] LOAD: relations are loaded')

    # merge
    nodes, edges = {}, {}
    for relations in list_of_relations:
        merge_relations(relations, nodes, edges)
    
    print('[2] MERGE: relations are merged, there are %d edges %d nodes' % (len(edges), len(nodes)))

    remove_kbs(nodes, edges)
    print('[3] CLEAN: KB relations are cleaned')

    # do this in combine.py
    #refine_relations(nodes, edges, False)
    #print('[3.2] CLEAN: certainly failed relations are cleaned')

    add_dump_relations(nodes, edges)
    print('[4.1] ADD: dump relations are added')

    # do this in combine.py
    #add_kbs(nodes, edges)
    #print('[4.2] ADD: KB relations are added')

    # add inferred one
    while True:
        inferred_relations_1 = infer_1(nodes, edges)
        inferred_relations_2 = infer_2(nodes, edges)

        dump_inferred_relations('R1', nodes, edges, inferred_relations_1)
        dump_inferred_relations('R2', nodes, edges, inferred_relations_2)

        I1 = inferred_relations_1 - set(edges.keys())
        I2 = inferred_relations_2 - set(edges.keys())
        print("R1 all %d, R2 all %d, both have %d, R1 own %d, R2 own %d (existing removed)" % (len(I1), len(I2), len(I1 & I2), len(I1 - I2), len(I2 - I1)))

        add_inferred_relations(nodes, edges, inferred_relations_1)
        add_inferred_relations(nodes, edges, inferred_relations_2)
        print('[4.2] ADD: inferred relations are added')

        if len(I1) == 0 and len(I2) == 0:
            break

    # do this in combine.py
    #refine_relations(nodes, edges, True)
    #print('[5] CLEAN: certainly failed relations are cleaned')

    #remove_relations_with_func_name([ 'CTFontCreateWithFontDescriptor' ], nodes, edges)

    # refine & check
    #refresh_kbs(nodes, edges)

    # print all relations
    dump_inferred_relations('all', nodes, edges, set(edges.keys()))

    # dump to out.json
    dump_relations(out_json, nodes, edges)


if __name__ == '__main__':
    with launch_ipdb_on_exception():
        main()
