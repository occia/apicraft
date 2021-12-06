import idautils
import idaapi
import ida_nalt
import idc
import json
from idaapi import *
import networkx as nx
import itertools
from win32api import GetFileVersionInfo, LOWORD, HIWORD

def get_version_number(filename):
    info = GetFileVersionInfo(filename, "\\")
    ms = info['FileVersionMS']
    ls = info['FileVersionLS']
    return HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls)

def get_preds(fc, node, nodeset=None):
    if nodeset is None:
        nodeset = []
    if node not in nodeset:
        nodeset.append(node)
        n = fc.npred(node)
        for i in range(n):
            get_preds(fc, fc.pred(node, i), nodeset)
    return nodeset


def get_succs(fc, node, nodeset=None):
    if nodeset is None:
        nodeset = []
    if node not in nodeset:
        nodeset.append(node)
        n = fc.nsucc(node)
        for i in range(n):
            get_succs(fc, fc.succ(node, i), nodeset)
    return nodeset


def get_lib_binary_loops(func, subset=None):
    loops_range = []
    image_base = ida_nalt.get_imagebase()
    if func:
        fc = qflow_chart_t()
        fc.create("", func, BADADDR, BADADDR, FC_NOEXT | FC_PREDS)
        nodes_total = fc.size()

        nids = {}
        s = subset
        if s is None:
            s = range(nodes_total)
        # collect every nid's parent and child nodes
        for nid in s:
            preds = get_preds(fc, nid)
            succs = get_succs(fc, nid)
            nids[nid] = (preds, succs)

        # find all loops in a function
        for nid in nids:
            # skip nids that are already part of a loop
            # if nid in loop:
            #    continue

            loop = set()
            preds, succs = nids[nid]

            # detect loop
            for i in range(len(succs)):
                if succs[i] in preds:
                    start_ea = fc[succs[i]].start_ea - image_base
                    end_ea = fc[succs[i]].end_ea - image_base
                    loop.add((start_ea, end_ea))

            # remove loops that do not xref themselves (FPs)
            if len(loop) == 1:
                found = False
                for j in range(fc.nsucc(nid)):
                    if nid == fc.succ(nid, j):
                        found = True
                if not found:
                    loop.clear()

            # remove duplicates
            elif len(loop) > 1:
                loop_list = list(sorted(loop))
                loop_start = loop_list[0][0]
                loop_end = loop_list[-1][-1]
                loop_range = [loop_start, loop_end]
                if loop_range in loops_range:
                    # TODO: add code to check for nested loops
                    loop.clear()

            if len(loop):
                loop_list = list(sorted(loop))
                loop_start = loop_list[0][0]
                loop_end = loop_list[-1][-1]
                loop_range = [loop_start, loop_end]
                loops_range.append(loop_range)
                # loops.append(sorted(loop))

    return loops_range


def get_gui_binary_loops(func, subset=None):
    image_base = ida_nalt.get_imagebase()
    if func:
        edges = list()
        loops = list()
        fc = qflow_chart_t()
        fc.create("", func, BADADDR, BADADDR, FC_NOEXT | FC_PREDS)
        nodes_total = fc.size()

        s = subset
        if s is None:
            s = range(nodes_total)

        # generate function's edege
        print("[+] generate function's edge")
        for nid in s:
            n = fc.nsucc(nid)
            for i in range(n):
                succ = fc.succ(nid, i)
                edge = (nid, succ)
                edges.append(edge)

        # generate simple cycles graph
        print("[+] generate simple cycles graph")
        G = nx.DiGraph(edges)
        simple_cycles = list(nx.simple_cycles(G))
        for idx, simple_cycle in enumerate(simple_cycles):
            loop = dict()
            loop_node_info = list()
            loop_ranges = list()
            simple_cycle = sorted(simple_cycle)
            loop_start = fc[simple_cycle[0]].start_ea
            loop_end = fc[simple_cycle[-1]].end_ea
            for node in simple_cycle:
                start_ea = fc[node].start_ea - image_base
                end_ea = fc[node].end_ea - image_base
                if start_ea in loop_node_info:
                    loop_node_info.remove(start_ea)
                else:
                    loop_node_info.append(start_ea)
                if end_ea in loop_node_info:
                    loop_node_info.remove(end_ea)
                else:
                    loop_node_info.append(end_ea)

            loop_node_info = sorted(loop_node_info)
            loop_node_info_length = len(loop_node_info)
            for i in range(int(loop_node_info_length / 2)):
                loop_ranges.append(
                    [loop_node_info[i * 2], loop_node_info[i * 2 + 1]])
            loop['id'] = idx
            loop['loop_ranges'] = loop_ranges
            # loop['node_info'] = loop_node_info
            loop['loop_nodes'] = simple_cycle
            loop['belong_to'] = list()
            # print("loop: " + str(loop))
            loops.append(loop)

        # calculate loop relationship
        print("[+] calculate loop relationship")
        # print("loops length: " + str(len(simple_cycles)))
        if len(loops) < 1000:
            for loop_a, loop_b in itertools.combinations(loops, 2):
                # print("loop_a: " + str(loop_a) + " loop_b: " + str(loop_b))
                if set(loop_a['loop_nodes']) < set(loop_b['loop_nodes']):
                    loop_a['belong_to'].append(loop_b['id'])
                elif set(loop_b['loop_nodes']) < set(loop_a['loop_nodes']):
                    loop_b['belong_to'].append(loop_a['id'])

        # delete loop_nodes key
        for loop in loops:
            del loop['loop_nodes']

        # print("loops: " + str(loops))
        return loops


def gen_bbs_info(func, start, end, loops_range):
    bbs_info = list()
    image_base = ida_nalt.get_imagebase()
    for block in idaapi.FlowChart(func):
        if start <= block.start_ea < end:
            start_ea = block.start_ea - image_base
            end_ea = block.end_ea - image_base

            # calculate whether or not basic block is in the loop
            bb_in_loop = False
            for loop_range in loops_range:
                if start_ea >= loop_range[0] and end_ea <= loop_range[-1]:
                    bb_in_loop = True
                    break

            # calculate whether or not basic block has call instrution
            block_ea = block.start_ea
            has_call_ins = False
            flag = False
            while block_ea <= block.end_ea:
                # print("block_ea: " + str(block_ea) + " - type: " + str(type(block_ea)))
                try:
                    flag = idaapi.is_call_insn(block_ea)
                except ValueError as e:
                    flag = False
                    pass
                if flag is True:
                    has_call_ins = True
                    break
                block_ea = idc.next_head(block_ea)
            bb_info = dict()
            bb_info['range'] = [start_ea, end_ea]
            bb_info['has_call_ins'] = has_call_ins
            bb_info['bb_in_loop'] = bb_in_loop
            bbs_info.append(bb_info)
        else:
            print("[-] Warning, broken CFG?")
    return bbs_info


def gen_func_range(func, start, end):
    bbs = list()
    func_ranges = list()
    image_base = ida_nalt.get_imagebase()
    for block in idaapi.FlowChart(func):
        if start <= block.start_ea < end:
            start_ea = block.start_ea - image_base
            end_ea = block.end_ea - image_base
            # start_ea = hex(block.start_ea)
            # end_ea = hex(block.end_ea)
            if start_ea in bbs:
                bbs.remove(start_ea)
            else:
                bbs.append(start_ea)
            if end_ea in bbs:
                bbs.remove(end_ea)
            else:
                bbs.append(end_ea)
        else:
            print("[-] Warning, broken CFG?")
    bbs = sorted(bbs)
    bbs_length = len(bbs)
    for i in range(int(bbs_length / 2)):
        func_ranges.append([bbs[i * 2], bbs[i * 2 + 1]])
    # print(bbs)
    return func_ranges


def gen_lib_binary_info():
    lib_binary_info = dict()

    for seg_ea in idautils.Segments():

        name = idc.get_segm_name(seg_ea)
        if ("__text" not in name) and (".text" not in name):
            continue

        start = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        for func_ea in idautils.Functions(start, end):

            f = idaapi.get_func(func_ea)
            if not f:
                continue

            func_info = dict()
            func_name = idaapi.get_func_name(func_ea)
            func_end_ea = idc.find_func_end(func_ea)

            print("[+] function: " + func_name)
            # func_info['func_range'] = [func_ea, func_end_ea]

            # get function loop information
            print("[+] gen function loops range")
            if func_name != '_pre_proc': # _pre_proc function of AudioCodecs will lead to RecursionError.
                loops_range = get_lib_binary_loops(f)
            else:
                print("[-] _pre_proc get_lib_library_loops RecursionError.")
                loops_range = list()
            # used for loops_range debug
            # func_info['loops_range'] = loops_range

            # get function basic blocks information
            print("[+] gen function basic blocks info")
            bbs_info = gen_bbs_info(f, start, end, loops_range)
            # func_info['bbs_info'] = sorted(list(bbs_info))
            func_info['bbs_info'] = bbs_info

            lib_binary_info[func_name] = func_info

    return lib_binary_info


def gen_gui_binary_info():
    gui_binary_info = dict()

    for seg_ea in idautils.Segments():

        name = idc.get_segm_name(seg_ea)
        if ("__text" not in name) and (".text" not in name):
            continue

        start = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        for func_ea in idautils.Functions(start, end):

            f = idaapi.get_func(func_ea)
            if not f:
                continue

            func_info = dict()
            func_name = idaapi.get_func_name(func_ea)
            func_end_ea = idc.find_func_end(func_ea)

            print("[+] function: " + func_name)
            print("[+] gen function range")
            func_info['func_range'] = gen_func_range(f, start, end)

            # get function loop information
            print("[+] gen function loops range")
            func_info['loops_info'] = get_gui_binary_loops(f)

            gui_binary_info[func_name] = func_info

    return gui_binary_info


if __name__ == '__main__':
    module_name = idaapi.get_root_filename()
    dir_path = "E:\\APICraft\\0xlib_harness\\fitness_function_calc\\mf-cov-jsons\\"
    # version_info = "10.15.7_19H15"

    version_number = get_version_number(ida_nalt.get_input_file_path())
    version_number_str = ".".join ([str (i) for i in version_number])

    module_info = dict()
    module_info['lib_info'] = gen_lib_binary_info()
    module_info['version'] = version_number_str
    json_dump_binary_info = dict()
    json_dump_binary_info[module_name] = module_info
    # json_dump_binary_info[module_name] = gen_gui_binary_info()

    out_file = dir_path + module_name + ".json"
    with open(out_file, 'w') as f:
        json.dump(json_dump_binary_info, f)
    print("[+] Done, dump the binary static info into json file, path: " +
          out_file)
