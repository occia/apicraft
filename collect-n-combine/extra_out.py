import json
import sys

import libdump
from libdump import FuncTrace

from ipdb import launch_ipdb_on_exception

import gc

# 
# 1. generate header pp in header_preprocessing
# 2. (optional) generate correct trace to avoid 0xdecimal thing
# 3. run extra_out.py to generate headerpp_fixed & trace_fixed
# 4. rename headerpp & trace
# 5. run collect
# 6. run librelation
# 7. run combine
# 

_ftraces = {}
_tmap = None
_fmap = None

# meta information json file, readonly
a = '../workdir/headerpp/headerpp_audio.json'

# traces got from consumer programs
b = [
    '../workdir/osx_trace/audio/afclip_sample.json' , 
    '../workdir/osx_trace/audio/messages.json' ,
    '../workdir/osx_trace/audio/quicktimeplayer.json' ,
    '../workdir/osx_trace/audio/notes.json' ,
    '../workdir/osx_trace/audio/voicememos.json' ,
]

def parse_dump(ty_json, func_traces):
    global _ftraces
    global _tmap
    global _fmap

    # parse json
    with open(ty_json, 'r') as f:
        ty_info = json.load(f)
        _tmap = ty_info['tmap']
        _fmap = ty_info['fmap']

    # parse json of func trace
    for func_trace in func_traces:
        _ftrace = []
        with open(func_trace, 'r') as f:
            trace_json = json.load(f)
            for i in range(len(trace_json['traces'])):
                one_ft = FuncTrace(False, i, trace_json['traces'][i], _fmap)
                _ftrace.append(one_ft)

        _ftraces[func_trace] = _ftrace


def parse_as_little_endian(arg_dump):
    size = arg_dump.width
    val = [ arg_dump.val[2*i:2*i+2] for i in range(0, size/8) ]
    return int(''.join(val[::-1]), base=16)


def infer_possible_outs():
    global _ftraces
    global _tmap

    possible_outs = set()

    for trace_file, traces in _ftraces.items():
        for trace in traces:
            if trace.level == 1 and trace.paired:
                func_name = trace.ori_func_name
                # locate possible args (pointer arg, currently we only consider one layer pointer)
                pointer_args = []
                for intag in trace.inargs:
                    ty_info = trace.get_arg_type(intag)
                    if ty_info['is_pointer'] and trace.inargs[intag].succ and trace.outargs[intag].succ:
                        pointer_args.append(intag)
                # is value changed?
                for parg in pointer_args:
                    addr = parse_as_little_endian(trace.inargs[parg])
                    ty_info = trace.get_arg_type(parg)
                    tkey = ty_info['tkey']
                    pointee_ty = _tmap[tkey]['pointees'][0]['tkey']
                    pointee_width = _tmap[pointee_ty]['size']
                    if addr != 0 and pointee_width > 0:
                        if pointee_width % 8 != 0:
                            raise Exception('pointee width is not the multiple of 8 (%d)' % (pointee_width))
                        num_of_bytes = pointee_width / 8
                        invals, outvals = [], []
                        for i in range(num_of_bytes):
                            inval = trace.inmemdump[addr + i]
                            invals.append(inval)
                            outval = trace.outmemdump[addr + i]
                            outvals.append(outval)
                        if ''.join(invals) != ''.join(outvals):
                            # this is a possible out arg
                            possible_outs.add( (func_name, parg) )
                            #print( '%s %s ( %s ) is a possible out arg, inval %s outval %s' % (func_name, parg, ty_info['cmp_type'], ''.join(invals), ''.join(outvals)) )
                            #print( '%s %s ( %s ) is a possible out arg' % (func_name, parg, ty_info['cmp_type']) )

    return possible_outs


def fix_ty_info(ty_file, possible_outs):
    # TODO: now we use remove way to fix the headerpp.json
    #       add way should be better

    global _fmap
    global _tmap

    outs = {}

    for func_name, one_arg in possible_outs:
        if func_name not in outs:
            outs[func_name] = set()
        outs[func_name].add(one_arg)
    #print('outs ', outs)

    for func_name, info in _fmap.items():
        new_outs = []
        for arginfo in info['out']:
            if arginfo['tag'] == 'ret':
                new_outs.append(arginfo)
            elif arginfo['tag'] in outs.get(func_name, set([])):
                #arginfo['tag'] = 'out_%s' % (arginfo['tag'])
                #new_outs.append(arginfo)
                new_outs.append(arginfo['pointee'])
            else:
                # need to be removed
                continue
        info['out'] = new_outs
    
        new_ins = []
        for arginfo in info['in']:
            if 'pointee' in arginfo:
                del arginfo['pointee']
            new_ins.append(arginfo)
        info['in'] = new_ins

    with open(ty_file + '_fixed', 'w') as f:
        json.dump({ 'tmap': _tmap, 'fmap': _fmap }, f)


def fix_trace(func_trace_files, possible_outs):
    # stupid design
    # trace also needs to be fixed as the dump is not correct now
    # fix the arg in out to out_arg
    global _fmap
    global _tmap
    global _ftraces

    outs = {}

    for func_name, one_arg in possible_outs:
        if func_name not in outs:
            outs[func_name] = set()
        outs[func_name].add(one_arg)

    for func_trace_file in func_trace_files:
        with open(func_trace_file, 'r') as f:
            print('before modifying')
            trace_json = json.load(f)
            for i in range(len(trace_json['traces'])):
                fixed_in_dict = {}
                trace = trace_json['traces'][i]
                func_name = trace['basic']['demangled_name']

                new_out_args = {}
                for outtag, outarg in trace["out"]["args"].items():
                    if outtag == 'ret':
                        new_out_args[outtag] = outarg
                    elif outtag in outs.get(func_name, set([])):
                        tag = 'out_%s' % outtag

                        pointee_outarg = { 'cnt': None, 'tag': tag, 'type': None }

                        # little endian for now
                        addr = int(''.join(outarg['cnt'][::-1]), base=16)
                        pointee_tkey = None
                        for info in _fmap[func_name]['out']:
                            if info['tag'] == tag:
                                pointee_tkey = info['tkey']
                        pointee_width = _tmap[pointee_tkey]['size']
                        if addr != 0 and pointee_width > 0:
                            if pointee_width % 8 != 0:
                                raise Exception('pointee width is not the multiple of 8 (%d)' % (pointee_width))
                            num_of_bytes = pointee_width / 8
                            vals = []
                            for i in range(num_of_bytes):
                                addr_str = '0x%x' % (addr + i)
                                val = trace["out"]['memdump'][addr_str]
                                vals.append(val)
                            pointee_outarg['cnt'] = vals
                            pointee_outarg['type'] = 'succ'
                        else:
                            pointee_outarg['cnt'] = []
                            pointee_outarg['type'] = 'fail'

                        new_out_args[tag] = pointee_outarg
                    else:
                        # remove
                        continue
                    
                trace['out']['args'] = new_out_args

            print('before dump')
            with open(func_trace_file + '_fixed', 'w') as g:
                json.dump(trace_json, g)
            print('after dump')


def main():
    gc.enable()

    print('parse dump begin')
    parse_dump(a, b)
    #parse_dump(a, sys.argv[1:])
    gc.collect()
    print('parse dump end')

    print('infer possible outs begin')
    possible_outs = infer_possible_outs()
    gc.collect()
    print('infer possible outs end')

    print('fix ty info begin')
    fix_ty_info(a, possible_outs)
    gc.collect()
    print('fix ty info end')

    print('fix trace begin')
    fix_trace(b, possible_outs)
    print('fix trace end')


if __name__ == '__main__':
    with launch_ipdb_on_exception():
        main()
