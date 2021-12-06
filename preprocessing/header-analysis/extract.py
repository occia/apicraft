# inspired by http://eli.thegreenplace.net/2011/07/03/parsing-c-in-python-with-clang/

import sys
import json
import pprint
import clang.cindex

from libtype import *

from ipdb import launch_ipdb_on_exception

NO = 0x0
DO = 0x1
EXP = 0x2

def verbose(cursor, level):
    '''filter predicate for show_ast: show all'''
    return DO | EXP

def shallow(cursor, level):
    if level == 0:
        return DO
    return NO

def only_children_do(cursor, level):
    if level >= 1:
        return DO | EXP
    return EXP

def no_system_includes(cursor, level):
    '''filter predicate for show_ast: filter out verbose stuff from system include files'''
    if (level!= 1) or (cursor.location.file is not None and not cursor.location.file.name.startswith('/usr/include')):
        return DO | EXP
    else:
        return NO

# A function show(level, *args) would have been simpler but less fun
# and you'd need a separate parameter for the AST walkers if you want it to be exchangeable.
class Level(int):
    '''represent currently visited level of a tree'''
    def show(self, *args):
        '''pretty print an indented line'''
        print('\t'*self + ' '.join(map(str, args)))
    def __add__(self, inc):
        '''increase level'''
        return Level(super(Level, self).__add__(inc))

def is_valid_type(t):
    '''used to check if a cursor has a type'''
    return t.kind != clang.cindex.TypeKind.INVALID
    
def is_a_record(t):
    return t.kind == clang.cindex.TypeKind.RECORD
    
def qualifiers(t):
    '''set of qualifiers of a type'''
    q = set()
    if t.is_const_qualified(): q.add('const')
    if t.is_volatile_qualified(): q.add('volatile')
    if t.is_restrict_qualified(): q.add('restrict')
    return q

def traverse(cursor, do, filter_pred=verbose, level=Level()):
    results = []
    st = filter_pred(cursor, level)  

    if st & DO:
        results.append(do(cursor, level))

    if st & EXP:
        for c in cursor.get_children():
            results.extend(traverse(c, do, filter_pred, level+1))

    return results

#
# predicate
#

def is_func_proto_type(cursor, level):
    if cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        if str(cursor.location.file).endswith(the_header_file):
        #if 'mupdf/' in str(cursor.location.file):
            return DO | EXP
    return EXP

def is_func_param_type(cursor, level):
    if cursor.kind == clang.cindex.CursorKind.PARM_DECL:
        return DO
    return EXP

def is_func_ret_type(cursor, level):
    if cursor.kind == clang.cindex.CursorKind.TYPE_REF:
        return DO | EXP
    return EXP

def is_record_type(cursor, level):
    kinds = [
        clang.cindex.CursorKind.STRUCT_DECL,
        clang.cindex.CursorKind.UNION_DECL,
        clang.cindex.CursorKind.CLASS_DECL,
    ]
    if cursor.kind in kinds:
        return DO | EXP
    return EXP

#
# do
#

def show_type(t, level, title):
    '''pretty print type AST'''
    global records
    level.show(title, str(t.kind), t.spelling, ' '.join(qualifiers(t)))
    #level.show(title, str(t.kind), ' '.join(qualifiers(t)))
    if is_valid_type(t.get_pointee()):
        show_type(t.get_pointee(), level+1, 'points to:')
    #elif is_a_record(t):
    #    for record in records:
    #        if record.type.spelling == t.spelling:
    #            level.show('subfields:')
    #            for field in record.get_children():
    #                show_type(field.type, level+1, 'field type')
    #else:
    #    pass

def show_ast(cursor, level):
    level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)
    #show_type(cursor.result_type, level, "result type")
    #if is_valid_type(cursor.type):
    #    show_type(cursor.type, level, 'type:')
    #    show_type(cursor.type.get_canonical(), level, 'canonical type:')

def show_func(cursor, level):
    #level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)
    level.show(cursor.spelling, cursor.displayname, cursor.location)

def show_arg(cursor, level):
    level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)

def show_ret(cursor, level):
    level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)
    if is_valid_type(cursor.type):
        show_type(cursor.type, level, 'type:')
        show_type(cursor.type.get_canonical(), level, 'canonical type:')

def show_records(cursor, level):
    level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)
    if is_valid_type(cursor.type):
        show_type(cursor.type, level, 'type:')
        show_type(cursor.type.get_canonical(), level, 'canonical type:')

def build_type_map(cursor=None, level=None, ty = None):
    global type_map

    libtype = None
    cty = None

    if cursor != None:
        ty = cursor.type

    if ty == None:
        raise Exception('ty is None')

    cty = ty.get_canonical()

    #print(ty.spelling, cty.spelling)

    if cty.spelling in type_map:
        return type_map[cty.spelling]

    type_map[cty.spelling] = LibTypeWrapper()

    kind = cty.kind
    if kind == clang.cindex.TypeKind.FUNCTIONPROTO or kind == clang.cindex.TypeKind.FUNCTIONNOPROTO:
        # function type
        args, ret = [], None

        if kind == clang.cindex.TypeKind.FUNCTIONPROTO:
            for arg_ty in cty.argument_types():
                args.append(build_type_map(None, None, arg_ty))

        ret = build_type_map(None, None, cty.get_result())
        get_ret_info = lambda c, l: ret.append(build_type_map(c))

        libtype = LibFuncType(cursor, ty, args, ret)
    elif kind == clang.cindex.TypeKind.RECORD:
        # composite type
        offsets, fields, widths = [], [], []

        for field_node in cty.get_fields():
            #show_ast(field_node, level)
            #show_type(field_node.type, Level(), "field")
            offsets.append(field_node.get_field_offsetof())
            fields.append(build_type_map(field_node, None, field_node.type))
            if field_node.is_bitfield():
                widths.append(field_node.get_bitfield_width())
            else:
                widths.append(field_node.type.get_size() * 8)

        libtype = LibRecordType(cursor, ty, fields, offsets, widths)
    elif kind == clang.cindex.TypeKind.POINTER:
        # pointer type
        #show_type(cty, Level(), "pointer")
        pointee = build_type_map(None, None, cty.get_pointee())

        libtype = LibPointerType(cursor, ty, pointee)
    elif kind == clang.cindex.TypeKind.VOID:
        # void type
        libtype = LibVoidType(cursor, ty)
    elif kind == clang.cindex.TypeKind.INVALID or kind == clang.cindex.TypeKind.UNEXPOSED:
        # invalid type
        libtype = LibInvalidType(cursor, ty)
    else:
        # TODO: perhaps add array type handling before the default plain type
        # other types
        libtype = LibPlainType(cursor, ty)

    # add type to type_map
    type_map[cty.spelling].set(libtype)

    return type_map[cty.spelling]


def build_func_map(cursor, level, ty = None):
    global type_map
    global func_map

    func = None
    cty = None
    ty_ref = None

    if cursor == None:
        raise Exception('cursor is None')

    ty = cursor.type
    cty = ty.get_canonical()

    kind = cty.kind
    if kind == clang.cindex.TypeKind.FUNCTIONPROTO or kind == clang.cindex.TypeKind.FUNCTIONNOPROTO:
        name = cursor.spelling

        if name in func_map:
            return

        if cty.spelling not in type_map:
            raise Exception('not find %s in type_map' % (name))

        if cursor.is_definition():
            # we ignore inline function as it cannot be traced but possibly will cause redefinition issues for liblook
            print("[WARN] Ignore inline function %s" % (name))
            return

        ty_ref = type_map[cty.spelling]

        func_map[name] = LibExpFunc(name, cursor, ty_ref)


#
# utils
#
def dump_incs(tu):
    for f in tu.get_includes():
        print('\t'*f.depth, f.include.name)

def dump_ast(tu):
    traverse(tu.cursor, show_ast, no_system_includes)

def dump_funcs(tu):
    global records
    collect_cursor = lambda c, l: c

    records.extend(traverse(tu.cursor, collect_cursor, is_record_type))

    funcs = traverse(tu.cursor, collect_cursor, is_func_proto_type)
    for f in funcs:
        print(">>>>>> dump for function %s >>>>>>" % (f.displayname))
        traverse(f, show_func, shallow)
        #traverse(f, show_func)
        print("arg \n")
        traverse(f, show_arg, is_func_param_type)
        print("ret \n")
        traverse(f, show_ret, is_func_ret_type)
        print("\n")

def dump_records(tu):
    collect_cursor = lambda c, l: c
    records.extend(traverse(tu.cursor, collect_cursor, is_record_type))
    for r in records:
        print(">>>>>> dump for records %s >>>>>>" % (r.displayname))
        traverse(r, show_records)
        print("\n")


def header_process(tu):
    pp = pprint.PrettyPrinter(indent=2)

    traverse(tu.cursor, build_type_map, verbose)

    #pp.pprint(type_map)

    traverse(tu.cursor, build_func_map, is_func_proto_type)

    #pp.pprint(func_map)


def to_maps_out(blacklist_funcs):
    global type_map
    global func_map
    global work_dir
    global out_file

    to_maps_out = build_type_maps(type_map, func_map, blacklist_funcs)

    #pp.pprint(to_maps_out)

    with open(work_dir + out_file, 'w') as f:
        json.dump(to_maps_out, f)


def to_libhook_out(blacklist_funcs):
    global func_map
    global work_dir
    global hook_code_file

    #to_libhook_out = build_pin_libhook_out(func_map, blacklist_funcs)
    to_libhook_out = build_sigjmp_libhook_out(func_map, blacklist_funcs)

    with open(work_dir + hook_code_file, 'w') as f:
        f.write(to_libhook_out)

def parse_per_line_file(file_name):
    lines = []
    with open(file_name, 'r') as f:
        for line in f.readlines():
            cnt = line.strip()
            if cnt.startswith('#'):
                continue
            lines.append(cnt)

    return list(set(lines))

def header_process1(tu):
    pp = pprint.PrettyPrinter(indent=2)

    raw_funcs, ty_funcs, pin_funcs = {}, {}, {}
    raw_records, ty_records, pin_records = {}, {}, {}

    collect_cursor = lambda c, l: c
    cursor_info = lambda c: (c.kind, c.type, str(c.type.kind), c.type.spelling, c.type.get_canonical(), str(c.type.get_canonical().kind), c.type.get_canonical().spelling, c.spelling, c.displayname, c.location)
    type_info = lambda t: (c.result_type, str(c.result_type.kind), c.result_type.spelling, c.result_type.get_canonical(), str(c.result_type.get_canonical().kind), c.result_type.get_canonical().spelling)

    # collect raw records
    record_nodes = traverse(tu.cursor, collect_cursor, is_record_type)
    for rnode in record_nodes:
        raw_record = {'self': None, 'members': []}

        get_raw_record_self_info = lambda c, l: raw_record.update({'self': cursor_info(c)})
        get_raw_record_members_info = lambda c, l: raw_record['members'].extend([ cursor_info(m) for m in rnode.get_children() ])

        traverse(rnode, get_raw_record_self_info, shallow)
        traverse(rnode, get_raw_record_members_info, only_children_do)

        raw_records[rnode.spelling] = raw_record

    pp.pprint(raw_records)

    # collect raw funcs
    func_nodes = traverse(tu.cursor, collect_cursor, is_func_proto_type)
    for fnode in func_nodes:
        raw_func = {'self': None, 'arg': [], 'ret': None}

        get_raw_func_info = lambda c, l: raw_func.update({'self': cursor_info(c)})
        get_raw_func_arg_info = lambda c, l: raw_func['arg'].append(cursor_info(c))
        get_raw_func_ret_info = lambda c, l: raw_func.update({'ret': type_info(c)})
        # func name
        traverse(fnode, get_raw_func_info, shallow)
        # func args
        traverse(fnode, get_raw_func_arg_info, is_func_param_type)
        # func ret
        traverse(fnode, get_raw_func_ret_info, shallow)

        raw_funcs[fnode.spelling] = raw_func
    pp.pprint(raw_funcs)

    # this is the interface to pintool
    # func in & out
    # now we consider return and pointer as out
    # all the arg are in
    for raw_func in raw_funcs:
        _in, _out = [], []
        for arg in raw_func['arg']:
            pass

the_header_file = None
records = []
out_file = None
hook_code_file = None
work_dir = "../workdir/headerpp/"

# Mac objc
osx_cfgs = [
"-cc1",
"-ast-dump",
"-fblocks",
"-x",
#"objective-c",
"objective-c++",
"-D__BEGIN_DECLS= ",
"-D__END_DECLS= ",
"-isysroot",
work_dir + "MacOSX10.15.sdk",
]

cfgs = osx_cfgs


'''
Usage: 

python extract.py \
        output_meta_info.json \
        output_generated_tracer_tool.mm \
        blacklist_cfg_file \
        header_file1 \
        header_file2 \
        header_file3 \
        header_file4 \
        header_file5 \
        header_file6 \
        ...
'''
def main():
    global the_header_file
    global cfgs
    global work_dir
    global out_file
    global hook_code_file

    clang.cindex.Config.set_library_file(work_dir + "libclang.dylib")
    #clang.cindex.Config.set_library_file(work_dir + "libclang.so")
    index = clang.cindex.Index.create()

    out_file = sys.argv[1]
    hook_code_file = sys.argv[2]
    blacklist_funcs = set(parse_per_line_file(work_dir + sys.argv[3]))
    
    for i in range(4, len(sys.argv)):
        the_header_file = sys.argv[i]
        tu = index.parse(sys.argv[i], args=cfgs)
        print('Translation unit:', tu.spelling)
        #dump_incs(tu)
        #dump_ast(tu)
        #dump_funcs(tu)
        #dump_records(tu)
        header_process(tu)

    to_maps_out(blacklist_funcs)
    to_libhook_out(blacklist_funcs)

if __name__ == '__main__':
    sys.setrecursionlimit(10000)
    with launch_ipdb_on_exception():
        main()
    #main()
