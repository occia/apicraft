import sys
import pprint
import clang.cindex


LIB_BT_FUNC     = 0
LIB_BT_RECORD   = 1
LIB_BT_POINTER  = 2
LIB_BT_VOID     = 3
LIB_BT_INVALID  = 4
LIB_BT_PLAIN    = 5


type_map = {}
func_map = {}


class LibTypeWrapper(object):
    def __init__(self, sth=None):
        self.cnt = sth

    def set(self, sth):
        self.cnt = sth

    def __str__(self):
        return 'Wrap<%s>' % (self.cnt)

    def __repr__(self):
        return 'Wrap<%s>' % (self.cnt.__repr__())


class LibBasicType(object):
    def __init__(self, c, t):
        # size is in bits
        self.cnode = c if c != None else None
        if c != None and t == None:
            t = c.type
        if t == None:
            raise Exception('error, type node is <NULL>')

        self.tnode = t
        self.ctnode = t.get_canonical()
        self.tkey = self.ctnode.spelling

        if self.cnode != None:
            self.ckind = self.cnode.kind
            # cspell behaves abnormal
            self.cspell = self.cnode.spelling
            self.cloc = self.cnode.location
            self.cdisp = self.cnode.displayname
        else:
            self.ckind = None
            self.cspell = None
            self.cloc = None
            self.cdisp = None

        self.tkind = self.tnode.kind
        self.tspell = self.tnode.spelling

        self.ctkind = self.ctnode.kind
        self.ctspell = self.ctnode.spelling

        # size is in bits
        #print('the tnode is %s %s %s %s' % (self.cspell, self.cloc, self.tspell, self.tkind))
        if self.tkind == clang.cindex.TypeKind.UNEXPOSED:
            self.size = -2
        else:
            size = self.tnode.get_size()
            self.size = size * 8 if size > 0 else size

    def is_pointer(self):
        return False

    def is_func(self):
        return False

    def is_typedef(self):
        return self.tkind == clang.cindex.TypeKind.TYPEDEF

    def is_integer(self):
        return self.tkind in set([ clang.cindex.TypeKind.UINT, clang.cindex.TypeKind.ULONG, clang.cindex.TypeKind.ULONGLONG ])

    def type_hash(self):
        return self.ctspell

    def is_same_type(self):
        raise Exception('has not implemented')

    def get_size(self):
        # size is in bits
        return self.size

    def is_size_error(self):
        '''
          CXTypeLayoutError_Invalid = -1,
          /**
           * The type is an incomplete Type.
           */
          CXTypeLayoutError_Incomplete = -2,
          /**
           * The type is a dependent Type.
           */
          CXTypeLayoutError_Dependent = -3,
          /**
           * The type is not a constant size type.
           */
          CXTypeLayoutError_NotConstantSize = -4,
          /**
           * The Field name is not valid for this record.
           */
          CXTypeLayoutError_InvalidFieldName = -5,
          /**
           * The type is undeduced.
           */
          CXTypeLayoutError_Undeduced = -6
        '''
        return self.size < 0

    def to_maps(self):
        raise Exception('has not implemented')


class LibFuncType(LibBasicType):
    def __init__(self, cursor, ty, args, ret):
        super(LibFuncType, self).__init__(cursor, ty)
        self.args = args
        self.ret = ret
        self.kind = LIB_BT_FUNC

    def __str__(self):
        return "LTFunc %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTFunc %s %s %d" % (self.tspell, self.cspell, self.size)

    def is_func(self):
        return True

    def to_maps(self):
        one = {'size': 0, 'pointees': [], 'tspell': self.tspell, 'ctspell': self.ctspell, 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


class LibRecordType(LibBasicType):
    def __init__(self, cursor, ty, fields, offsets, widths):
        super(LibRecordType, self).__init__(cursor, ty)
        self.offsets = offsets
        self.fields = fields
        self.widths = widths
        self.kind = LIB_BT_RECORD

    def __str__(self):
        return "LTRec %s %s %d %s" % (self.tspell, self.cspell, self.size, [(self.offsets[i], self.fields[i]) for i in range(len(self.fields))])
        #return "LTRec %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTRec %s %s %d %s" % (self.tspell, self.cspell, self.size, [(self.offsets[i], self.fields[i]) for i in range(len(self.fields))])
        #return "LTRec %s %s %d" % (self.tspell, self.cspell, self.size)

    def to_maps(self):
        one = {'size': self.size, 'pointees': [ {"offset": self.offsets[i], "tkey": self.fields[i].cnt.tkey} for i in range(len(self.fields)) if self.fields[i].cnt.is_pointer()], 'tspell': self.tspell, 'ctspell': self.ctspell , 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


class LibPointerType(LibBasicType):
    def __init__(self, cursor, ty, pointee):
        super(LibPointerType, self).__init__(cursor, ty)
        self.pointee = pointee
        self.kind = LIB_BT_POINTER

    def is_pointer(self):
        return True

    def __str__(self):
        return "LTPtr %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTPtr %s %s %d" % (self.tspell, self.cspell, self.size)

    def to_maps(self):
        one = {'size': self.size, 'pointees': [{"offset": 0, "tkey": self.pointee.cnt.tkey}], 'tspell': self.tspell, 'ctspell': self.ctspell, 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


class LibVoidType(LibBasicType):
    def __init__(self, cursor, ty):
        super(LibVoidType, self).__init__(cursor, ty)
        self.kind = LIB_BT_VOID

    def __str__(self):
        return "LTVoi %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTVoi %s %s %d" % (self.tspell, self.cspell, self.size)

    def to_maps(self):
        one = {'size': 0, 'pointees': [], 'tspell': self.tspell, 'ctspell': self.ctspell, 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


class LibInvalidType(LibBasicType):
    def __init__(self, cursor, ty):
        super(LibInvalidType, self).__init__(cursor, ty)
        self.kind = LIB_BT_INVALID

    def __str__(self):
        return "LTInv %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTInv %s %s %d" % (self.tspell, self.cspell, self.size)

    def to_maps(self):
        one = {'size': 0, 'pointees': [], 'tspell': self.tspell, 'ctspell': self.ctspell, 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


class LibPlainType(LibBasicType):
    def __init__(self, cursor, ty):
        super(LibPlainType, self).__init__(cursor, ty)
        self.kind = LIB_BT_PLAIN

    def __str__(self):
        return "LTPla %s %s %d" % (self.tspell, self.cspell, self.size)

    def __repr__(self):
        return "LTPla %s %s %d" % (self.tspell, self.cspell, self.size)

    def to_maps(self):
        one = {'size': self.size, 'pointees': [], 'tspell': self.tspell, 'ctspell': self.ctspell, 'tkind': str(self.tkind), 'ctkind': str(self.ctkind),}
        return one


def need_cmp(libtype):
    # TODO: add more
    scope = [clang.cindex.TypeKind.UNEXPOSED, clang.cindex.TypeKind.POINTER, clang.cindex.TypeKind.RECORD, clang.cindex.TypeKind.ENUM]
    return libtype.tspell != libtype.ctspell or libtype.tnode.kind in scope


class LibExpFunc():
    def __init__(self, name, cursor, ty_ref):
        self.name = name
        self.fkey = name
        self.node = cursor
        self.ty_ref = ty_ref
        self.mangled_name = cursor.mangled_name

        self.arg_sizes = []
        # in/out strategy
        self.ins = []
        self.outs = []
        idx = 0
        #get_one = lambda tag, arg_ref: {'tag': tag, 'type': arg_ref, 'cmp_type': arg_ref.cnt.tspell, 'ct_type': arg_ref.cnt.ctspell, 'need_cmp': need_cmp(arg_ref.cnt), 'is_pointer': arg_ref.cnt.is_pointer(), 'is_int': arg_ref.cnt.is_integer() }
        get_one = lambda tag, arg_ref: {'tag': tag, 'type': arg_ref, 'tkey': arg_ref.cnt.tkey, 'cmp_type': arg_ref.cnt.tspell, 'ct_type': arg_ref.cnt.ctspell, 'need_cmp': need_cmp(arg_ref.cnt), 'is_pointer': arg_ref.cnt.is_pointer(), 'is_int': arg_ref.cnt.is_integer() }

        for arg_ref in self.ty_ref.cnt.args:
            one = get_one('arg%d' % (idx), arg_ref)
            if one['is_pointer']:
                # this is used for second time fix of the libtype
                one['pointee'] = get_one('out_arg%d' % (idx), arg_ref.cnt.pointee)
                #raise Exception('here')
                #one['pointee'] = {}
            self.ins.append(one)
            self.outs.append(one)
            self.arg_sizes.append(arg_ref.cnt.get_size())
            idx = idx + 1

        ret_ref = self.ty_ref.cnt.ret
        self.outs.append( get_one('ret', ret_ref) )
        self.arg_sizes.append(ret_ref.cnt.get_size())

    def __str__(self):
        return "LEFunc (%s) %s %s" % (self.ty_ref, self.name, self.node.location)

    def __repr__(self):
        return "LEFunc (%s) %s %s" % (self.ty_ref.__repr__(), self.name, self.node.location)

    def to_maps(self):
        func = {'in': [], 'out': []}
        for _in in self.ins:
            one = {}
            one['tag'] = _in['tag']
            # to avoid type cannot be serialize
            #one['tkey'] = _in['type'].cnt.tkey
            one['tkey'] = _in['tkey']
            one['cmp_type'] = _in['cmp_type']
            one['ct_type'] = _in['ct_type']
            one['need_cmp'] = _in['need_cmp']
            one['is_pointer'] = _in['is_pointer']
            one['is_int'] = _in['is_int']
            if one['is_pointer']:
                # to avoid type cannot be serialize
                one['pointee'] = _in['pointee']
                del one['pointee']['type']
            func['in'].append(one)

        for _out in self.outs:
            one = {}
            one['tag'] = _out['tag']
            #one['tkey'] = _out['type'].cnt.tkey
            one['tkey'] = _out['tkey']
            one['cmp_type'] = _out['cmp_type']
            one['ct_type'] = _out['ct_type']
            one['need_cmp'] = _out['need_cmp']
            one['is_pointer'] = _out['is_pointer']
            one['is_int'] = _out['is_int']
            if one['is_pointer'] and (one['tag'] != 'ret'):
                one['pointee'] = _out['pointee']
            func['out'].append(one)

        func['tspell'] = self.ty_ref.cnt.tspell
        func['ctspell'] = self.ty_ref.cnt.ctspell
        func['arg_sizes'] = self.arg_sizes
        func['mangled_name'] = self.mangled_name
        return func

    # libhook generation common funcs
    def libhook_handle_tys(self, ty_ref, tid, extra_usings):
        custom_typedef_check = lambda t: ( t.cnt.tkind == clang.cindex.TypeKind.TYPEDEF ) or \
                                        ( t.cnt.is_func() ) or \
                                        ( t.cnt.tkind == clang.cindex.TypeKind.CONSTANTARRAY ) or \
                                        ( t.cnt.tkind == clang.cindex.TypeKind.ENUM )
        #                                ( t.cnt.tspell.startswith('enum ') )
        if ty_ref.cnt.is_typedef():
            return ty_ref.cnt.tspell

        need_custom_typedef = False
        tref = ty_ref
        while True:
            if custom_typedef_check(tref):
                need_custom_typedef = True
                break
            elif tref.cnt.is_pointer():
                tref = tref.cnt.pointee
            else:
                break
        if need_custom_typedef:
            using = 'using %s = %s;' % (tid, ty_ref.cnt.tspell)
            extra_usings.append(using)
            return tid
        else:
            return ty_ref.cnt.tspell

    def to_pin_libhook(self):
        get_tid = lambda func, tag: func + "_T_" + tag
        func_id = self.fkey
        extra_ty = []
        extra_usings = []

        # ret
        ret_type = self.libhook_handle_tys(self.ty_ref.cnt.ret, get_tid(func_id, 'ret'), extra_usings)

        # args, we believe all args at least will be inarg
        args = []
        for one_arg in self.ins:
            tag = one_arg['tag']
            arg_ref = one_arg['type']
            args.append( (tag, self.libhook_handle_tys(arg_ref, get_tid(func_id, tag), extra_usings)) )
            #if func_id == "CGContextSetShouldSubpixelPositionFonts":
            #    print('tag ', tag, arg_ref.cnt.tspell, arg_ref.cnt.tnode.get_pointee().spelling, arg_ref.cnt.tnode.get_pointee().kind)
        # WARN: we also assume arg tag is arg%d
        args.sort( key=lambda arg: int(filter(str.isdigit, arg[0])) )

        temp = '\n'.join(extra_ty)
        # proto
        proto = "%s my_%s (%s)" % (ret_type, func_id, ', '.join([ pair[1] + " " + pair[0] for pair in args ]))
        extra_using_str = '\n'.join(extra_usings)
        if ret_type != 'void':
            temp += '''
#define FUNC_ID "%s"
// extra usings
%s
// declaration
%s;
DYLD_INTERPOSE(my_%s, %s)
// definition
%s 
{
    //disc_enter_func(FUNC_ID);
    %s ret = %s(%s);
    //disc_leave_func(FUNC_ID, (void *)&ret);
    return ret;
}
#undef FUNC_ID
'''
            return temp % (func_id, extra_using_str, proto, func_id, func_id, proto, ret_type, func_id, ', '.join([ pair[0] for pair in args ]))
        else:
            temp += '''
#define FUNC_ID "%s"
// extra usings
%s
// declaration
%s;
DYLD_INTERPOSE(my_%s, %s)
// definition
%s 
{
    //disc_enter_func(FUNC_ID);
    %s(%s);
    //disc_leave_func(FUNC_ID, NULL);
}
#undef FUNC_ID
'''
            return temp % (func_id, extra_using_str, proto, func_id, func_id, proto, func_id, ', '.join([ pair[0] for pair in args ]))

    def to_sigjmp_libhook(self):
        get_tid = lambda func, tag: func + "_T_" + tag
        func_id = self.fkey
        extra_ty = []
        extra_usings = []

        #if func_id == 'aaa':
        #    print(func_id, self.node.location, self.ty_ref.cnt.tnode.kind)

        # ret
        ret_type = self.libhook_handle_tys(self.ty_ref.cnt.ret, get_tid(func_id, 'ret'), extra_usings)
        #if func_id == "png_set_longjmp_fn":
        #    ret_ref = self.ty_ref.cnt.ret
        #    print('ret ', ret_ref.cnt.cloc, ret_ref.cnt.tspell, ret_ref.cnt.ctspell, ret_ref.cnt.tnode.spelling, ret_ref.cnt.tnode.kind, ret_ref.cnt.pointee.cnt.tnode.kind)

        # args, we believe all args at least will be inarg
        # and we also dump all in args in outs to infer out arg
        args = []
        outs = []

        for one_arg in self.ins:
            tag = one_arg['tag']
            arg_ref = one_arg['type']
            args.append( (tag, self.libhook_handle_tys(arg_ref, get_tid(func_id, tag), extra_usings)) )
            #if func_id == "aaa":
            #    print('tag ', tag, arg_ref.cnt.tspell, arg_ref.cnt.tnode.get_pointee().spelling, arg_ref.cnt.tnode.get_pointee().kind)
        # WARN: we also assume arg tag is arg%d
        args.sort( key=lambda arg: int(filter(str.isdigit, arg[0])) )

        for one_out in self.outs:
            tag = one_out['tag']
            out_ref = one_out['type']
            if tag != 'ret' or ret_type != 'void':
                outs.append( (tag, self.libhook_handle_tys(out_ref, get_tid(func_id, tag), extra_usings)) )

        temp = '\n'.join(extra_ty)
        # proto
        arglist_proto = "%s" % (', '.join([ pair[1] + " " + pair[0] for pair in args ]))
        if self.name == 'CFArrayApplyFunction':
            # we cannot handle attribute thing easily
            arglist_proto = "CFArrayRef arg0, CFRange arg1, CFArrayApplierFunction CF_NOESCAPE arg2, void *arg3"
        arglist = ', '.join([ pair[0] for pair in args ])
        # arg dump
        in_arg_dumps = '\n            '.join([ 'DUMP_ARG(&funcArgs, FUNC_ID, true, %s);' % (arg_tag) for arg_tag, _ in args ])
        out_arg_dumps = '\n            '.join([ 'DUMP_ARG(&funcArgs, FUNC_ID, false, %s);' % (out_tag) for out_tag, _ in outs ])
        extra_using_str = '\n'.join(extra_usings)

        if ret_type != 'void':
            temp += '''
#define FUNC_ID "%s"
#pragma push_macro(FUNC_ID)
#undef %s
// extra usings
%s
INTERPOSE(%s)(%s)
{
    #define RUN_FUNC  %s ret = real::%s(%s)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
        return ret;
    } else {
        {
            FuncArgs funcArgs;
            %s
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            %s
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }

        return ret;
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID
'''
            return temp % (func_id, func_id, extra_using_str, func_id, arglist_proto, ret_type, func_id, arglist, in_arg_dumps, out_arg_dumps)
        else:
            temp += '''
#define FUNC_ID "%s"
#pragma push_macro(FUNC_ID)
#undef %s
// extra usings
%s
INTERPOSE(%s)(%s)
{
    #define RUN_FUNC  real::%s(%s)

    static std::atomic_int run_count(0);
    void *caller0 = __builtin_extract_return_addr (__builtin_return_address (0));
    void *caller1 = 0;
    //void *caller1 = __builtin_extract_return_addr (__builtin_return_address (1));

    int cur_count = atomic_fetch_add(&run_count, 1);

    init_libhook();

    if (needs_dump) {
        dump_trace();
        RUN_FUNC;
    } else {
        {
            FuncArgs funcArgs;
            %s
            func_enter(FUNC_ID, &funcArgs, caller0, caller1, cur_count);
        }
        RUN_FUNC;
        {
            FuncArgs funcArgs;
            %s
            func_leave(FUNC_ID, &funcArgs, cur_count);
        }
    }

    #undef RUN_FUNC
}
#pragma pop_macro(FUNC_ID)
#undef FUNC_ID
'''
            return temp % (func_id, func_id, extra_using_str, func_id, arglist_proto, func_id, arglist, in_arg_dumps, out_arg_dumps)



def build_type_maps(_typemap, _funcmap, blacklist_funcs):
    tmap, fmap = {}, {}

    for tkey, tref in _typemap.items():
        if tkey != "":
            tmap[tkey] = tref.cnt.to_maps()

    for fkey, f in _funcmap.items():
        if fkey not in blacklist_funcs:
            fmap[fkey] = f.to_maps()
            #fmap['my_' + fkey] = f.to_maps()

    # TODO: add disc enter/leave in type map?

    return {'tmap': tmap, 'fmap': fmap}

def build_pin_libhook_out(_funcmap, blacklist_funcs):
    funcs = []

    # headers
    funcs.append('''
#include <stdio.h>
//#include <string.h>
#include <unistd.h>
#include <fcntl.h>
//#import <CoreGraphics/CoreGraphics.h>
//#import <AudioToolbox/AudioToolbox.h>
//#import <CoreText/CoreText.h>
''')

    # macros
    funcs.append('''
#define DYLD_INTERPOSE(_replacment,_replacee) \\
  __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \\
  __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };
''')

    # disc enter/leave funcs
    """
    funcs.append('''
void disc_enter_func(const char *func_id)
{
  fprintf(stderr, "entering my_%s\\n", func_id);
}

void disc_leave_func(const char *func_id, void *ret)
{
  fprintf(stderr, "leaving my_%s\\n", func_id);
}
''')
    """

    for fkey, f in _funcmap.items():
        if fkey not in blacklist_funcs:
            funcs.append('/////////////////////')
            funcs.append(f.to_pin_libhook())
    
    return '\n'.join(funcs)

def build_sigjmp_libhook_out(_funcmap, blacklist_funcs):
    template_file = "./sigjmp_hook_temp.cpp"
    funcs = []

    with open(template_file, 'r') as f:
        funcs.append(f.read(-1))

    # headers
    funcs.append('''
#include <unistd.h>
#include <fcntl.h>
#import <CoreGraphics/CoreGraphics.h>
#import <AudioToolbox/AudioToolbox.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreText/CoreText.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreAudio/CoreAudio.h>
#import <CoreAudio/AudioDriverPlugIn.h>

''')

    funcs.append('''
void dump_arg(FuncArgs *funcArgs, const char *funcName, bool isIn, const char *tag, unsigned char *argp, size_t len)
{
    funcArgs->addInfo(funcName, isIn, tag, argp, len);
}

#define DUMP_ARG(funcArgs, func, isin, arg) dump_arg(funcArgs, func, isin, #arg, (unsigned char *)(&arg), sizeof(arg))

''')

    for fkey, f in _funcmap.items():
        if fkey not in blacklist_funcs:
            funcs.append('/////////////////////')
            funcs.append(f.to_sigjmp_libhook())
    
    return '\n'.join(funcs)
