# inspired by http://eli.thegreenplace.net/2011/07/03/parsing-c-in-python-with-clang/

import sys
import pprint
import clang.cindex

cfgs = [
"-cc1",
"-ast-dump",
"-fblocks",
"-x",
"objective-c",
"-isysroot",
"./MacOSX10.15.sdk",
]

clang.cindex.Config.set_library_file("./libclang.dylib")

index = clang.cindex.Index.create()
tu = index.parse("./main.c", args=cfgs)
#print('Translation unit:', tu.spelling)
#dump_incs(tu)
#dump_ast(tu)
#dump_funcs(tu)
#dump_records(tu)
#header_process(tu)
