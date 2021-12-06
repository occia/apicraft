import sys
import json
import pprint

mode = sys.argv[1]
ty_json = sys.argv[2]
funcname = sys.argv[3]
typename = sys.argv[3]

pp = pprint.PrettyPrinter(indent=2)

with open(ty_json, 'r') as f:
    ty_info = json.load(f)
    tmap = ty_info['tmap']
    fmap = ty_info['fmap']

    if mode == 'f':
        print('%s:' % (funcname))
        pp.pprint(fmap[funcname])

        for info in fmap[funcname]['in']:
            intag = info['tag']
            print('\n%s:' % (intag) )
            pp.pprint(tmap[info['tkey']])

        for info in fmap[funcname]['out']:
            outtag = info['tag']
            print('\n%s:' % (outtag) )
            pp.pprint(tmap[info['tkey']])
    elif mode == 't':
        print('\n%s:' % (typename) )
        pp.pprint(tmap[typename])
    else:
        print('not f or t for 2nd argument')