import json
import sys

jsons = []

out_file = sys.argv[1]

for arg in sys.argv[2:]:
    jsons.append(arg)
    #print('arg %s' % (arg))

whole_json = {}

for one_json_file in jsons:
    with open(one_json_file, 'r') as f:
        one_json = json.load(f)
        for libname, info in one_json.items():
            whole_json[libname] = info

with open(out_file, 'w') as f:
    json.dump(whole_json, f)