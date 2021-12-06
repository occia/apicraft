# -*- coding: utf-8 -*-

import sys
import json
import os.path

# this is the most simple metric
# we could add more function here that leverage binary analysis info using IDA
def calc_total_bb_num(covtrace):
    #print('bb num is %d' % covtrace['basic_blocks_info']['unique_count'])
    return covtrace['basic_blocks_info']['unique_count']

def get_trace_unique_bb(covtrace):
    return list(set([ (d['image'], d['offset']) for d in covtrace['basic_blocks_info']['list'] ]))

def parse_pin_cov_trace(cov_json):
    with open(cov_json, 'r') as f:
        covtrace = json.load(f)
        for info in covtrace['basic_blocks_info']['list']:
            info['image'] = os.path.basename(info['image']).strip()
        return covtrace

# including tinyinst & frida
def parse_others_cov_trace(cov_file):
    covtrace = {}

    #print('cov_file is %s' % (cov_file))
    with open(cov_file, 'r') as f:
        covtrace['basic_blocks_info'] = { 'list':[], 'unique_count':0 }
        # WARN: empty blacklist in tinyinst
        covtrace['blacklisted_modules'] = { 'list':[], 'unique_count':0 }
        # WARN: empty modules in tinyinst
        covtrace['modules'] = { 'list':[], 'unique_count':0 }

        for line in f:
            if line.strip() != '':
                module_name, offset = line.strip().split('+')
                # WARN: the module name is different from what we get in pin, this is the basename in tinyinst while full path in pin
                covtrace['basic_blocks_info']['list'].append({'image': module_name, 'offset': int(offset, base=16)})
        covtrace['basic_blocks_info']['unique_count'] = len(covtrace['basic_blocks_info']['list'])
    
    return covtrace

def call_as_lib(cov_json):
    # 1. parse cov trace
    #covtrace = parse_pin_cov_trace(cov_json)
    covtrace = parse_others_cov_trace(cov_json)

    #print("total bb num is %d" % (calc_total_bb_num()))

    # 2. calculate metric (could add IDA part)
    # the out_json is dyninfo
    out_json = {}
    out_json["bb_count"] = calc_total_bb_num(covtrace)
    out_json["trace_bbs"] = get_trace_unique_bb(covtrace)

    return out_json

def main():
    # 1. parse cov trace
    cov_json = sys.argv[1]
    out_file = sys.argv[2]

    #covtrace = parse_pin_cov_trace(cov_json)
    covtrace = parse_others_cov_trace(cov_json)

    #print("total bb num is %d" % (calc_total_bb_num()))

    # 2. calculate metric (could add IDA part)
    # the out_json is dyninfo
    out_json = {}
    out_json["bb_count"] = calc_total_bb_num(covtrace)
    out_json["trace_bbs"] = get_trace_unique_bb(covtrace)

    # 3. dump to file
    with open(out_file, 'w') as f:
        json.dump(out_json, f)

if __name__ == '__main__':
    main()
