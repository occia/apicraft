# -*- coding: utf-8 -*-

import pathos.multiprocessing
import random
import sys

from pathos.multiprocessing import ProcessingPool as Pool
from multiprocessing import Queue
# python 2 use Q
#import Queue as Q
# for python 3 use q
import queue as Q
import datetime

import tblib.pickling_support
tblib.pickling_support.install()

idxQs = []
argQs = []


class ExceptionWrapper(object):
    def __init__(self, ee):
        self.ee = ee
        __, __, self.tb = sys.exc_info()

    def re_raise(self):
        # for Python 2 use this
        #raise self.ee, None, self.tb
        # for Python 3 replace the previous line by:
        raise self.ee.with_traceback(self.tb)

#
# multiprocessing
#

def cpunum():
    return pathos.multiprocessing.cpu_count()

# debug use
def do_in_serial_with_idx(do_func, all_args, rslt_handle, share_rslt):
    task_num = len(all_args)
    if task_num == 0:
        return

    rslt_list = []

    for args in all_args:
        if share_rslt:
            do_func(0, args, rslt_list)
        else:
            rslt_list.append(do_func(0, args))

    rslt_handle(rslt_list)

def loop_wrapper_with_idx(wrapper_args):
    global idxQs, argQs

    iQid, aQid, share_rslt = wrapper_args
    idxQ, argQ = idxQs[iQid], argQs[aQid]

    idx = idxQ.get()

    several_rslts = []

    start = datetime.datetime.now()

    try:
        while True:
            try:
                do_func, args = argQ.get_nowait()
                if share_rslt:
                    do_func(idx, args, several_rslts)
                else:
                    several_rslts.append(do_func(idx, args))
            except Q.Empty: 
                break
    except Exception as e:
        return [ ExceptionWrapper(e) ]

    end = datetime.datetime.now()
    #print("process %d handled %d tasks, exec time is %.4f s" % (idx, len(several_rslts), (end - start).total_seconds()))
    return several_rslts

def do_in_parallel_with_idx(do_func, all_args, rslt_handle, debug = False, para = None, share_rslt=False):
    task_num = len(all_args)
    if task_num == 0:
        return

    if debug:
        do_in_serial_with_idx(do_func, all_args, rslt_handle, share_rslt)
        return

    # do tasks in parallel
    if para == None:
        para = cpunum()
    if task_num < para:
        para = task_num

    idxQ = Queue()
    for idx in range(0, para):
        idxQ.put(idx)
    idxQs.append(idxQ)
    iQid = idxQs.index(idxQ)

    # prepare wrapper args
    argQ = Queue()
    for args in all_args:
        argQ.put((do_func, args))
    argQs.append(argQ)
    aQid = argQs.index(argQ)

    # run in parallel
    pool = Pool(para)
    rslt_list = []

    chunk_rslt_list = pool.uimap(loop_wrapper_with_idx, para * [ (iQid, aQid, share_rslt) ])
    for chunk_rslt in chunk_rslt_list:
        if (len(chunk_rslt) == 1) and isinstance(chunk_rslt[0], ExceptionWrapper):
            chunk_rslt[0].re_raise()
        rslt_list.extend(chunk_rslt)

    rslt_handle(rslt_list)

    pool.close()
    pool.join()
    pool.clear()

    idxQs.remove(idxQ)
    argQs.remove(argQ)

def test_do_func_with_idx(idx, args):
    print("idx %d args is %s" % (idx, args))

def test_rslt_handle(rslt_list):
    return

def test():
    do_in_parallel_with_idx(test_do_func_with_idx, ['a', 'b', 'c'], test_rslt_handle, debug=False)

if __name__ == '__main__':
    test()
