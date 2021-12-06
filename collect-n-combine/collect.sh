#!/bin/bash

set -x
set -e

task=$1
workdir=../workdir/harness_gen

[ ! -d cfgs/${task}/traces ] && echo "error task value ${task}" && exit 1
[ ! -d cfgs/${task}/funcs ] && echo "error task value ${task}" && exit 1
[ ! -d cfgs/${task}/cfgs ] && echo "error task value ${task}" && exit 1
[ ! -f cfgs/${task}/env ] && echo "error task value ${task}" && exit 1

# intros HEADERPP, TIMEIDA, COVIDA
. cfgs/${task}/env

get_name() {
	echo `basename $1` | awk -F"." '{print $1}' | awk -F"-" '{print $2}'
}


collect_one() {
	_task=$1
	_trace=$2
	_func=$3
	_cfg=$4
	_hpp=$5
	
	#/Users/kvmmac/Library/Python/2.7/bin/kernprof -l -v collect.py \
	python collect.py \
	    ${_hpp} \
	    ${_trace} \
	    ${_func} \
	    ${_cfg} \
	    ../relations/R_${_task}.json
}

for func in cfgs/${task}/funcs/use-*
do
	for trace in cfgs/${task}/traces/use-*
	do
                for cfg in cfgs/${task}/cfgs/use-*
                do
			echo ">>> collecting ${task} ${trace} ${func} ${cfg} <<<"

			name=${task}-`get_name ${cfg}`-`get_name ${trace}`-`get_name ${func}`
			collect_one ${name} ${trace} ${func} ${cfg} ${HEADERPP}
		done
	done
done

