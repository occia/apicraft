#!/bin/bash

set -x
set -e

task=$1
workdir=../workdir/harness_gen

[ ! -d cfgs/${task}/relations ] && echo "error task value ${task}" && exit 1
[ ! -d cfgs/${task}/funcs ] && echo "error task value ${task}" && exit 1
[ ! -d cfgs/${task}/cfgs ] && echo "error task value ${task}" && exit 1
[ ! -f cfgs/${task}/env ] && echo "error task value ${task}" && exit 1

# this intros HEADERPP, TIMEIDA, COVIDA
. cfgs/${task}/env

get_name() {
	echo `basename $1` | awk -F"." '{print $1}' | awk -F"-" '{print $2}'
}

combine() {
	_relation=$1
	_func=$2
	_cfg=$3
	_hpp=$4
	_covida=$5
	
	#/Users/kvmmac/Library/Python/2.7/bin/kernprof -l -v combine.py \
	python3 combine.py \
	    ${_hpp} \
	    ${_relation} \
	    ${_func} \
	    ${_cfg} \
	    ${_covida}
}

for func in cfgs/${task}/funcs/use-*
do
	for relation in cfgs/${task}/relations/use-*
	do
		for cfg in cfgs/${task}/cfgs/use-*
		do
			echo ">>> handling ${task} ${relation} ${func} ${cfg} <<<"

			cd ${workdir}
			bash clean.sh
			cd -
			combine ${relation} ${func} ${cfg} ${HEADERPP} ${COVIDA}

			cd ${workdir}

			dir=${task}-`get_name ${cfg}`-`get_name ${relation}`-`get_name ${func}`

			rm -rf ${dir}
			mkdir -p ${dir}

			rsync -r --include='*.sh' --exclude='*' . ${dir}/
			rsync -r --remove-source-files --include='*.txt' --include='*.json' --include='*.m' --include='*.mm' --include='*.png' --include='*.log' --include='*.gv' --exclude='*' . ${dir}/
			rm -f dyn_probe*.sh
			bash clean.sh

			cd -
		done
	done
done

