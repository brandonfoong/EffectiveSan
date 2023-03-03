#!/bin/python3

import re
import sys

def main():
    workloads = {}
    names = [
        '400.perlbench', '401.bzip2', '403.gcc', '429.mcf',
        '445.gobmk', '456.hmmer', '458.sjeng', '462.libquantum',
        '464.h264ref', '471.omnetpp', '473.astar', '483.xalancbmk',
        '433.milc', '444.namd', '447.dealII', '450.soplex',
        '453.povray', '470.lbm', '482.sphinx3'
    ]
    curr_prog = ''
    for line in sys.stdin:
        if 'program' in line:
            m = re.search('\d+\.\w+', line)
            prog = m.group(0)
            if prog not in workloads:
                workloads[prog] = [0, 0, 0]
        if 'cache' in line:
            hit, miss, cold_miss = line.split(',')
            h = int(hit.split()[3])
            m = int(miss.split()[3])
            cm = int(cold_miss.split()[3])
            workloads[prog][0] += h
            workloads[prog][1] += m
            workloads[prog][2] += cm
    print('workload hits misses total hit% cold_misses cold_miss%')
    for prog in names:
        total_hits, total_misses, total_cold_misses = workloads[prog]
        total = total_hits + total_misses
        if total:
            print(prog, total_hits, total_misses,
                total, f'{total_hits/total:.02f}',
                total_cold_misses, f'{total_cold_misses/total_misses:.05f}')
            print(f'{total_hits/total:.02f}', file=sys.stderr)
        # else:
        #     print(file=sys.stderr)

if __name__ == '__main__':
    main()
