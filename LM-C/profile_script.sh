#!/bin/sh

echo "PERF STATS" > perf_stats.txt
echo "" >> perf_stats.txt

PERF_CMD="perf"

PERL_ARGS="stat -e cpu-cycles -e instructions -e cache-references
-e cache-misses -e branch-misses -e cpu-clock -e page-faults -e
context-switches -e cpu-migrations -e minor-faults -e major-faults -e
emulation-faults -e L1-dcache-loads -e L1-dcache-load-misses -e
L1-dcache-stores -e L1-dcache-store-misses -e branch-loads -e
branch-load-misses -B --append -o perf_stats.txt"

PROG="./main_lm -lmots"

for i in `seq 1 10`;
do
    echo "" >> perf_stats.txt
    $PERF_CMD $PERL_ARGS $PROG
done   

