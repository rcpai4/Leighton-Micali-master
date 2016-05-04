#!/bin/bash

PERF_CMD="perf"

PERL_ARGS="stat -e cpu-cycles -e instructions -e cache-references
-e cache-misses -e branch-misses -e cpu-clock -e page-faults -e
context-switches -e cpu-migrations -e minor-faults -e major-faults -e
emulation-faults -e L1-dcache-loads -e L1-dcache-load-misses -e
L1-dcache-stores -e L1-dcache-store-misses -e branch-loads -e
branch-load-misses -B --append -o"

iteration=10

numsig=2

declare -a ALGOS=("priv" "pub" "sign" "verify")

for ALGO in "${ALGOS[@]}";  
do
    PERF_FILE="perf_stat-$ALGO.txt"
    PROG="./main_lm -sha256 -lmots -testmode $ALGO -numsig"
    echo "PERF STATS SHA-256" > $PERF_FILE
    
    for j in `seq 1 $iteration`;
    do
        echo "" >> $PERF_FILE
        echo "$PERF_CMD $PERL_ARGS $PERF_FILE $PROG $numsig"
        $PERF_CMD $PERL_ARGS $PERF_FILE $PROG $numsig
    done
done


