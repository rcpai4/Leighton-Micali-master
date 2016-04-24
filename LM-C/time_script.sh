#!/bin/bash

PERF_CMD="perf"

PERL_ARGS="stat -e cpu-cycles -B --append -o"

iteration=10

numsig=1024

declare -a ALGOS=("-lms")

for ALGO in "${ALGOS[@]}";  
do
    PERF_FILE="perf_stat$ALGO.txt"
    PROG="./main_lm -sha256 $ALGO -numsig"
    echo "PERF STATS SHA-256" > $PERF_FILE
    
    for j in `seq 1 $iteration`;
    do
        echo "" >> $PERF_FILE
        echo "$PERF_CMD $PERL_ARGS $PERF_FILE $PROG $numsig"
        $PERF_CMD $PERL_ARGS $PERF_FILE $PROG $numsig
    done
done


