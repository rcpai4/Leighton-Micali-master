#!/bin/sh

PERF_CMD="perf"

PERL_ARGS="stat -e cpu-cycles -e instructions -e cache-references
-e cache-misses -e branch-misses -e cpu-clock -e page-faults -e
context-switches -e cpu-migrations -e minor-faults -e major-faults -e
emulation-faults -e L1-dcache-loads -e L1-dcache-load-misses -e
L1-dcache-stores -e L1-dcache-store-misses -e branch-loads -e
branch-load-misses"

PROG="./main_lm -lmots"

sudo $PERF_CMD $PERL_ARGS $PROG
