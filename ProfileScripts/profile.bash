#!/bin/bash

i="0"
N="200"

echo "TIME PROFILE FOR LM-OTS" > file.txt

while [ $i -lt $N ]
do
    echo "ITERATION NUM: $i" >> file.txt
    { time python hash-signature.py; } 2>> file.txt
    i=$[$i+1]
done
mv file.txt time_profile_lmots.txt
