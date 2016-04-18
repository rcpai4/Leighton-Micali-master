# Leighton-Micali-general

This is the implementation of Leighton-Micali hash based signature
system written in python. This is based(copy/paste) of ietf draft 
found in https://tools.ietf.org/html/draft-mcgrew-hash-sigs-03.

To run:
python hash-signature.py

For C-Implemention:
All the code(LM-OTS and LMS) is placed under Lm-C directory. Just go to this directory and run
the following command.

make clean

make all

To run LM-OTS test case run:

./main_lm -lmots

To run LMS test case run:

./main_lm -lms

To run HLMS test case run:

./main_lm -hlms

To run All test case run:

./main  -lmots -lms -hlms

To use specify the number of signatures :

./main  -numsig 250 

To choose SHA-256 as your hash you can use options:

./main  -sha256 

To choose BLAKE2B as your hash you can use options:

./main  -blake2b

To choose BLAKE2S as your hash you can use options:

./main  -blake2s 

To change the Hashing algorithm, goto to file commons.c. There is a global
variable called chosen_has_algo. Change it to SHA_256 or BLAKE_2B or BLAKE_2S
for respective hashing algorithm.

In order to run in the dragonboard 410c. You need to change the gcc compiler
in Makefile(if you are cross compiling).






