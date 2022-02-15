#!/bin/bash

./test_mkyber512
./test_mkyber768
./test_mkyber1024
./testvectors512 | diff - ../ref/vectors512
./testvectors768 | diff - ../ref/vectors768
./testvectors1024 | diff - ../ref/vectors1024
