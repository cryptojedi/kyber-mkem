#!/bin/bash

./test_mkyber512
./test_mkyber768
./test_mkyber1024
./testvectors512 > vectors512
./testvectors768 > vectors768
./testvectors1024 > vectors1024
