# Kyber-mKEM

## Build instructions 

These instructions are assuming a typical Linux build environment with clang and GNU make installed):

```
cd ref && make && test.sh
cd ../avx2 && make && test.sh
```

This will build and run functional tests and generate and compare test vectors
of all parameter sets of both implementations. 

In order to run benchmarks of the AVX2-based implementation (outputting LaTeX macros), 
simply run 

```
cd avx2
./bench_mkyber512
./bench_mkyber768
./bench_mkyber1024
```
