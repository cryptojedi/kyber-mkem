# Kyber-mKEM

This repository contains implementations of a multi-KEM (mKEM) based on the 
[NIST PQC finalist Kyber](https://pq-crystals.org/kyber). 
Most of the code is from 
[the public-domain (CC0) implementations of Kyber](https://github.com/pq-crystals/kyber); 
the modifications implemented here are the ones required to move from KEM to mKEM functionality; see below for more details.

## Content of this repository
This repository contains a reference implementation in C (derived from the Kyber reference implementation)
and an optimized implementation targeting 64-bit Intel and AMD CPUs featuring the AVX2 vector instruction set (derived from the Kyber AVX2 implementation).

The most notable changes between the original Kyber implementation and the Kyber-mKEM implementation
here are in the file `mkem.c`, which replaces the file `kem.c` from the Kyber implementation,
and in the file `indcpa.c`, which implements the underlying IND-CPA secure public-key encryption.
Most notably, in `mkem.c` and `mkem.h` we introduce an API to implement the mKEM functionality.

The `crypto_mkem_keypair` function is given a public `seed` of length `KYBER_SYMBYTES` bytes 
and computes a secret key `sk` of length `MKYBER_SECRETKEYBYTES` 
and a public key `pk` of length `MKYBER_PUBLICKEYBYTES`:

```
int crypto_mkem_keypair(uint8_t *pk, 
                        uint8_t *sk, 
                        const uint8_t *seed);
```

Encapsulation to `num_keys` recipients receives as input an array of pointers to public keys `pk`;
each of those public keys needs to be of length `MKYBER_PUBLICKEYBYTES`. It additionally
receives the length of this array in the argument `num_keys` and the `seed` of `KYBER_SYMBYTES`.
This seed *has to be the same as the one used for in all keypair computations that computed
the public keys the function is encapsulating to*. The function computes as output a shared
secret `ss` of length `KYBER_SSBYTES` and ciphertexts. These ciphertexts consist of two parts;
the first part `c1` of length `MKYBER_C1BYTES` is the same for all recipients and can be broadcast.
The other component of length `MKYBER_C2BYTES` is different for each recipient. The caller
passes an array `c2` of `num_keys` pointers each pointing to an array of `MKYBER_C2BYTES`:

```
int crypto_mkem_enc(uint8_t *c1,
                    uint8_t **c2s,
                    uint8_t *ss,
                    const uint8_t *seed,
                    size_t num_keys,
                    uint8_t *const* pk);
```

Decapsulation uses essentially the same API as KEMs, except that the ciphertext is passed in
two individual components `c1` and `c2`:

```
int crypto_mkem_dec(uint8_t *ss,
                    const uint8_t *c1,
                    const uint8_t *c2,
                    const uint8_t *sk);
```

For encapsulation we also implement a "split" API consisting of two functions, one that performs
all recipient-independent computations (i.e., the first ciphertext component `c1`) and another
one computing the recipient-specific components `c2`. In addition to the arguments explained for
the monolithic encapsulation API above, these functions make use of a pointer to `KYBER_SYMBYTES`
secret uniformly random bytes `r` (which has to be the same randomness for the two functions) and
a pointer `fwd` to `MKYBER_FWDBYTES`, to forward results of intermediate computations from the function
computing `c1` to the function computing `c2`:

```
int crypto_mkem_enc_c1(uint8_t *c1,
                       uint8_t *ss,
                       uint8_t *fwd,
                       const uint8_t *seed,
                       const uint8_t *r);


int crypto_mkem_enc_c2(uint8_t *c2,
                       const uint8_t *pk,
                       const uint8_t *r,
                       const uint8_t *fwd);
```

## Example usage

For an example of how to use the API functions, see the `test_keys` function in file `ref/test_mkyber.c`.

## Build instructions 

These instructions are assuming a typical Linux build environment with clang and GNU make installed):

```
cd ref && make && ./test.sh
cd ../avx2 && make && ./test.sh
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
