#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "mkem.h"
#include "randombytes.h"

#define NTESTS 1000
#define NKEYS 5

static int test_keys(void)
{
  uint8_t *pk[NKEYS];
  uint8_t *sk[NKEYS];
  
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t rnd[KYBER_SYMBYTES];

  uint8_t c1[MKYBER_C1BYTES];
  uint8_t fwd[MKYBER_FWDBYTES];
  uint8_t *c2[NKEYS];

  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];

  size_t i;
  int ret = 0;

  for(i=0;i<NKEYS;i++)
  {
    pk[i] = malloc(MKYBER_PUBLICKEYBYTES);
    sk[i] = malloc(MKYBER_SECRETKEYBYTES);
    c2[i] = malloc(MKYBER_C2BYTES);
  }

  randombytes(seed, KYBER_SYMBYTES);

  for(i=0;i<NKEYS;i++)
    crypto_mkem_keypair(pk[i], sk[i], seed);

  /* Test monolithic batch API */
  crypto_mkem_enc(c1, c2, key_a, seed, NKEYS, pk);
  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR keys (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  /* Test split batch API */
  randombytes(rnd, KYBER_SYMBYTES);
  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_enc_c1(c1, key_a, fwd, seed, rnd);
    crypto_mkem_enc_c2(c2[i], pk[i], rnd, fwd);
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR keys (split API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  for(i=0;i<NKEYS;i++)
  {
    free(pk[i]);
    free(sk[i]);
    free(c2[i]);
  }

  return ret;
}

static int test_invalid_sk(void)
{
  uint8_t *pk[NKEYS];
  uint8_t *sk[NKEYS];
  
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t rnd[KYBER_SYMBYTES];

  uint8_t c1[MKYBER_C1BYTES];
  uint8_t fwd[MKYBER_FWDBYTES];
  uint8_t *c2[NKEYS];

  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];

  size_t i;
  int ret = 0;

  for(i=0;i<NKEYS;i++)
  {
    pk[i] = malloc(MKYBER_PUBLICKEYBYTES);
    sk[i] = malloc(MKYBER_SECRETKEYBYTES);
    c2[i] = malloc(MKYBER_C2BYTES);
  }

  randombytes(seed, KYBER_SYMBYTES);

  for(i=0;i<NKEYS;i++)
    crypto_mkem_keypair(pk[i], sk[i], seed);

  // Replace secret keys with randomness
  for(i=0;i<NKEYS;i++)
    randombytes(sk[i], MKYBER_SECRETKEYBYTES);
  

  /* Test monolithic batch API */
  crypto_mkem_enc(c1, c2, key_a, seed, NKEYS, pk);
  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  /* Test split batch API */
  randombytes(rnd, KYBER_SYMBYTES);
  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_enc_c1(c1, key_a, fwd, seed, rnd);
    crypto_mkem_enc_c2(c2[i], pk[i], rnd, fwd);
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR keys (split API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  for(i=0;i<NKEYS;i++)
  {
    free(pk[i]);
    free(sk[i]);
    free(c2[i]);
  }

  return ret;
}


static int test_invalid_ciphertext(void)
{
  uint8_t *pk[NKEYS];
  uint8_t *sk[NKEYS];
  
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t rnd[KYBER_SYMBYTES];

  uint8_t c1[MKYBER_C1BYTES];
  uint8_t fwd[MKYBER_FWDBYTES];
  uint8_t *c2[NKEYS];

  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];

  size_t i, pos;
  int ret = 0;

  for(i=0;i<NKEYS;i++)
  {
    pk[i] = malloc(MKYBER_PUBLICKEYBYTES);
    sk[i] = malloc(MKYBER_SECRETKEYBYTES);
    c2[i] = malloc(MKYBER_C2BYTES);
  }

  randombytes(seed, KYBER_SYMBYTES);

  for(i=0;i<NKEYS;i++)
    crypto_mkem_keypair(pk[i], sk[i], seed);

  /* Test monolithic batch API */
  crypto_mkem_enc(c1, c2, key_a, seed, NKEYS, pk);
  for(i=0;i<NKEYS;i++)
  {
    randombytes((unsigned char *)&pos, sizeof(pos));
    c1[pos % MKYBER_C1BYTES] ^= 1; /* Flip one bit in c1 */
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext c1 (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
    c1[pos % MKYBER_C1BYTES] ^= 1; /* Flip bit in c1 back */
    randombytes((unsigned char *)&pos, sizeof(pos));
    c2[i][pos % MKYBER_C2BYTES] ^= 1; /* Flip one bit in c2 */
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext c2 (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  /* Test split batch API */
  randombytes(rnd, KYBER_SYMBYTES);
  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_enc_c1(c1, key_a, fwd, seed, rnd);
    crypto_mkem_enc_c2(c2[i], pk[i], rnd, fwd);
    randombytes((unsigned char *)&pos, sizeof(pos));
    c1[pos % MKYBER_C1BYTES] ^= 1; /* Flip one bit in c1 */
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext c1 (split API) at position %lu\n", i);
      ret = 1;
      break;
    }
    c1[pos % MKYBER_C1BYTES] ^= 1; /* Flip bit in c1 back */
    randombytes((unsigned char *)&pos, sizeof(pos));
    c2[i][pos % MKYBER_C2BYTES] ^= 1; /* Flip one bit in c2 */
    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR invalid ciphertext c2 (split API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  for(i=0;i<NKEYS;i++)
  {
    free(pk[i]);
    free(sk[i]);
    free(c2[i]);
  }

  return ret;
}

int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk();
    r |= test_invalid_ciphertext();
    if(r)
      return 1;
  }

  return 0;
}
