#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "randombytes.h"
#include "mkem.h"

#define NTESTS 1000
#define NKEYS 20

static uint32_t rbseed[32] = {
  3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5
};
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ rbseed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  uint32_t t[12]; uint32_t x; uint32_t sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ rbseed[12 + i];
  for (i = 0;i < 8;++i) out[i] = rbseed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

void randombytes(uint8_t *x,size_t xlen)
{
  while (xlen > 0) {
    if (!outleft) {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
    *x = out[--outleft];
    ++x;
    --xlen;
  }
}

static void testvector(uint8_t *v, unsigned long long vlen)
{
  unsigned long long i;
  for(i=0;i<vlen;i++)
    printf("%02x", v[i]);
  printf("\n");
}


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
  testvector(seed, KYBER_SYMBYTES);

  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_keypair(pk[i], sk[i], seed);
    testvector(pk[i], MKYBER_PUBLICKEYBYTES);
    testvector(sk[i], MKYBER_SECRETKEYBYTES);
  }

  /* Test monolithic batch API */
  crypto_mkem_enc(c1, c2, key_a, seed, NKEYS, pk);
  testvector(c1, MKYBER_C1BYTES);
  testvector(key_a, KYBER_SSBYTES);

  for(i=0;i<NKEYS;i++)
  {
    testvector(c2[i], MKYBER_C2BYTES);

    crypto_mkem_dec(key_b, c1, c2[i], sk[i]);
    if(memcmp(key_a, key_b, KYBER_SSBYTES)) {
      printf("ERROR keys (monolithic API) at position %lu\n", i);
      ret = 1;
      break;
    }
  }

  /* Test split batch API */
  randombytes(rnd, KYBER_SYMBYTES);
  testvector(rnd, KYBER_SYMBYTES);

  for(i=0;i<NKEYS;i++)
  {
    crypto_mkem_enc_c1(c1, key_a, fwd, seed, rnd);
    testvector(c1, MKYBER_C1BYTES);
    testvector(key_a, KYBER_SSBYTES);
    crypto_mkem_enc_c2(c2[i], pk[i], rnd, fwd);
    testvector(c2[i], MKYBER_C2BYTES);
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


int main(void)
{
  unsigned int i;

  for(i=0;i<NTESTS;i++) {
    if(test_keys()) return -1;
  }

  return 0;
}
