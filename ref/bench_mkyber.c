#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "mkem.h"
#include "randombytes.h"

#define NRUNS 1000
#define MAXUSERS 1000
 
static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

static uint64_t cpucycles_overhead(void) {
  uint64_t t0, t1, overhead = -1LL;
  unsigned int i;

  for(i=0;i<100000;i++) {
    t0 = cpucycles();
    __asm__ volatile ("");
    t1 = cpucycles();
    if(t1 - t0 < overhead)
      overhead = t1 - t0;
  }

  return overhead;
}
 
static int cmp_uint64(const void *a, const void *b) {
  if(*(uint64_t *)a < *(uint64_t *)b) return -1;
  if(*(uint64_t *)a > *(uint64_t *)b) return 1;
  return 0;
}

static uint64_t median(uint64_t *l, size_t llen) {
  qsort(l,llen,sizeof(uint64_t),cmp_uint64);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}


static void print_bench(char *s, int n, int k, uint64_t *t,size_t tlen)
{
  static uint64_t overhead = -1;
  size_t i;

  if(tlen < 2) {
    fprintf(stderr, "ERROR: Need a least two cycle counts!\n");
    return;
  }

  if(overhead  == (uint64_t)-1)
    overhead = cpucycles_overhead();

  tlen--;
  for(i=0;i<tlen;++i)
    t[i] = t[i+1] - t[i] - overhead;

  printf("\\newcommand{%s", s);
  if(k==2) printf("low");
  if(k==3) printf("mid");
  if(k==4) printf("high");
  switch(n){
    case 1:
      printf("one");
      break;
    case 2:
      printf("two");
      break;
    case 10:
      printf("X");
      break;
    case 100:
      printf("C");
      break;
    case 1000:
      printf("M");
      break;
  }
  printf("ref}{$%lu$}\n",median(t, tlen));
}

static void run_bench(void)
{
  uint8_t *pks[MAXUSERS];
  uint8_t *sks[MAXUSERS];
  
  uint8_t seed[KYBER_SYMBYTES];

  uint8_t c1[MKYBER_C1BYTES];
  uint8_t *c2s[MAXUSERS];

  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];

  uint64_t t[NRUNS];

  size_t i;

  for(i=0;i<MAXUSERS;i++)
  {
    pks[i] = malloc(MKYBER_PUBLICKEYBYTES);
    sks[i] = malloc(MKYBER_SECRETKEYBYTES);
    c2s[i] = malloc(MKYBER_C2BYTES);
  }

  randombytes(seed, KYBER_SYMBYTES);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_keypair(pks[0], sks[0], seed);
  }
  print_bench("\\mgencyc",0,KYBER_K,t,NRUNS);

  for(i=0;i<MAXUSERS;i++)
    crypto_mkem_keypair(pks[i], sks[i], seed);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_enc(c1, c2s, key_a, seed, 1, pks);
  }
  print_bench("\\menccyc",1,KYBER_K,t,NRUNS);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_enc(c1, c2s, key_a, seed, 2, pks);
  }
  print_bench("\\menccyc",2,KYBER_K,t,NRUNS);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_enc(c1, c2s, key_a, seed, 10, pks);
  }
  print_bench("\\menccyc",10,KYBER_K,t,NRUNS);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_enc(c1, c2s, key_a, seed, 100, pks);
  }
  print_bench("\\menccyc",100,KYBER_K,t,NRUNS);

  for(i=0;i<NRUNS;i++) {
    t[i] = cpucycles();
    crypto_mkem_enc(c1, c2s, key_a, seed, 1000, pks);
  }
  print_bench("\\menccyc",1000,KYBER_K,t,NRUNS);

  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    crypto_mkem_dec(key_b, c1, c2s[0], sks[0]);
  }
  print_bench("\\mdeccyc",0,KYBER_K,t,NRUNS);

  for(i=0;i<MAXUSERS;i++)
  {
    free(pks[i]);
    free(sks[i]);
    free(c2s[i]);
  }

#if KYBER_K == 2
  printf("\\newcommand{\\mpkbyteslowoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowoneref}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteslowtworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowtworef}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowtworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteslowXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowXref}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteslowCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowCref}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteslowMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowMref}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#elif KYBER_K == 3
  printf("\\newcommand{\\mpkbytesmidoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidoneref}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbytesmidtworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidtworef}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidtworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbytesmidXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidXref}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbytesmidCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidCref}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbytesmidMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidMref}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#elif KYBER_K == 4
  printf("\\newcommand{\\mpkbyteshighoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighoneref}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighoneref}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteshightworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshightworef}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshightworef}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteshighXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighXref}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighXref}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteshighCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighCref}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighCref}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteshighMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighMref}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighMref}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#endif
}

int main(void)
{
  run_bench();
  return 0;
}
