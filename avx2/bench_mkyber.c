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
  printf("}{$%lu$}\n",median(t, tlen));
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
  printf("\\newcommand{\\mpkbyteslowone}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowone}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowone}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteslowtwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowtwo}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowtwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteslowX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowX}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteslowC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowC}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteslowM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteslowM}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteslowM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#elif KYBER_K == 3
  printf("\\newcommand{\\mpkbytesmidone}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidone}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidone}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbytesmidtwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidtwo}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidtwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbytesmidX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidX}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbytesmidC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidC}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbytesmidM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbytesmidM}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbytesmidM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#elif KYBER_K == 4
  printf("\\newcommand{\\mpkbyteshighone}{$%u$}\n", MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighone}{$%u$}\n", MKYBER_C1BYTES+MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighone}{$%u$}\n", MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteshightwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshightwo}{$%u$}\n", MKYBER_C1BYTES+2*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshightwo}{$%u$}\n", 2*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+2*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteshighX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighX}{$%u$}\n", MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighX}{$%u$}\n", 10*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+10*MKYBER_C2BYTES);
  
  printf("\\newcommand{\\mpkbyteshighC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighC}{$%u$}\n", MKYBER_C1BYTES+100*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighC}{$%u$}\n", 100*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+100*MKYBER_C2BYTES);

  printf("\\newcommand{\\mpkbyteshighM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES);
  printf("\\newcommand{\\mctbyteshighM}{$%u$}\n", MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
  printf("\\newcommand{\\mtotbyteshighM}{$%u$}\n", 1000*MKYBER_PUBLICKEYBYTES+MKYBER_C1BYTES+1000*MKYBER_C2BYTES);
#endif
}

int main(void)
{
  run_bench();
  return 0;
}
