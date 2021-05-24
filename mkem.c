#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "mkem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        crypto_mkem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of MKYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of MKYBER_SECRETKEYBYTES bytes)
*              - const uint8_t *seed: pointer to the input public seed, which
*                needs to be of length KYBER_SYMBYTES and generated beforehand
*
* Returns 0 (success)
**************************************************/
int crypto_mkem_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  size_t i;
  indcpa_mkeypair(pk, sk, seed);

  /* Copy public key into secret key */
  sk += MKYBER_INDCPA_SECRETKEYBYTES;
  for(i=0;i<MKYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i] = pk[i];

  /* Copy seed into secret key */
  sk += MKYBER_INDCPA_PUBLICKEYBYTES;
  for(i=0;i<KYBER_SYMBYTES;i++)
    sk[i] = seed[i];

  return 0;
}

/*************************************************
* Name:        crypto_mkem_enc_c1
*
* Description: Generates first ciphertext component and shared key
*
* Arguments:   - uint8_t *c1: pointer to output first ciphertext component
*                (an already allocated array of MKYBER_C1BYTES bytes)
*              - uint8_t *ss: pointer to output shared key
*                (an already allocated array of MKYBER_SYMBYTES bytes)
*              - const uint8_t *seed: pointer to the input public seed, which
*                needs to be of length KYBER_SYMBYTES and generated beforehand
*              - const uint8_t *r: pointer to input random coins;
*                needs to be of length KYBER_SYMBYTES and generated beforehand
*
* Returns 0 (success)
**************************************************/
int crypto_mkem_enc_c1(uint8_t *c1,
                       uint8_t *ss,
                       const uint8_t *seed,
                       const uint8_t *r)
{
  uint8_t buf[KYBER_SYMBYTES];
  uint8_t kr[2*KYBER_SYMBYTES];
  size_t i;

  /* Don't release system RNG output */
  hash_h(buf, r, KYBER_SYMBYTES);
  /* Hash buf to shared key and coins */
  hash_g(kr, buf, KYBER_SYMBYTES);
  for(i=0;i<KYBER_SYMBYTES;i++) ss[i] = kr[i];

  indcpa_enc_c1(c1, seed, kr+KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_mkem_enc_c2
*
* Description: Generates second ciphertext component
*
* Arguments:   - uint8_t *c2: pointer to output second ciphertext component
*                (an already allocated array of MKYBER_C2BYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an array of MKYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *r: pointer to input random coins;
*                needs to be of length KYBER_SYMBYTES and generated beforehand
*
* Returns 0 (success)
**************************************************/
int crypto_mkem_enc_c2(uint8_t *c2,
                       const uint8_t *pk,
                       const uint8_t *r)
{
  uint8_t buf[KYBER_SYMBYTES];
  uint8_t kr[2*KYBER_SYMBYTES];

  /* Don't release system RNG output */
  hash_h(buf, r, KYBER_SYMBYTES);
  /* Hash buf to shared key and coins */
  hash_g(kr, buf, KYBER_SYMBYTES);

  indcpa_enc_c2(c2, buf, pk, kr+KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_mkem_enc
*
* Description: Generates a batch of ciphertexts all with the same first component c1
*
* Arguments:   - uint8_t *c1: pointer to output first ciphertext component
*                (an already allocated array of MKYBER_C1BYTES bytes)
*              - uint8_t *c2: pointer to output second ciphertext components
*                (an array of num_key pointers, each to an allocated array of MKYBER_C2BYTES bytes)
*              - uint8_t *ss: pointer to output shared key
*                (an already allocated array of MKYBER_SYMBYTES bytes)
*              - const uint8_t *seed: pointer to the input public seed, which
*                needs to be of length KYBER_SYMBYTES and generated beforehand
*              - size_t num_keys: input batch size
*              - uint8_t **pk: array of num_keys pointers to public keys, 
*                each pointing to an array of MKYBER_PUBLICKEYBYTES bytes
*
* Returns 0 (success)
**************************************************/
int crypto_mkem_enc(uint8_t *c1,
                    uint8_t **c2s,
                    uint8_t *ss,
                    const uint8_t *seed,
                    size_t num_keys,
                    uint8_t *const* pk)
{
  uint8_t buf[KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  size_t i;

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Hash buf to shared key and coins */
  hash_g(kr, buf, KYBER_SYMBYTES);
  for(i=0;i<KYBER_SYMBYTES;i++) ss[i] = kr[i];
  
  indcpa_enc_c1(c1, seed, kr+KYBER_SYMBYTES);

  for(i=0;i<num_keys;i++)
  {
    indcpa_enc_c2(c2s[i], buf, pk[i], kr+KYBER_SYMBYTES);
  }
  return 0;
}

/*************************************************
* Name:        crypto_mkem_enc
*
* Description: Generates a batch of ciphertexts all with the same first component c1
*
* Arguments:   - uint8_t *ss: pointer to output shared key
*                (an already allocated array of MKYBER_SYMBYTES bytes)
*              - const uint8_t *c1: pointer to input first ciphertext component
*                (an array of MKYBER_C1BYTES bytes)
*              - const uint8_t *c2: pointer to input second ciphertext component
*                (an array of MKYBER_C2BYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of MKYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_mkem_dec(uint8_t *ss,
                    const uint8_t *c1,
                    const uint8_t *c2,
                    const uint8_t *sk)
{
  int fail;
  uint8_t buf[KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp1[MKYBER_C1BYTES];
  uint8_t cmp2[MKYBER_C2BYTES];
  const uint8_t *pk   = sk+MKYBER_INDCPA_SECRETKEYBYTES;
  const uint8_t *seed = pk+MKYBER_INDCPA_PUBLICKEYBYTES;

  indcpa_dec(buf, c1, c2, sk);

  hash_g(kr, buf, KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc_c1(cmp1, seed, kr+KYBER_SYMBYTES);
  indcpa_enc_c2(cmp2, buf, pk, kr+KYBER_SYMBYTES);

  fail  = verify(c1, cmp1, MKYBER_C1BYTES);
  fail |= verify(c2, cmp2, MKYBER_C2BYTES);

  /* Write random bytes to buf */
  randombytes(ss, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(ss, ss, KYBER_SYMBYTES);

  /* Overwrite randomness with shared key if re-encryption was successful */
  cmov(ss, kr, KYBER_SYMBYTES, 1-fail);

  return 0;
}
