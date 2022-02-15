#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "uniform.h"
#include "symmetric.h"
#include "randombytes.h"

#include "debug.h"

static void pack_pk(uint8_t r[MKYBER_INDCPA_PUBLICKEYBYTES],
                    const polyvec *pk, const uint8_t fakepkseed[KYBER_SYMBYTES])
{
  unsigned int i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[KYBER_POLYVECBYTES+i] = fakepkseed[i];
}

static void unpack_pk(polyvec *pk0, polyvec *pk1,
                      const uint8_t packedpk[MKYBER_INDCPA_PUBLICKEYBYTES])
{
  int i;
  polyvec_frombytes(pk0, packedpk);
  gen_polyvec(pk1, packedpk+KYBER_POLYVECBYTES);
  for(i=0;i<KYBER_K;i++)
    poly_nttunpack(&pk1->vec[i]);

  polyvec_add(pk1, pk1, pk0);
  polyvec_reduce(pk1); //XXX: Only for debugging purposes
}

static void pack_sk(uint8_t r[MKYBER_INDCPA_SECRETKEYBYTES], polyvec *sk, uint8_t b)
{
  polyvec_tobytes(r, sk);
  r[MKYBER_INDCPA_SECRETKEYBYTES-1] = b;
}

static void unpack_sk(polyvec *sk, uint8_t *b, const uint8_t packedsk[MKYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
  *b = packedsk[MKYBER_INDCPA_SECRETKEYBYTES-1];
}


/*************************************************
* Name:        indcpa_mkeypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length MKYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length MKYBER_INDCPA_SECRETKEYBYTES bytes)
*              - const uint8_t *publicseed: pointer to input public seed
*                             (of length KYBER_SYMBYTES)
**************************************************/
void indcpa_mkeypair(uint8_t pk[MKYBER_INDCPA_PUBLICKEYBYTES],
                     uint8_t sk[MKYBER_INDCPA_SECRETKEYBYTES],
                     const uint8_t publicseed[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t noiseseed[KYBER_SYMBYTES+1]; /* Additional byte to set random order of public keys */
  uint8_t fakepkseed[KYBER_SYMBYTES];
  polyvec a[KYBER_K], e, pkpv, fakepkpv, skpv;

  randombytes(noiseseed, KYBER_SYMBYTES+1);

  gen_a(a, publicseed);

#if KYBER_K == 2
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, e.vec+0, e.vec+1, noiseseed, 0, 1, 2, 3);
#elif KYBER_K == 3
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, e.vec+0, noiseseed, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+1, e.vec+2, pkpv.vec+0, pkpv.vec+1, noiseseed, 4, 5, 6, 7);
#elif KYBER_K == 4
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, skpv.vec+3, noiseseed,  0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+0, e.vec+1, e.vec+2, e.vec+3, noiseseed, 4, 5, 6, 7);
#endif


  polyvec_ntt(&skpv);
  polyvec_reduce(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }
 
  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  randombytes(fakepkseed, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(fakepkseed, fakepkseed, KYBER_SYMBYTES);
  gen_polyvec(&fakepkpv, fakepkseed);
  for(i=0;i<KYBER_K;i++)
    poly_nttunpack(&fakepkpv.vec[i]);

  polyvec_sub(&fakepkpv, &pkpv, &fakepkpv);
  polyvec_reduce(&fakepkpv);

  polyvec_cmov(&pkpv, &fakepkpv, noiseseed[KYBER_SYMBYTES]&1);

  pack_sk(sk, &skpv, noiseseed[KYBER_SYMBYTES]&1);
  pack_pk(pk, &pkpv, fakepkseed);
}

/*************************************************
* Name:        indcpa_enc_c1
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*              Generates only first ciphertext component
*
* Arguments:   - uint8_t *c1: pointer to output ciphertext component
*                             (of length MKYBER_C1BYTES bytes)
*              - uint8_t *fwd: pointer to (secret) information that is forwarded
*                              to enc_c2 (of length MKYBER_FWDBYTES)
*              - const uint8_t *seed: pointer to input public seed
*                                  (of length KYBER_SYMBYTES bytes)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc_c1(uint8_t c1[MKYBER_C1BYTES],
                   uint8_t fwd[MKYBER_FWDBYTES],
                   const uint8_t seed[KYBER_SYMBYTES],
                   const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  polyvec sp0, sp1, ep0, ep1, at[KYBER_K], b0, b1;
  uint8_t tbuf[KYBER_POLYVECCOMPRESSEDBYTES+2];

  gen_at(at, seed);

  #if KYBER_K == 2
  poly_getnoise_eta1_4x(sp0.vec+0, sp0.vec+1, sp1.vec+0, sp1.vec+1, coins,  0, 1, 2, 3);
  poly_getnoise_eta2_4x(ep0.vec+0, ep0.vec+1, ep1.vec+0, ep1.vec+1, coins,  4, 5, 6, 7);
  #elif KYBER_K == 3
  poly_getnoise_eta1_4x(sp0.vec+0, sp0.vec+1, sp0.vec+2, sp1.vec+0, coins,  0, 1, 2, 3);
  poly_getnoise_eta1122_4x(sp1.vec+1, sp1.vec+2, ep0.vec+0, ep0.vec+1, coins,  4, 5, 6, 7);
  poly_getnoise_eta1_4x(ep0.vec+2, ep1.vec+0, ep1.vec+1, ep1.vec+2, coins,  8, 9, 10, 11);
  #elif KYBER_K == 4
  poly_getnoise_eta1_4x(sp0.vec+0, sp0.vec+1, sp0.vec+2, sp0.vec+3, coins,  0, 1, 2, 3);
  poly_getnoise_eta1_4x(sp1.vec+0, sp1.vec+1, sp1.vec+2, sp1.vec+3, coins,  4, 5, 6, 7);
  poly_getnoise_eta2_4x(ep0.vec+0, ep0.vec+1, ep0.vec+2, ep0.vec+3, coins,  8, 9, 10, 11);
  poly_getnoise_eta2_4x(ep1.vec+0, ep1.vec+1, ep1.vec+2, ep1.vec+3, coins,  12, 13, 14, 15);
  #endif

  polyvec_ntt(&sp0);
  polyvec_ntt(&sp1);
  polyvec_reduce(&sp0);
  polyvec_reduce(&sp1);
 
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b0.vec[i], &at[i], &sp0);
 
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b1.vec[i], &at[i], &sp1);
 
  polyvec_invntt_tomont(&b0);
  polyvec_add(&b0, &b0, &ep0);
  polyvec_reduce(&b0);
  
  polyvec_compress(c1, &b0);

  polyvec_invntt_tomont(&b1);
  polyvec_add(&b1, &b1, &ep1);
  polyvec_reduce(&b1);

  polyvec_tobytes(fwd, &sp0);
  polyvec_tobytes(fwd+KYBER_POLYVECBYTES, &sp1);
  
  polyvec_compress(tbuf, &b1);
  memcpy(c1+KYBER_POLYVECCOMPRESSEDBYTES, tbuf, KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        indcpa_enc_c2
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*              Generates only second ciphertext component
*
* Arguments:   - uint8_t *c2: pointer to output ciphertext component
*                             (of length MKYBER_C2BYTES bytes)
*              - const uint8_t *m: pointer to input plaintext
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length MKYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const uint8_t *fwd: array of (secret) information forwarded
*                                    from indcpa_enc_c1
*              - const uint8_t *coins2: array of public-key dependent coins
**************************************************/
void indcpa_enc_c2(uint8_t c2[MKYBER_C2BYTES],
                   const uint8_t msg[KYBER_INDCPA_MSGBYTES],
                   const uint8_t pk[MKYBER_INDCPA_PUBLICKEYBYTES],
                   const uint8_t fwd[MKYBER_FWDBYTES],
                   const uint8_t coins2[KYBER_SYMBYTES])
{
  uint8_t nonce = 0;
  polyvec sp0, sp1, pkpv0, pkpv1;
  poly v0, v1, k, epp0, epp1;
  uint8_t tcoins2[KYBER_SYMBYTES];
  uint8_t flippks;

  polyvec_frombytes(&sp0, fwd);
  polyvec_frombytes(&sp1, fwd+KYBER_POLYVECBYTES);

  memcpy(tcoins2, coins2, KYBER_SYMBYTES);
  flippks = tcoins2[0] & 1;
  tcoins2[0] &= 0xfe;  /* Take one bit of coins to decide whether to flip or not */

  poly_getnoise_eta2(&epp0, tcoins2, nonce++); /* used to encaps to first pk */
  poly_getnoise_eta2(&epp1, tcoins2, nonce++); /* used to encaps to second pk */

  poly_frommsg(&k, msg);
  
  unpack_pk(&pkpv0, &pkpv1, pk);
  polyvec_cswap(&pkpv0, &pkpv1, flippks);

  /* Encaps to first pk */
  polyvec_basemul_acc_montgomery(&v0, &pkpv0, &sp0);

  poly_invntt_tomont(&v0);

  poly_add(&v0, &v0, &epp0);
  poly_add(&v0, &v0, &k);
  poly_reduce(&v0);

  poly_compress(c2, &v0);
  
  /* Encaps to second pk */
  polyvec_basemul_acc_montgomery(&v1, &pkpv1, &sp1);

  poly_invntt_tomont(&v1);

  poly_add(&v1, &v1, &epp1);
  poly_add(&v1, &v1, &k);
  poly_reduce(&v1);

  poly_compress(c2+KYBER_POLYCOMPRESSEDBYTES, &v1);
  c2[MKYBER_C2BYTES-1] = flippks;
}


/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c1: pointer to input first ciphertext component
*                                   (of length MKYBER_C1BYTES)
*              - const uint8_t *c2: pointer to input second ciphertext component
*                                   (of length MKYBER_C2BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length MKYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c1[MKYBER_C1BYTES],
                const uint8_t c2[MKYBER_C2BYTES],
                const uint8_t sk[MKYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b0, b1, skpv;
  poly v0, v1, mp;
  uint8_t bb;

  uint8_t tbuf[MKYBER_C1BYTES+12];
  memcpy(tbuf,c1+KYBER_POLYVECCOMPRESSEDBYTES,KYBER_POLYVECCOMPRESSEDBYTES);

  polyvec_decompress(&b0, c1);
  polyvec_decompress(&b1, tbuf);
  polyvec_cmov(&b0, &b1, sk[MKYBER_INDCPA_SECRETKEYBYTES-1]^c2[MKYBER_C2BYTES-1]);

  poly_decompress(&v0, c2);
  poly_decompress(&v1, c2+KYBER_POLYCOMPRESSEDBYTES);

  unpack_sk(&skpv, &bb, sk);
  poly_cmov(&v0, &v1, bb^c2[MKYBER_C2BYTES-1]);

  polyvec_ntt(&b0);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b0);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v0, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
