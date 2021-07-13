#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "uniform.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"

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
  polyvec_frombytes(pk0, packedpk);
  gen_polyvec(pk1, packedpk+KYBER_POLYVECBYTES);
  polyvec_add(pk1, pk1, pk0);
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
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, fakepkpv, skpv;

  randombytes(noiseseed+1, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  randombytes(fakepkseed, KYBER_SYMBYTES);
  gen_polyvec(&fakepkpv, fakepkseed);

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
*              - const uint8_t *seed: pointer to input public seed
*                                  (of length KYBER_SYMBYTES bytes)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc_c1(uint8_t c1[MKYBER_C1BYTES],
                   const uint8_t seed[KYBER_SYMBYTES],
                   const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t nonce = 0;
  polyvec sp0, sp1, ep0, ep1, at[KYBER_K], b0, b1;

  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp0.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp1.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep0.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep1.vec+i, coins, nonce++);

  polyvec_ntt(&sp0);
  polyvec_ntt(&sp1);

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
  
  polyvec_compress(c1+KYBER_POLYVECCOMPRESSEDBYTES, &b1);
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
**************************************************/
void indcpa_enc_c2(uint8_t c2[MKYBER_C2BYTES],
                   const uint8_t msg[KYBER_INDCPA_MSGBYTES],
                   const uint8_t pk[MKYBER_INDCPA_PUBLICKEYBYTES])
{
  unsigned int i;
  uint8_t nonce = 0;
  polyvec sp0, sp1, pkpv0, pkpv1;
  poly v0, v1, k, epp0, epp1;
  uint8_t coins[KYBER_SYMBYTES];
  uint8_t buf[MKYBER_INDCPA_PUBLICKEYBYTES+KYBER_INDCPA_MSGBYTES];

  /* Recompute "ephemeral secrets" s0 and s1 and transform to NTT domain */
  /* XXX: Could change API to avoid doing this both in indcpa_enc_c1 and here */
  hash_h(coins, msg, KYBER_SYMBYTES);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp0.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp1.vec+i, coins, nonce++);
  
  polyvec_ntt(&sp0);
  polyvec_ntt(&sp1);

  /* Compute public-key dependent coins */
  /* XXX: Think through if this derivation of epp0 and epp1 is OK */
  memcpy(buf,pk,MKYBER_INDCPA_PUBLICKEYBYTES);
  memcpy(buf+MKYBER_INDCPA_PUBLICKEYBYTES,msg,KYBER_INDCPA_MSGBYTES);
  hash_h(coins, buf, MKYBER_INDCPA_PUBLICKEYBYTES+KYBER_INDCPA_MSGBYTES);
  poly_getnoise_eta2(&epp0, coins, nonce++); /* used to encaps to first pk */
  poly_getnoise_eta2(&epp1, coins, nonce++); /* used to encaps to second pk */

  poly_frommsg(&k, msg);
  
  unpack_pk(&pkpv0, &pkpv1, pk);

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
*                                  (of length MMKYBER_C1BYTES)
*              - const uint8_t *c2: pointer to input second ciphertext component
*                                  (of length MKYBER_C2BYTES)
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

  polyvec_decompress(&b0, c1);
  polyvec_decompress(&b1, c1+KYBER_POLYVECCOMPRESSEDBYTES);
  polyvec_cmov(&b0, &b1, sk[MKYBER_INDCPA_SECRETKEYBYTES-1]);

  poly_decompress(&v0, c2);
  poly_decompress(&v1, c2+KYBER_POLYCOMPRESSEDBYTES);

  unpack_sk(&skpv, &bb, sk);
  poly_cmov(&v0, &v1, bb);

  polyvec_ntt(&b0);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b0);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v0, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
