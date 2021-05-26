#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"

static void pack_pk(uint8_t r[MKYBER_INDCPA_PUBLICKEYBYTES],
                    const polyvec *pk)
{
  polyvec_tobytes(r, pk);
}

static void unpack_pk(polyvec *pk,
                      const uint8_t packedpk[MKYBER_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
}

static void pack_sk(uint8_t r[MKYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[MKYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
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
  uint8_t noiseseed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  randombytes(noiseseed, KYBER_SYMBYTES);

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

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv);
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
  polyvec sp, ep, at[KYBER_K], b;

  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
  
  polyvec_invntt_tomont(&b);
  polyvec_add(&b, &b, &ep);
  polyvec_reduce(&b);
  
  polyvec_compress(c1, &b);

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
  polyvec sp, pkpv;
  poly v, k, epp;
  uint8_t coins[KYBER_SYMBYTES];
  uint8_t buf[MKYBER_INDCPA_PUBLICKEYBYTES+KYBER_INDCPA_MSGBYTES];

  /* Recompute "ephemeral secret" s and transform to NTT domain */
  /* XXX: Could change API to avoid doing this both in indcpa_enc_c1 and here */
  hash_h(coins, msg, KYBER_SYMBYTES);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  polyvec_ntt(&sp);

  /* Compute public-key dependent coins */
  memcpy(buf,pk,MKYBER_INDCPA_PUBLICKEYBYTES);
  memcpy(buf+MKYBER_INDCPA_PUBLICKEYBYTES,msg,KYBER_INDCPA_MSGBYTES);
  hash_h(coins, buf, MKYBER_INDCPA_PUBLICKEYBYTES+KYBER_INDCPA_MSGBYTES);
  poly_getnoise_eta2(&epp, coins, nonce);

  unpack_pk(&pkpv, pk);
  poly_frommsg(&k, msg);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  poly_invntt_tomont(&v);

  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  poly_reduce(&v);

  poly_compress(c2, &v);
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
  polyvec b, skpv;
  poly v, mp;

  polyvec_decompress(&b, c1);
  poly_decompress(&v, c2);

  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
