#include "uniform.h"
#include "symmetric.h"

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
#define GEN_POLY_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_POLY_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_POLY_NBLOCKS, &state);
      buflen = GEN_POLY_NBLOCKS*XOF_BLOCKBYTES;
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
* Name:        gen_polyvec
*
* Description: Deterministically generate polyvec a from a seed.  Entries 
*              of the polyvec are polynomials that look uniformly random. 
*              Performs rejection sampling on output of a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput polyvec
*              - const uint8_t *seed: pointer to input seed
**************************************************/
void gen_polyvec(polyvec *a, const uint8_t seed[KYBER_SYMBYTES])
{
  unsigned int ctr, i, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_POLY_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    xof_absorb(&state, seed, 0, i);

    xof_squeezeblocks(buf, GEN_POLY_NBLOCKS, &state);
    buflen = GEN_POLY_NBLOCKS*XOF_BLOCKBYTES;
    ctr = rej_uniform(a->vec[i].coeffs, KYBER_N, buf, buflen);

    while(ctr < KYBER_N) {
      off = buflen % 3;
      for(k = 0; k < off; k++)
        buf[k] = buf[buflen - off + k];
      xof_squeezeblocks(buf + off, 1, &state);
      buflen = off + XOF_BLOCKBYTES;
      ctr += rej_uniform(a->vec[i].coeffs + ctr, KYBER_N - ctr, buf, buflen);
    }
  }
}
