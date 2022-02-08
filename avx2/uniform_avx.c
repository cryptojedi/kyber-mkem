#include "uniform.h"
#include "symmetric.h"

#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "params.h"
#include "consts.h"

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output array
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
  while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
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

#ifndef BMI
static const uint8_t idx[256][8] = {
  {-1, -1, -1, -1, -1, -1, -1, -1},
  { 0, -1, -1, -1, -1, -1, -1, -1},
  { 2, -1, -1, -1, -1, -1, -1, -1},
  { 0,  2, -1, -1, -1, -1, -1, -1},
  { 4, -1, -1, -1, -1, -1, -1, -1},
  { 0,  4, -1, -1, -1, -1, -1, -1},
  { 2,  4, -1, -1, -1, -1, -1, -1},
  { 0,  2,  4, -1, -1, -1, -1, -1},
  { 6, -1, -1, -1, -1, -1, -1, -1},
  { 0,  6, -1, -1, -1, -1, -1, -1},
  { 2,  6, -1, -1, -1, -1, -1, -1},
  { 0,  2,  6, -1, -1, -1, -1, -1},
  { 4,  6, -1, -1, -1, -1, -1, -1},
  { 0,  4,  6, -1, -1, -1, -1, -1},
  { 2,  4,  6, -1, -1, -1, -1, -1},
  { 0,  2,  4,  6, -1, -1, -1, -1},
  { 8, -1, -1, -1, -1, -1, -1, -1},
  { 0,  8, -1, -1, -1, -1, -1, -1},
  { 2,  8, -1, -1, -1, -1, -1, -1},
  { 0,  2,  8, -1, -1, -1, -1, -1},
  { 4,  8, -1, -1, -1, -1, -1, -1},
  { 0,  4,  8, -1, -1, -1, -1, -1},
  { 2,  4,  8, -1, -1, -1, -1, -1},
  { 0,  2,  4,  8, -1, -1, -1, -1},
  { 6,  8, -1, -1, -1, -1, -1, -1},
  { 0,  6,  8, -1, -1, -1, -1, -1},
  { 2,  6,  8, -1, -1, -1, -1, -1},
  { 0,  2,  6,  8, -1, -1, -1, -1},
  { 4,  6,  8, -1, -1, -1, -1, -1},
  { 0,  4,  6,  8, -1, -1, -1, -1},
  { 2,  4,  6,  8, -1, -1, -1, -1},
  { 0,  2,  4,  6,  8, -1, -1, -1},
  {10, -1, -1, -1, -1, -1, -1, -1},
  { 0, 10, -1, -1, -1, -1, -1, -1},
  { 2, 10, -1, -1, -1, -1, -1, -1},
  { 0,  2, 10, -1, -1, -1, -1, -1},
  { 4, 10, -1, -1, -1, -1, -1, -1},
  { 0,  4, 10, -1, -1, -1, -1, -1},
  { 2,  4, 10, -1, -1, -1, -1, -1},
  { 0,  2,  4, 10, -1, -1, -1, -1},
  { 6, 10, -1, -1, -1, -1, -1, -1},
  { 0,  6, 10, -1, -1, -1, -1, -1},
  { 2,  6, 10, -1, -1, -1, -1, -1},
  { 0,  2,  6, 10, -1, -1, -1, -1},
  { 4,  6, 10, -1, -1, -1, -1, -1},
  { 0,  4,  6, 10, -1, -1, -1, -1},
  { 2,  4,  6, 10, -1, -1, -1, -1},
  { 0,  2,  4,  6, 10, -1, -1, -1},
  { 8, 10, -1, -1, -1, -1, -1, -1},
  { 0,  8, 10, -1, -1, -1, -1, -1},
  { 2,  8, 10, -1, -1, -1, -1, -1},
  { 0,  2,  8, 10, -1, -1, -1, -1},
  { 4,  8, 10, -1, -1, -1, -1, -1},
  { 0,  4,  8, 10, -1, -1, -1, -1},
  { 2,  4,  8, 10, -1, -1, -1, -1},
  { 0,  2,  4,  8, 10, -1, -1, -1},
  { 6,  8, 10, -1, -1, -1, -1, -1},
  { 0,  6,  8, 10, -1, -1, -1, -1},
  { 2,  6,  8, 10, -1, -1, -1, -1},
  { 0,  2,  6,  8, 10, -1, -1, -1},
  { 4,  6,  8, 10, -1, -1, -1, -1},
  { 0,  4,  6,  8, 10, -1, -1, -1},
  { 2,  4,  6,  8, 10, -1, -1, -1},
  { 0,  2,  4,  6,  8, 10, -1, -1},
  {12, -1, -1, -1, -1, -1, -1, -1},
  { 0, 12, -1, -1, -1, -1, -1, -1},
  { 2, 12, -1, -1, -1, -1, -1, -1},
  { 0,  2, 12, -1, -1, -1, -1, -1},
  { 4, 12, -1, -1, -1, -1, -1, -1},
  { 0,  4, 12, -1, -1, -1, -1, -1},
  { 2,  4, 12, -1, -1, -1, -1, -1},
  { 0,  2,  4, 12, -1, -1, -1, -1},
  { 6, 12, -1, -1, -1, -1, -1, -1},
  { 0,  6, 12, -1, -1, -1, -1, -1},
  { 2,  6, 12, -1, -1, -1, -1, -1},
  { 0,  2,  6, 12, -1, -1, -1, -1},
  { 4,  6, 12, -1, -1, -1, -1, -1},
  { 0,  4,  6, 12, -1, -1, -1, -1},
  { 2,  4,  6, 12, -1, -1, -1, -1},
  { 0,  2,  4,  6, 12, -1, -1, -1},
  { 8, 12, -1, -1, -1, -1, -1, -1},
  { 0,  8, 12, -1, -1, -1, -1, -1},
  { 2,  8, 12, -1, -1, -1, -1, -1},
  { 0,  2,  8, 12, -1, -1, -1, -1},
  { 4,  8, 12, -1, -1, -1, -1, -1},
  { 0,  4,  8, 12, -1, -1, -1, -1},
  { 2,  4,  8, 12, -1, -1, -1, -1},
  { 0,  2,  4,  8, 12, -1, -1, -1},
  { 6,  8, 12, -1, -1, -1, -1, -1},
  { 0,  6,  8, 12, -1, -1, -1, -1},
  { 2,  6,  8, 12, -1, -1, -1, -1},
  { 0,  2,  6,  8, 12, -1, -1, -1},
  { 4,  6,  8, 12, -1, -1, -1, -1},
  { 0,  4,  6,  8, 12, -1, -1, -1},
  { 2,  4,  6,  8, 12, -1, -1, -1},
  { 0,  2,  4,  6,  8, 12, -1, -1},
  {10, 12, -1, -1, -1, -1, -1, -1},
  { 0, 10, 12, -1, -1, -1, -1, -1},
  { 2, 10, 12, -1, -1, -1, -1, -1},
  { 0,  2, 10, 12, -1, -1, -1, -1},
  { 4, 10, 12, -1, -1, -1, -1, -1},
  { 0,  4, 10, 12, -1, -1, -1, -1},
  { 2,  4, 10, 12, -1, -1, -1, -1},
  { 0,  2,  4, 10, 12, -1, -1, -1},
  { 6, 10, 12, -1, -1, -1, -1, -1},
  { 0,  6, 10, 12, -1, -1, -1, -1},
  { 2,  6, 10, 12, -1, -1, -1, -1},
  { 0,  2,  6, 10, 12, -1, -1, -1},
  { 4,  6, 10, 12, -1, -1, -1, -1},
  { 0,  4,  6, 10, 12, -1, -1, -1},
  { 2,  4,  6, 10, 12, -1, -1, -1},
  { 0,  2,  4,  6, 10, 12, -1, -1},
  { 8, 10, 12, -1, -1, -1, -1, -1},
  { 0,  8, 10, 12, -1, -1, -1, -1},
  { 2,  8, 10, 12, -1, -1, -1, -1},
  { 0,  2,  8, 10, 12, -1, -1, -1},
  { 4,  8, 10, 12, -1, -1, -1, -1},
  { 0,  4,  8, 10, 12, -1, -1, -1},
  { 2,  4,  8, 10, 12, -1, -1, -1},
  { 0,  2,  4,  8, 10, 12, -1, -1},
  { 6,  8, 10, 12, -1, -1, -1, -1},
  { 0,  6,  8, 10, 12, -1, -1, -1},
  { 2,  6,  8, 10, 12, -1, -1, -1},
  { 0,  2,  6,  8, 10, 12, -1, -1},
  { 4,  6,  8, 10, 12, -1, -1, -1},
  { 0,  4,  6,  8, 10, 12, -1, -1},
  { 2,  4,  6,  8, 10, 12, -1, -1},
  { 0,  2,  4,  6,  8, 10, 12, -1},
  {14, -1, -1, -1, -1, -1, -1, -1},
  { 0, 14, -1, -1, -1, -1, -1, -1},
  { 2, 14, -1, -1, -1, -1, -1, -1},
  { 0,  2, 14, -1, -1, -1, -1, -1},
  { 4, 14, -1, -1, -1, -1, -1, -1},
  { 0,  4, 14, -1, -1, -1, -1, -1},
  { 2,  4, 14, -1, -1, -1, -1, -1},
  { 0,  2,  4, 14, -1, -1, -1, -1},
  { 6, 14, -1, -1, -1, -1, -1, -1},
  { 0,  6, 14, -1, -1, -1, -1, -1},
  { 2,  6, 14, -1, -1, -1, -1, -1},
  { 0,  2,  6, 14, -1, -1, -1, -1},
  { 4,  6, 14, -1, -1, -1, -1, -1},
  { 0,  4,  6, 14, -1, -1, -1, -1},
  { 2,  4,  6, 14, -1, -1, -1, -1},
  { 0,  2,  4,  6, 14, -1, -1, -1},
  { 8, 14, -1, -1, -1, -1, -1, -1},
  { 0,  8, 14, -1, -1, -1, -1, -1},
  { 2,  8, 14, -1, -1, -1, -1, -1},
  { 0,  2,  8, 14, -1, -1, -1, -1},
  { 4,  8, 14, -1, -1, -1, -1, -1},
  { 0,  4,  8, 14, -1, -1, -1, -1},
  { 2,  4,  8, 14, -1, -1, -1, -1},
  { 0,  2,  4,  8, 14, -1, -1, -1},
  { 6,  8, 14, -1, -1, -1, -1, -1},
  { 0,  6,  8, 14, -1, -1, -1, -1},
  { 2,  6,  8, 14, -1, -1, -1, -1},
  { 0,  2,  6,  8, 14, -1, -1, -1},
  { 4,  6,  8, 14, -1, -1, -1, -1},
  { 0,  4,  6,  8, 14, -1, -1, -1},
  { 2,  4,  6,  8, 14, -1, -1, -1},
  { 0,  2,  4,  6,  8, 14, -1, -1},
  {10, 14, -1, -1, -1, -1, -1, -1},
  { 0, 10, 14, -1, -1, -1, -1, -1},
  { 2, 10, 14, -1, -1, -1, -1, -1},
  { 0,  2, 10, 14, -1, -1, -1, -1},
  { 4, 10, 14, -1, -1, -1, -1, -1},
  { 0,  4, 10, 14, -1, -1, -1, -1},
  { 2,  4, 10, 14, -1, -1, -1, -1},
  { 0,  2,  4, 10, 14, -1, -1, -1},
  { 6, 10, 14, -1, -1, -1, -1, -1},
  { 0,  6, 10, 14, -1, -1, -1, -1},
  { 2,  6, 10, 14, -1, -1, -1, -1},
  { 0,  2,  6, 10, 14, -1, -1, -1},
  { 4,  6, 10, 14, -1, -1, -1, -1},
  { 0,  4,  6, 10, 14, -1, -1, -1},
  { 2,  4,  6, 10, 14, -1, -1, -1},
  { 0,  2,  4,  6, 10, 14, -1, -1},
  { 8, 10, 14, -1, -1, -1, -1, -1},
  { 0,  8, 10, 14, -1, -1, -1, -1},
  { 2,  8, 10, 14, -1, -1, -1, -1},
  { 0,  2,  8, 10, 14, -1, -1, -1},
  { 4,  8, 10, 14, -1, -1, -1, -1},
  { 0,  4,  8, 10, 14, -1, -1, -1},
  { 2,  4,  8, 10, 14, -1, -1, -1},
  { 0,  2,  4,  8, 10, 14, -1, -1},
  { 6,  8, 10, 14, -1, -1, -1, -1},
  { 0,  6,  8, 10, 14, -1, -1, -1},
  { 2,  6,  8, 10, 14, -1, -1, -1},
  { 0,  2,  6,  8, 10, 14, -1, -1},
  { 4,  6,  8, 10, 14, -1, -1, -1},
  { 0,  4,  6,  8, 10, 14, -1, -1},
  { 2,  4,  6,  8, 10, 14, -1, -1},
  { 0,  2,  4,  6,  8, 10, 14, -1},
  {12, 14, -1, -1, -1, -1, -1, -1},
  { 0, 12, 14, -1, -1, -1, -1, -1},
  { 2, 12, 14, -1, -1, -1, -1, -1},
  { 0,  2, 12, 14, -1, -1, -1, -1},
  { 4, 12, 14, -1, -1, -1, -1, -1},
  { 0,  4, 12, 14, -1, -1, -1, -1},
  { 2,  4, 12, 14, -1, -1, -1, -1},
  { 0,  2,  4, 12, 14, -1, -1, -1},
  { 6, 12, 14, -1, -1, -1, -1, -1},
  { 0,  6, 12, 14, -1, -1, -1, -1},
  { 2,  6, 12, 14, -1, -1, -1, -1},
  { 0,  2,  6, 12, 14, -1, -1, -1},
  { 4,  6, 12, 14, -1, -1, -1, -1},
  { 0,  4,  6, 12, 14, -1, -1, -1},
  { 2,  4,  6, 12, 14, -1, -1, -1},
  { 0,  2,  4,  6, 12, 14, -1, -1},
  { 8, 12, 14, -1, -1, -1, -1, -1},
  { 0,  8, 12, 14, -1, -1, -1, -1},
  { 2,  8, 12, 14, -1, -1, -1, -1},
  { 0,  2,  8, 12, 14, -1, -1, -1},
  { 4,  8, 12, 14, -1, -1, -1, -1},
  { 0,  4,  8, 12, 14, -1, -1, -1},
  { 2,  4,  8, 12, 14, -1, -1, -1},
  { 0,  2,  4,  8, 12, 14, -1, -1},
  { 6,  8, 12, 14, -1, -1, -1, -1},
  { 0,  6,  8, 12, 14, -1, -1, -1},
  { 2,  6,  8, 12, 14, -1, -1, -1},
  { 0,  2,  6,  8, 12, 14, -1, -1},
  { 4,  6,  8, 12, 14, -1, -1, -1},
  { 0,  4,  6,  8, 12, 14, -1, -1},
  { 2,  4,  6,  8, 12, 14, -1, -1},
  { 0,  2,  4,  6,  8, 12, 14, -1},
  {10, 12, 14, -1, -1, -1, -1, -1},
  { 0, 10, 12, 14, -1, -1, -1, -1},
  { 2, 10, 12, 14, -1, -1, -1, -1},
  { 0,  2, 10, 12, 14, -1, -1, -1},
  { 4, 10, 12, 14, -1, -1, -1, -1},
  { 0,  4, 10, 12, 14, -1, -1, -1},
  { 2,  4, 10, 12, 14, -1, -1, -1},
  { 0,  2,  4, 10, 12, 14, -1, -1},
  { 6, 10, 12, 14, -1, -1, -1, -1},
  { 0,  6, 10, 12, 14, -1, -1, -1},
  { 2,  6, 10, 12, 14, -1, -1, -1},
  { 0,  2,  6, 10, 12, 14, -1, -1},
  { 4,  6, 10, 12, 14, -1, -1, -1},
  { 0,  4,  6, 10, 12, 14, -1, -1},
  { 2,  4,  6, 10, 12, 14, -1, -1},
  { 0,  2,  4,  6, 10, 12, 14, -1},
  { 8, 10, 12, 14, -1, -1, -1, -1},
  { 0,  8, 10, 12, 14, -1, -1, -1},
  { 2,  8, 10, 12, 14, -1, -1, -1},
  { 0,  2,  8, 10, 12, 14, -1, -1},
  { 4,  8, 10, 12, 14, -1, -1, -1},
  { 0,  4,  8, 10, 12, 14, -1, -1},
  { 2,  4,  8, 10, 12, 14, -1, -1},
  { 0,  2,  4,  8, 10, 12, 14, -1},
  { 6,  8, 10, 12, 14, -1, -1, -1},
  { 0,  6,  8, 10, 12, 14, -1, -1},
  { 2,  6,  8, 10, 12, 14, -1, -1},
  { 0,  2,  6,  8, 10, 12, 14, -1},
  { 4,  6,  8, 10, 12, 14, -1, -1},
  { 0,  4,  6,  8, 10, 12, 14, -1},
  { 2,  4,  6,  8, 10, 12, 14, -1},
  { 0,  2,  4,  6,  8, 10, 12, 14}
};
#endif

#define _mm256_cmpge_epu16(a, b) _mm256_cmpeq_epi16(_mm256_max_epu16(a, b), a)
#define _mm_cmpge_epu16(a, b) _mm_cmpeq_epi16(_mm_max_epu16(a, b), a)

#define REJ_UNIFORM_AVX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS*XOF_BLOCKBYTES)

static unsigned int rej_uniform_avx(int16_t * restrict r, const uint8_t *buf)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;
  uint32_t good;
#ifdef BMI
  uint64_t idx0, idx1, idx2, idx3;
#endif
  const __m256i bound  = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i ones   = _mm256_set1_epi8(1);
  const __m256i mask  = _mm256_set1_epi16(0xFFF);
  const __m256i idx8  = _mm256_set_epi8(15,14,14,13,12,11,11,10,
                                         9, 8, 8, 7, 6, 5, 5, 4,
                                        11,10,10, 9, 8, 7, 7, 6,
                                         5, 4, 4, 3, 2, 1, 1, 0);
  __m256i f0, f1, g0, g1, g2, g3;
  __m128i f, t, pilo, pihi;

  ctr = pos = 0;
  while(ctr <= KYBER_N - 32 && pos <= REJ_UNIFORM_AVX_BUFLEN - 48) {
    f0 = _mm256_loadu_si256((__m256i *)&buf[pos]);
    f1 = _mm256_loadu_si256((__m256i *)&buf[pos+24]);
    f0 = _mm256_permute4x64_epi64(f0, 0x94);
    f1 = _mm256_permute4x64_epi64(f1, 0x94);
    f0 = _mm256_shuffle_epi8(f0, idx8);
    f1 = _mm256_shuffle_epi8(f1, idx8);
    g0 = _mm256_srli_epi16(f0, 4);
    g1 = _mm256_srli_epi16(f1, 4);
    f0 = _mm256_blend_epi16(f0, g0, 0xAA);
    f1 = _mm256_blend_epi16(f1, g1, 0xAA);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    pos += 48;

    g0 = _mm256_cmpgt_epi16(bound, f0);
    g1 = _mm256_cmpgt_epi16(bound, f1);

    g0 = _mm256_packs_epi16(g0, g1);
    good = _mm256_movemask_epi8(g0);

#ifdef BMI
    idx0 = _pdep_u64(good >>  0, 0x0101010101010101);
    idx1 = _pdep_u64(good >>  8, 0x0101010101010101);
    idx2 = _pdep_u64(good >> 16, 0x0101010101010101);
    idx3 = _pdep_u64(good >> 24, 0x0101010101010101);
    idx0 = (idx0 << 8) - idx0;
    idx0  = _pext_u64(0x0E0C0A0806040200, idx0);
    idx1 = (idx1 << 8) - idx1;
    idx1  = _pext_u64(0x0E0C0A0806040200, idx1);
    idx2 = (idx2 << 8) - idx2;
    idx2  = _pext_u64(0x0E0C0A0806040200, idx2);
    idx3 = (idx3 << 8) - idx3;
    idx3  = _pext_u64(0x0E0C0A0806040200, idx3);

    g0 = _mm256_castsi128_si256(_mm_cvtsi64_si128(idx0));
    g1 = _mm256_castsi128_si256(_mm_cvtsi64_si128(idx1));
    g0 = _mm256_inserti128_si256(g0, _mm_cvtsi64_si128(idx2), 1);
    g1 = _mm256_inserti128_si256(g1, _mm_cvtsi64_si128(idx3), 1);
#else
    g0 = _mm256_castsi128_si256(_mm_loadl_epi64((__m128i *)&idx[(good >>  0) & 0xFF]));
    g1 = _mm256_castsi128_si256(_mm_loadl_epi64((__m128i *)&idx[(good >>  8) & 0xFF]));
    g0 = _mm256_inserti128_si256(g0, _mm_loadl_epi64((__m128i *)&idx[(good >> 16) & 0xFF]), 1);
    g1 = _mm256_inserti128_si256(g1, _mm_loadl_epi64((__m128i *)&idx[(good >> 24) & 0xFF]), 1);
#endif

    g2 = _mm256_add_epi8(g0, ones);
    g3 = _mm256_add_epi8(g1, ones);
    g0 = _mm256_unpacklo_epi8(g0, g2);
    g1 = _mm256_unpacklo_epi8(g1, g3);

    f0 = _mm256_shuffle_epi8(f0, g0);
    f1 = _mm256_shuffle_epi8(f1, g1);

    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_castsi256_si128(f0));
    ctr += _mm_popcnt_u32((good >>  0) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_extracti128_si256(f0, 1));
    ctr += _mm_popcnt_u32((good >> 16) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_castsi256_si128(f1));
    ctr += _mm_popcnt_u32((good >>  8) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_extracti128_si256(f1, 1));
    ctr += _mm_popcnt_u32((good >> 24) & 0xFF);
  }

  while(ctr <= KYBER_N - 8 && pos <= REJ_UNIFORM_AVX_BUFLEN - 12) {
    f = _mm_loadu_si128((__m128i *)&buf[pos]);
    f = _mm_shuffle_epi8(f, _mm256_castsi256_si128(idx8));
    t = _mm_srli_epi16(f, 4);
    f = _mm_blend_epi16(f, t, 0xAA);
    f = _mm_and_si128(f, _mm256_castsi256_si128(mask));
    pos += 12;

    t = _mm_cmpgt_epi16(_mm256_castsi256_si128(bound), f);
    good = _mm_movemask_epi8(t);

#ifdef BMI
    good &= 0x5555;
    idx0 = _pdep_u64(good, 0x1111111111111111);
    idx0 = (idx0 << 8) - idx0;
    idx0 = _pext_u64(0x0E0C0A0806040200, idx0);
    pilo = _mm_cvtsi64_si128(idx0);
#else
    good = _pext_u32(good, 0x5555);
    pilo = _mm_loadl_epi64((__m128i *)&idx[good]);
#endif

    pihi = _mm_add_epi8(pilo, _mm256_castsi256_si128(ones));
    pilo = _mm_unpacklo_epi8(pilo, pihi);
    f = _mm_shuffle_epi8(f, pilo);
    _mm_storeu_si128((__m128i *)&r[ctr], f);
    ctr += _mm_popcnt_u32(good);
  }

  while(ctr < KYBER_N && pos <= REJ_UNIFORM_AVX_BUFLEN - 3) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4));
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(val1 < KYBER_Q && ctr < KYBER_N)
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
#if KYBER_K == 2
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 1;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 1;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[1].vec[0]);
  poly_nttunpack(&a[1].vec[1]);
}
#elif KYBER_K == 3
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;
  keccak_state state1x;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 0;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 0;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[0].vec[2].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[0].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[0].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[0].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[0].vec[2]);
  poly_nttunpack(&a[1].vec[0]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 2;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 2;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 2;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 2;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[1].vec[1].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[1].vec[2].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[2].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[2].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[1].vec[1].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[1].vec[2].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[2].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[2].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[1].vec[1]);
  poly_nttunpack(&a[1].vec[2]);
  poly_nttunpack(&a[2].vec[0]);
  poly_nttunpack(&a[2].vec[1]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  buf[0].coeffs[32] = 2;
  buf[0].coeffs[33] = 2;
  shake128_absorb_once(&state1x, buf[0].coeffs, 34);
  shake128_squeezeblocks(buf[0].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state1x);
  ctr0 = rej_uniform_avx(a[2].vec[2].coeffs, buf[0].coeffs);
  while(ctr0 < KYBER_N) {
    shake128_squeezeblocks(buf[0].coeffs, 1, &state1x);
    ctr0 += rej_uniform(a[2].vec[2].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[2].vec[2]);
}
#elif KYBER_K == 4
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int i, ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  for(i=0;i<4;i++) {
    f = _mm256_loadu_si256((__m256i *)seed);
    _mm256_store_si256(buf[0].vec, f);
    _mm256_store_si256(buf[1].vec, f);
    _mm256_store_si256(buf[2].vec, f);
    _mm256_store_si256(buf[3].vec, f);

    if(transposed) {
      buf[0].coeffs[32] = i;
      buf[0].coeffs[33] = 0;
      buf[1].coeffs[32] = i;
      buf[1].coeffs[33] = 1;
      buf[2].coeffs[32] = i;
      buf[2].coeffs[33] = 2;
      buf[3].coeffs[32] = i;
      buf[3].coeffs[33] = 3;
    }
    else {
      buf[0].coeffs[32] = 0;
      buf[0].coeffs[33] = i;
      buf[1].coeffs[32] = 1;
      buf[1].coeffs[33] = i;
      buf[2].coeffs[32] = 2;
      buf[2].coeffs[33] = i;
      buf[3].coeffs[32] = 3;
      buf[3].coeffs[33] = i;
    }

    shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

    ctr0 = rej_uniform_avx(a[i].vec[0].coeffs, buf[0].coeffs);
    ctr1 = rej_uniform_avx(a[i].vec[1].coeffs, buf[1].coeffs);
    ctr2 = rej_uniform_avx(a[i].vec[2].coeffs, buf[2].coeffs);
    ctr3 = rej_uniform_avx(a[i].vec[3].coeffs, buf[3].coeffs);

    while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
      shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

      ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
      ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
      ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
      ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
    }

    poly_nttunpack(&a[i].vec[0]);
    poly_nttunpack(&a[i].vec[1]);
    poly_nttunpack(&a[i].vec[2]);
    poly_nttunpack(&a[i].vec[3]);
  }
}
#endif


#define GEN_POLY_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

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
/* TODO: Optimize this using AVX2 */
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
