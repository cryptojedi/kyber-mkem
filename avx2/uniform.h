#ifndef UNIFORM_H
#define UNIFORM_H

#include "polyvec.h"

#define REJ_UNIFORM_AVX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS*XOF_BLOCKBYTES)

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

#define gen_polyvec KYBER_NAMESPACE(gen_polyvec)
void gen_polyvec(polyvec *a, const uint8_t seed[KYBER_SYMBYTES]);

#endif
