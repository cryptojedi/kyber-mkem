#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

void indcpa_mkeypair(uint8_t pk[MKYBER_INDCPA_PUBLICKEYBYTES],
                     uint8_t sk[MKYBER_INDCPA_SECRETKEYBYTES],
                     const uint8_t publicseed[KYBER_SYMBYTES]);

void indcpa_enc_c1(uint8_t c1[MKYBER_C1BYTES],
                   uint8_t fwd[MKYBER_FWDBYTES],
                   const uint8_t seed[KYBER_SYMBYTES],
                   const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_enc_c2(uint8_t c2[MKYBER_C2BYTES],
                   const uint8_t m[KYBER_INDCPA_MSGBYTES],
                   const uint8_t pk[MKYBER_INDCPA_PUBLICKEYBYTES],
                   const uint8_t fwd[MKYBER_FWDBYTES]);

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c1[MKYBER_C1BYTES],
                const uint8_t c2[MKYBER_C2BYTES],
                const uint8_t sk[MKYBER_INDCPA_SECRETKEYBYTES]);

#endif
