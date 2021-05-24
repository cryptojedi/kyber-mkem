#ifndef KYBER_MKEM_H
#define KYBER_MKEM_H

#include <stdint.h>
#include "params.h"

int crypto_mkem_keypair(uint8_t *pk, 
                        uint8_t *sk, 
                        const uint8_t *seed);


int crypto_mkem_enc_c1(uint8_t *c1,
                       uint8_t *ss,
                       const uint8_t *seed,
                       const uint8_t *r);


int crypto_mkem_enc_c2(uint8_t *c2,
                       const uint8_t *pk,
                       const uint8_t *r);


int crypto_mkem_enc(uint8_t *c1,
                    uint8_t **c2s,
                    uint8_t *ss,
                    const uint8_t *seed,
                    size_t num_keys,
                    uint8_t *const* pk);


int crypto_mkem_dec(uint8_t *ss,
                    const uint8_t *c1,
                    const uint8_t *c2,
                    const uint8_t *sk);

#endif
