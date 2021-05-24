#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_mkyber512_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_mkyber512_ref_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_mkyber768_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_mkyber768_ref_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_mkyber1024_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_mkyber1024_ref_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2


#define MKYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES)
#define MKYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

#define MKYBER_PUBLICKEYBYTES  (MKYBER_INDCPA_PUBLICKEYBYTES)
#define MKYBER_SECRETKEYBYTES  (MKYBER_INDCPA_SECRETKEYBYTES + MKYBER_INDCPA_PUBLICKEYBYTES + KYBER_SYMBYTES)
#define MKYBER_C1BYTES         (KYBER_POLYVECCOMPRESSEDBYTES)
#define MKYBER_C2BYTES         (KYBER_POLYCOMPRESSEDBYTES)

#endif
