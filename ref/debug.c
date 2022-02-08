#include <stdio.h>

#include "params.h"
#include "debug.h"

void poly_print(const poly *p)
{
  int i;
  uint8_t buf[KYBER_POLYBYTES];
  poly_tobytes(buf, p);
  for(i=0;i<KYBER_POLYBYTES;i++)
    printf("%02x", buf[i]);
  printf("\n");
}

void polyvec_print(const polyvec *p)
{
  int i;
  for(i=0;i<KYBER_K;i++)
    poly_print(&p->vec[i]);
  printf("\n");
}
