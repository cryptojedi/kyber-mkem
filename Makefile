CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = mkem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
SOURCESNINETIES = $(SOURCES) sha256.c sha512.c aes256ctr.c symmetric-aes.c
HEADERS = params.h mkem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h
HEADERSNINETIES = $(HEADERS) aes256ctr.h sha2.h

.PHONY: all speed shared clean

all: \
  test_mkyber512 \
  test_mkyber768 \
  test_mkyber1024 \
  test_mkyber512_90s \
  test_mkyber768_90s \
  test_mkyber1024_90s \


test_mkyber512: $(SOURCESKECCAK) $(HEADERSKECCAK) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

test_mkyber768: $(SOURCESKECCAK) $(HEADERSKECCAK) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

test_mkyber1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

test_mkyber512_90s: $(SOURCESNINETIES) $(HEADERSNINETIES) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -DKYBER_90S $(SOURCESNINETIES) randombytes.c test_mkyber.c -o $@

test_mkyber768_90s: $(SOURCESNINETIES) $(HEADERSNINETIES) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 -DKYBER_90S $(SOURCESNINETIES) randombytes.c test_mkyber.c -o $@

test_mkyber1024_90s: $(SOURCESNINETIES) $(HEADERSNINETIES) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 -DKYBER_90S $(SOURCESNINETIES) randombytes.c test_mkyber.c -o $@


clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf test_mkyber512
	-$(RM) -rf test_mkyber768
	-$(RM) -rf test_mkyber1024
	-$(RM) -rf test_mkyber512_90s
	-$(RM) -rf test_mkyber768_90s
	-$(RM) -rf test_mkyber1024_90s
