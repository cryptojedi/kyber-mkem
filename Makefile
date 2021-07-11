CC = /usr/bin/clang
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -fsanitize=address -fsanitize=undefined
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = mkem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c fips202.c symmetric-shake.c uniform.c
HEADERS = params.h mkem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h fips202.h uniform.h
HEADERSNINETIES = $(HEADERS) aes256ctr.h sha2.h

.PHONY: all clean

all: \
  test_mkyber512 \
  test_mkyber768 \
  test_mkyber1024 \


test_mkyber512: $(SOURCES) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCES) randombytes.c test_mkyber.c -o $@

test_mkyber768: $(SOURCES) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) randombytes.c test_mkyber.c -o $@

test_mkyber1024: $(SOURCES) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCES) randombytes.c test_mkyber.c -o $@

clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf test_mkyber512
	-$(RM) -rf test_mkyber768
	-$(RM) -rf test_mkyber1024
