CC = /usr/bin/clang
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -fsanitize=address -fsanitize=undefined \
	-mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer

BENCHFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith \
						 -mavx2 -mbmi2 -mpopcnt -march=native -mtune=native -O3 -fomit-frame-pointer

NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCESKECCAK   = fips202.c fips202x4.c symmetric-shake.c \
  								keccak4x/KeccakP-1600-times4-SIMD256.o

SOURCESKECCAKBENCH   = fips202.c fips202x4.c symmetric-shake.c \
  								     keccak4x/KeccakP-1600-times4-SIMD256-bench.o

SOURCES = cbd.c consts.c indcpa.c mkem.c poly.c polyvec.c verify.c uniform.c debug.c \
					basemul.S fq.S invntt.S ntt.S shuffle.S 

HEADERS = align.h api.h cbd.h consts.h fips202.h fips202x4.h indcpa.h mkem.h ntt.h params.h poly.h polyvec.h randombytes.h reduce.h symmetric.h verify.h uniform.h debug.h

.PHONY: all clean

all: \
  test_mkyber512 \
  test_mkyber768 \
  test_mkyber1024 \
  bench_mkyber512 \
  bench_mkyber768 \
  bench_mkyber1024 \
  testvectors512 \
  testvectors768 \
  testvectors1024


keccak4x/KeccakP-1600-times4-SIMD256.o: \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) $(CFLAGS) -c $< -o $@

keccak4x/KeccakP-1600-times4-SIMD256-bench.o: \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) $(BENCHFLAGS) -c $< -o $@

test_mkyber512: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCES) $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

test_mkyber768: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

test_mkyber1024: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) test_mkyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCES) $(SOURCESKECCAK) randombytes.c test_mkyber.c -o $@

bench_mkyber512: $(SOURCES) $(SOURCESKECCAKBENCH) $(HEADERS) bench_mkyber.c randombytes.c
	$(CC) $(BENCHFLAGS) -DKYBER_K=2 $(SOURCES) $(SOURCESKECCAKBENCH) randombytes.c bench_mkyber.c -o $@

bench_mkyber768: $(SOURCES) $(SOURCESKECCAKBENCH) $(HEADERS) bench_mkyber.c randombytes.c
	$(CC) $(BENCHFLAGS) -DKYBER_K=3 $(SOURCES) $(SOURCESKECCAKBENCH) randombytes.c bench_mkyber.c -o $@

bench_mkyber1024: $(SOURCES) $(SOURCESKECCAKBENCH) $(HEADERS) bench_mkyber.c randombytes.c
	$(CC) $(BENCHFLAGS) -DKYBER_K=4 $(SOURCES) $(SOURCESKECCAKBENCH) randombytes.c bench_mkyber.c -o $@

testvectors512: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) testvectors.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCES) $(SOURCESKECCAK) testvectors.c -o $@

testvectors768: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) testvectors.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) $(SOURCESKECCAK) testvectors.c -o $@

testvectors1024: $(SOURCES) $(SOURCESKECCAK) $(HEADERS) testvectors.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCES) $(SOURCESKECCAK) testvectors.c -o $@



clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf test_mkyber512
	-$(RM) -rf test_mkyber768
	-$(RM) -rf test_mkyber1024
	-$(RM) -rf testvectors512
	-$(RM) -rf testvectors768
	-$(RM) -rf testvectors1024
	-$(RM) -rf keccak4x/KeccakP-1600-times4-SIMD256.o
	-$(RM) -rf keccak4x/KeccakP-1600-times4-SIMD256-bench.o
