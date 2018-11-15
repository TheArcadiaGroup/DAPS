# allow to use Host cuda functions in C/C++
DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST		= autogen.sh README.md README.txt LICENSE.txt \
			  ccminer.sln ccminer.vcxproj ccminer.vcxproj.filters \
			  compat/gettimeofday.c compat/getopt/getopt_long.c

SUBDIRS = compat

bin_PROGRAMS = ccminer

ccminer_SOURCES	= elist.h miner.h compat.h \
			  compat/inttypes.h compat/stdbool.h compat/unistd.h \
			  compat/sys/time.h compat/getopt/getopt.h \
			  crc32.c \
			  ccminer.cpp pools.cpp util.cpp bench.cpp bignum.cpp \
			  api.cpp hashlog.cpp nvml.cpp stats.cpp sysinfos.cpp cuda.cpp \
			  nvsettings.cpp \
			  crypto/xmr-rpc.cpp crypto/wildkeccak-cpu.cpp crypto/wildkeccak.cu \
			  sha256/sha256d.cu sha256/cuda_sha256d.cu sha256/sha256t.cu sha256/cuda_sha256t.cu cuda_checkhash.cu \
			  sia/sia.cu sia/sia-rpc.cpp sph/blake2b.c \
			  sph/bmw.c sph/blake.c sph/groestl.c sph/jh.c sph/keccak.c sph/skein.c \
			  sph/cubehash.c sph/echo.c sph/luffa.c sph/sha2.c sph/shavite.c sph/simd.c \
			  sph/hamsi.c sph/hamsi_helper.c sph/streebog.c \
			  sph/shabal.c sph/whirlpool.c sph/sha2big.c sph/haval.c \
			  sph/ripemd.c sph/sph_sha2.c

# scrypt
ccminer_SOURCES += scrypt.cpp \
    scrypt/blake.cu scrypt/keccak.cu scrypt/sha256.cu \
    scrypt/salsa_kernel.cu scrypt/test_kernel.cu \
    scrypt/fermi_kernel.cu scrypt/kepler_kernel.cu \
    scrypt/nv_kernel.cu scrypt/nv_kernel2.cu scrypt/titan_kernel.cu

if HAVE_NVML
nvml_defs = -DUSE_WRAPNVML
nvml_libs = -ldl
endif

if HAVE_WINDOWS
ccminer_SOURCES += compat/winansi.c
endif

ccminer_LDFLAGS  = $(PTHREAD_FLAGS) @CUDA_LDFLAGS@
ccminer_LDADD    = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @CUDA_LIBS@ @OPENMP_CFLAGS@ @LIBS@ $(nvml_libs)
ccminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES) $(nvml_defs)

if HAVE_OSX
ccminer_CPPFLAGS += -I/usr/local/llvm/lib/clang/4.0.0/include
ccminer_LDFLAGS += -L/usr/local/llvm/lib
ccminer_LDADD += -lomp
endif

#ccminer_CPPFLAGS += -DUSE_LIBSODIUM
#ccminer_LDFLAGS += -Lequi/lib
#ccminer_LDADD += -lsodium
ccminer_LDADD += -lcuda

nvcc_ARCH :=
#nvcc_ARCH += -gencode=arch=compute_61,code=\"sm_61,compute_61\"
nvcc_ARCH += -gencode=arch=compute_52,code=\"sm_52,compute_52\"
nvcc_ARCH += -gencode=arch=compute_50,code=\"sm_50,compute_50\"
#nvcc_ARCH += -gencode=arch=compute_35,code=\"sm_35,compute_35\"
#nvcc_ARCH += -gencode=arch=compute_30,code=\"sm_30,compute_30\"

nvcc_FLAGS = $(nvcc_ARCH) @CUDA_INCLUDES@ -I. @CUDA_CFLAGS@
nvcc_FLAGS += $(JANSSON_INCLUDES) --ptxas-options="-v"

# we're now targeting all major compute architectures within one binary.
.cu.o:
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=128 -o $@ -c $<

# This object does not use cuda device code but call the different kernels (autotune)
scrypt/salsa_kernel.o: scrypt/salsa_kernel.cu
	$(NVCC) $(JANSSON_INCLUDES) -I. @CUDA_INCLUDES@ @CUDA_CFLAGS@ -gencode=arch=compute_30,code=\"sm_30,compute_30\" -o $@ -c $<

# These kernels are for older devices (SM)

scrypt/test_kernel.o: scrypt/test_kernel.cu
	$(NVCC) $(JANSSON_INCLUDES) -I. @CUDA_INCLUDES@ @CUDA_CFLAGS@ -gencode=arch=compute_30,code=\"sm_30,compute_30\" -o $@ -c $<

scrypt/fermi_kernel.o: scrypt/fermi_kernel.cu
	$(NVCC) $(JANSSON_INCLUDES) -I. @CUDA_INCLUDES@ @CUDA_CFLAGS@ -gencode=arch=compute_30,code=\"sm_30,compute_30\" -o $@ -c $<

scrypt/kepler_kernel.o: scrypt/kepler_kernel.cu
	$(NVCC) $(JANSSON_INCLUDES) -I. @CUDA_INCLUDES@ @CUDA_CFLAGS@ -gencode=arch=compute_30,code=\"sm_30,compute_30\" -o $@ -c $<

scrypt/nv_kernel.o: scrypt/nv_kernel.cu
	$(NVCC) $(JANSSON_INCLUDES) -I. @CUDA_INCLUDES@ @CUDA_CFLAGS@ -gencode=arch=compute_30,code=\"sm_30,compute_30\" -o $@ -c $<

scrypt/titan_kernel.o: scrypt/titan_kernel.cu
	$(NVCC) $(nvcc_FLAGS) -gencode=arch=compute_35,code=\"sm_35,compute_35\" -o $@ -c $<
