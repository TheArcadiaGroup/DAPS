
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c scrypt.c
if USE_ASM
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
if ARCH_PPC
minerd_SOURCES += sha2-ppc.S scrypt-ppc.S
endif
endif
if TARGET_WINDOWS
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= -lchilkat-9.5.0_win @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ -lrpcrt4
minerd_CFLAGS	= -fno-strict-aliasing
minerd_CPPFLAGS	= @LIBCURL_CPPFLAGS@ $(JANSSON_INCLUDES) $(PTHREAD_FLAGS) 
else
if TARGET_DARWIN
minerd_LDFLAGS	= $(PTHREAD_FLAGS) -L./lib -framework CoreFoundation -framework IOKit -framework Security
minerd_LDADD	= -lchilkat-9.5.0_mac @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ -lz
minerd_CFLAGS	= -fno-strict-aliasing -I./include
minerd_CPPFLAGS	= @LIBCURL_CPPFLAGS@ $(JANSSON_INCLUDES) $(PTHREAD_FLAGS)
else
minerd_LDFLAGS	= $(PTHREAD_FLAGS) -L./lib
minerd_LDADD	= -lchilkat-9.5.0_linux @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@
minerd_CFLAGS	= -fno-strict-aliasing -I./include
minerd_CPPFLAGS	= @LIBCURL_CPPFLAGS@ $(JANSSON_INCLUDES) $(PTHREAD_FLAGS)
endif
endif
ACLOCAL_AMFLAGS = -I m4
CCLD = @CXX@