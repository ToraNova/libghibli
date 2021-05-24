# compile a shared library to be installed; $(libdir) @default /usr/local/lib
# using libtool (different library name to avoid confusion)
# if this is used, the SHARED library file is also compiled
lib_LTLIBRARIES = libghibli.la
libghibli_la_SOURCES =	utils/bufhelp.c utils/simplesock.c utils/futil.c utils/jbase64.c \
			impl/crypto.c impl/ibi.c impl/ds.c \
			impl/schnorr.c impl/heng.c \
			core.c ghibli.c
libghibli_la_LDFLAGS = -lsodium

# for pluggable authentication modules
libsecurity_LTLIBRARIES = pam_ghibc.la
pam_ghibc_la_SOURCES =ghibc_pam.c
pam_ghibc_la_LIBADD = libghibli.la
pam_ghibc_la_LDFLAGS = -lsodium -lpam -lpam_misc -module -avoid-version

# header files to be installed; $(includedir) @default /usr/local/include
include_HEADERS = ghibli.h

# the following block is disabled by
# ../configure --disable-runnables
if COMPILERUNS
# define programs to be compiled and installed; $(bindir) @default /usr/local/bin
bin_PROGRAMS = ghibc
ghibc_SOURCES = ghibc_cli.c
ghibc_LDADD = libghibli.la
endif

# the following block is enabled by
# ../configure --enable-tests
if COMPILETESTS
# define programs to be compiled but not installed
# useful for test applications
noinst_PROGRAMS = coretest example schnorrtest dstest ibitest
coretest_SOURCES = tests/coretest.c
# assume test.c is using the shared library, using this to link
coretest_LDADD = libghibli.la
example_SOURCES = tests/example.c
example_LDADD = libghibli.la
schnorrtest_SOURCES = tests/schibitest.c
schnorrtest_LDADD = libghibli.la
dstest_SOURCES = tests/dstest.c
dstest_LDADD = libghibli.la
ibitest_SOURCES = tests/ibitest.c
ibitest_LDADD = libghibli.la
# one may include an optional argument as such
# nodist_include_HEADERS (to not include in distribution)
# distribution and installation is different! once installs to
# the current system, the other prepares it to be used on another system
endif

# COMPLEX SETUP BELOW: ALLOW SELECTION OF DIFF UPSTREAM LIBRARIES
# See configure.ac line 61 and beyond
#if ULOPENSSL
#libsigilmqv_la_SOURCES = \
#		sigilcrypt_openssl.cpp \
#		sigilmqv.cpp sigilmqv.c.cpp \
#		utils/simplesock.c utils/bufhelp.c
#libsigilmqv_la_LDFLAGS = -lcrypto
#endif
#if ULSODIUM
#libsigilmqv_la_SOURCES = \
#		sigilcrypt_sodium.cpp \
#		sigilmqv.cpp sigilmqv.c.cpp \
#		utils/simplesock.c utils/bufhelp.c
#libsigilmqv_la_LDFLAGS = -lsodium
#endif
