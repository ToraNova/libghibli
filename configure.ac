LT_PREREQ([2.4.6])
AC_INIT([libghibli], [1.0], [chia_jason96@live.com])
AC_CONFIG_AUX_DIR([autoconf-aux])

# initialize automake, report warnings as errors
# foreign keyword here specify that this package is a foreign package
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

# initialize libtool (for shared library)
AM_PROG_AR
LT_INIT([disable-static])

# check for C and C++ compiler
AC_PROG_CC
AC_PROG_CXX

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev, or pam on arch-linux.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])
AC_CHECK_LIB([pam], [pam_start])

PKG_CHECK_MODULES([LIBSODIUM], [libsodium], [], [])

# specify the header
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# all makefiles (makefile.am) must be declared here. one .am per directory
AC_CONFIG_FILES([Makefile src/Makefile])
AC_CHECK_FUNCS([secure_getenv])

# Argument to enable error/warning log, defaults to YES
AC_ARG_ENABLE([ewlog],
[  --enable-ewlog    'Enable error and warning output to stdout.'],
[case "${enableval}" in
  yes) ewlog=true ;;
  no)  ewlog=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-ewlog]) ;;
esac],[ewlog=true])
AS_IF(
[test x$ewlog = xtrue],[AC_DEFINE([EWLOG],[1],['Error and warning logs enabled'])]
)

# Argument to enable debug log, defaults to NO
AC_ARG_ENABLE([debug],
[  --enable-debug    'Enable debugging output to stdout.'],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=false])
AS_IF(
[test x$debug = xtrue],[AC_DEFINE([DEBUG],[1],['Debugging output enabled'])]
)

# Argument to compile test programs, defaults to NO
AC_ARG_ENABLE([tests],
[  --enable-tests    'Compile test programs.'],
[case "${enableval}" in
  yes) tests=true ;;
  no)  tests=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-tests]) ;;
esac],[tests=false])
AM_CONDITIONAL([COMPILETESTS], [test x$tests = xtrue])

# Argument to compile test programs, defaults to NO
AC_ARG_ENABLE([runnables],
[  --enable-runnables    'Compile runnable utils.'],
[case "${enableval}" in
  yes) runnables=true ;;
  no)  runnables=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-runnables]) ;;
esac],[runnables=false])
AM_CONDITIONAL([COMPILERUNS], [test x$runnables = xtrue])

AC_ARG_WITH([libsecuritydir],
    	[AS_HELP_STRING([--libsecuritydir],
	['Directory to install PAM modules.'])],
    	[], [default_libsecuritydir='/usr/lib/security'])
AC_SUBST([libsecuritydir], [$default_libsecuritydir])

AC_OUTPUT
