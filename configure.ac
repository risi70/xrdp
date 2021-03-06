# Process this file with autoconf to produce a configure script

AC_PREREQ(2.65)
AC_INIT([xrdp], [0.9.0], [xrdp-devel@googlegroups.com])
AC_CONFIG_HEADERS(config_ac.h:config_ac-h.in)
AM_INIT_AUTOMAKE([1.7.2 foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_C_CONST
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Use silent rules by default if supported by Automake
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AX_CFLAGS_WARN_ALL
AX_APPEND_COMPILE_FLAGS([-Wwrite-strings])
AX_GCC_FUNC_ATTRIBUTE([format])
AX_TYPE_SOCKLEN_T

case $host_os in
	*linux*)
		linux=yes
		;;
	*freebsd*)
		freebsd=yes
		;;
	*netbsd*)
		netbsd=yes
		;;
	*openbsd*)
		openbsd=yes
		;;
esac

AM_CONDITIONAL(LINUX, [test "x$linux" = xyes])
AM_CONDITIONAL(FREEBSD, [test "x$freebsd" = xyes])
AM_CONDITIONAL(OPENBSD, [test "x$openbsd" = xyes])
AM_CONDITIONAL(NETBSD, [test "x$netbsd" = xyes])

AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != xno; then
        AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

AC_ARG_ENABLE(pam, AS_HELP_STRING([--disable-pam],
              [Build PAM support (default: yes)]),
              [], [enable_pam=yes])
AC_ARG_ENABLE(nopam, AS_HELP_STRING([--enable-nopam],
              [Build no PAM support (default: no, deprecated)]),
              [
                  if test "x$enable_nopam" = "xyes"
                  then
                      enable_pam=no
                      AC_MSG_WARN([--enable-nopam option is deprecated. Please use --disable-pam instead.])
                  fi
              ])
AM_CONDITIONAL(SESMAN_NOPAM, [test x$enable_pam != xyes])
AC_ARG_ENABLE(ipv6, AS_HELP_STRING([--enable-ipv6],
              [Build IPv6 support (default: no, experimental)]),
              [], [enable_ipv6=no])
AC_ARG_ENABLE(ipv6only, AS_HELP_STRING([--enable-ipv6only],
              [Build IPv6-only (default: no)]),
              [], [enable_ipv6only=no])
AC_ARG_ENABLE(kerberos, AS_HELP_STRING([--enable-kerberos],
              [Build kerberos support (default: no)]),
              [], [enable_kerberos=no])
AC_ARG_ENABLE(bsd, AS_HELP_STRING([--enable-bsd],
              [Build BSD auth support (default: no)]),
              [bsd=true], [bsd=false])
AM_CONDITIONAL(SESMAN_BSD, [test x$bsd = xtrue])
AM_CONDITIONAL(SESMAN_KERBEROS, [test x$enable_kerberos = xyes])
AC_ARG_ENABLE(pamuserpass, AS_HELP_STRING([--enable-pamuserpass],
              [Build pam userpass support (default: no)]),
              [], [enable_pamuserpass=no])
AM_CONDITIONAL(SESMAN_PAMUSERPASS, [test x$enable_pamuserpass = xyes])
AC_ARG_ENABLE(xrdpdebug, AS_HELP_STRING([--enable-xrdpdebug],
              [Build debug (default: no)]),
              [], [enable_xrdpdebug=no])
AM_CONDITIONAL(XRDP_DEBUG, [test x$enable_xrdpdebug = xyes])
AC_ARG_ENABLE(neutrinordp, AS_HELP_STRING([--enable-neutrinordp],
              [Build neutrinordp module (default: no)]),
              [], [enable_neutrinordp=no])
AM_CONDITIONAL(XRDP_NEUTRINORDP, [test x$enable_neutrinordp = xyes])
AC_ARG_ENABLE(jpeg, AS_HELP_STRING([--enable-jpeg],
              [Build jpeg module (default: no)]),
              [], [enable_jpeg=no])
AM_CONDITIONAL(XRDP_JPEG, [test x$enable_jpeg = xyes])
AC_ARG_ENABLE(tjpeg, AS_HELP_STRING([--enable-tjpeg],
              [Build turbo jpeg module (default: no)]),
              [], [enable_tjpeg=no])
AM_CONDITIONAL(XRDP_TJPEG, [test x$enable_tjpeg = xyes])
AC_ARG_ENABLE(fuse, AS_HELP_STRING([--enable-fuse],
              [Build fuse(clipboard file / drive redir) (default: no)]),
              [], [enable_fuse=no])
AM_CONDITIONAL(XRDP_FUSE, [test x$enable_fuse = xyes])
AC_ARG_ENABLE(xrdpvr, AS_HELP_STRING([--enable-xrdpvr],
              [Build xrdpvr module (default: no)]),
              [], [enable_xrdpvr=no])
AM_CONDITIONAL(XRDP_XRDPVR, [test x$enable_xrdpvr = xyes])
AC_ARG_ENABLE(rfxcodec, AS_HELP_STRING([--enable-rfxcodec],
              [Build using librfxcodec (default: no)]),
              [], [enable_rfxcodec=no])
AM_CONDITIONAL(XRDP_RFXCODEC, [test x$enable_rfxcodec = xyes])
AC_ARG_ENABLE(opus, AS_HELP_STRING([--enable-opus],
              [Build opus(audio codec) (default: no)]),
              [], [enable_opus=no])
AM_CONDITIONAL(XRDP_OPUS, [test x$enable_opus = xyes])
AC_ARG_ENABLE(loginfirst, AS_HELP_STRING([--enable-loginfirst],
              [Build with login window first and session selection following (default: no)]),
              [], [enable_loginfirst=no])
AM_CONDITIONAL(XRDP_LOGINFIRST, [test x$enable_loginfirst = xyes])
AC_ARG_ENABLE(mp3lame, AS_HELP_STRING([--enable-mp3lame],
              [Build lame mp3(audio codec) (default: no)]),
              [], [enable_mp3lame=no])
AM_CONDITIONAL(XRDP_MP3LAME, [test x$enable_mp3lame = xyes])
AC_ARG_ENABLE(pixman, AS_HELP_STRING([--enable-pixman],
              [Use pixman library (default: no)]),
              [], [enable_pixman=no])
AM_CONDITIONAL(XRDP_PIXMAN, [test x$enable_pixman = xyes])

# checking for openssl
AC_CHECK_HEADER([openssl/rc4.h], [],
  [AC_MSG_ERROR([please install libssl-dev or openssl-devel])],
  [#include <stdlib.h>])

# checking for pam variation
# Linux-PAM is used in Linux systems
# OpenPAM is used by FreeBSD, NetBSD, DragonFly BSD and OS X
# OpenBSD uses BSD Authentication rather than both PAMs
AC_CHECK_HEADER([security/_pam_types.h],
                [AC_DEFINE([HAVE__PAM_TYPES_H], 1, [Using Linux-PAM], [])])
AC_CHECK_HEADER([security/pam_constants.h],
                [AC_DEFINE([HAVE_PAM_CONSTANTS_H], 1, [Using OpenPAM], [])])

# checking if pam should be autodetected.
if test "x$enable_pam" = "xyes"
then
  if test "x$enable_kerberos" != "xyes"
  then
    if test -z "$enable_bsd"
    then
      AC_CHECK_HEADER([security/pam_appl.h], [],
        [AC_MSG_ERROR([please install libpam0g-dev or pam-devel])])
    fi
  fi
fi

if test "x$enable_ipv6only" = "xyes"
then
  enable_ipv6=yes
  AC_DEFINE([XRDP_ENABLE_IPV6ONLY],1,[Enable IPv6 only])
fi

if test "x$enable_ipv6" = "xyes"
then
  AC_DEFINE([XRDP_ENABLE_IPV6],1,[Enable IPv6])
fi

if test "x$enable_pam" != "xyes" || test "x$bsd" = "xtrue"
then
  AC_DEFINE([USE_NOPAM],1,[Disable PAM])
fi

AS_IF( [test "x$enable_neutrinordp" = "xyes"] , [PKG_CHECK_MODULES(FREERDP, freerdp >= 1.0.0)] )

# checking for libjpeg
if test "x$enable_jpeg" = "xyes"
then
  AC_CHECK_HEADER([jpeglib.h], [],
    [AC_MSG_ERROR([please install libjpeg-dev or libjpeg-devel])])
fi

if test "x$enable_xrdpdebug" = "xyes"
then
  CFLAGS="-g -O0"
fi

# checking for fuse
if test "x$enable_fuse" = "xyes"
then
  PKG_CHECK_MODULES([FUSE], [fuse >= 2.6], [],
    [AC_MSG_ERROR([please install libfuse-dev or fuse-devel])])
fi

# checking for opus
if test "x$enable_opus" = "xyes"
then
  AC_CHECK_HEADER([opus/opus.h], [],
    [AC_MSG_ERROR([please install libopus-dev or opus-devel])])
fi

# checking for lame mp3
if test "x$enable_mp3lame" = "xyes"
then
  AC_CHECK_HEADER([lame/lame.h], [],
    [AC_MSG_ERROR([please install libmp3lame-dev or lamemp3-devel])])
fi

AS_IF( [test "x$enable_pixman" = "xyes"] , [PKG_CHECK_MODULES(XRDP_PIXMAN, pixman-1 >= 0.1.0)] )

# checking for TurboJPEG
if test "x$enable_tjpeg" = "xyes"
then
if test ! -z "$TURBOJPEG_PATH"
then
  # env var TURBOJPEG_PATH has been defined, use that
  AC_CHECK_HEADER([$TURBOJPEG_PATH/include/turbojpeg.h], [],
    [AC_MSG_ERROR([could not find TurboJPEG in dir specified by env variable TURBOJPEG_PATH ($TURBOJPEG_PATH)])])

   AC_SUBST(TurboJpegIncDir, ["-I$TURBOJPEG_PATH/include"])
   AC_SUBST(TurboJpegLibDir, ["-L$TURBOJPEG_PATH/lib -Wl,-rpath -Wl,$TURBOJPEG_PATH/lib"])
elif test -e /opt/libjpeg-turbo/lib64
then
  # TurboJPEG has been installed to /opt on a 64 bit m/c
  AC_SUBST(TurboJpegIncDir, ["-I/opt/libjpeg-turbo/include"])
  AC_SUBST(TurboJpegLibDir, ["-L/opt/libjpeg-turbo/lib64 -Wl,-rpath -Wl,/opt/libjpeg-turbo/lib64"])
elif test -e /opt/libjpeg-turbo/lib32
then
  # TurboJPEG has been installed to /opt on a 32 bit m/c
  AC_SUBST(TurboJpegIncDir, ["-I/opt/libjpeg-turbo/include"])
  AC_SUBST(TurboJpegLibDir, ["-L/opt/libjpeg-turbo/lib32 -Wl,-rpath -Wl,/opt/libjpeg-turbo/lib32"])
else
  # check in default location
  AC_CHECK_HEADER([/usr/include/turbojpeg.h], [],
    [AC_MSG_ERROR([please install TurboJPEG ])])
  AC_SUBST(TurboJpegIncDir, [""])
  AC_SUBST(TurboJpegLibDir, [""])
fi
fi

AC_PATH_XTRA
if test "x$no_x" == "xyes"; then
  AC_MSG_ERROR([please install libx11-dev or libX11-devel])
fi

save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $X_CFLAGS"

# checking for Xfixes
AC_CHECK_HEADER([X11/extensions/Xfixes.h], [],
  [AC_MSG_ERROR([please install libx11-dev and libxfixes-dev or libXfixes-devel])],
  [#include <X11/Xlib.h>])

# checking for Xrandr
AC_CHECK_HEADER([X11/extensions/Xrandr.h], [],
  [AC_MSG_ERROR([please install libxrandr-dev or libXrandr-devel])],
  [#include <X11/Xlib.h>])

CFLAGS="$save_CFLAGS"

AC_SUBST([moduledir], '${libdir}/xrdp')

if test "x${prefix}" = "xNONE" ; then
sysconfdir="/etc";
localstatedir="/var";
fi
AC_CONFIG_FILES([Makefile
                 common/Makefile
                 vnc/Makefile
                 rdp/Makefile
                 libxrdp/Makefile
                 xup/Makefile
                 mc/Makefile
                 neutrinordp/Makefile
                 xrdp/Makefile
                 sesman/Makefile
                 sesman/libscp/Makefile
                 sesman/tools/Makefile
                 sesman/sessvc/Makefile
                 sesman/chansrv/Makefile
                 keygen/Makefile
                 docs/Makefile
                 docs/man/Makefile
                 instfiles/Makefile
                 instfiles/pam.d/Makefile
                 instfiles/init.d/Makefile
                 instfiles/rc.d/Makefile
                 instfiles/default/Makefile
                 instfiles/pulse/Makefile
                 genkeymap/Makefile
                 xrdpapi/Makefile
                 xrdpvr/Makefile
])
#                 fontdump/Makefile
#                 xrdp/cursors/Makefile
#                 Xserver/hw/rdp/Makefile
AC_OUTPUT

# example of how to check for a struct in a header
#AC_CHECK_MEMBER([struct in6_addr.s6_addr],
#                [],
#                [AC_DEFINE(NO_ARPA_INET_H_IP6, 1, [for IPv6])],
#                [#include <arpa/inet.h>])
