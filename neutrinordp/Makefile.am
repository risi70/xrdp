AM_CPPFLAGS = \
  -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
  -DXRDP_SBIN_PATH=\"${sbindir}\" \
  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
  -DXRDP_PID_PATH=\"${localstatedir}/run\" \
  -I$(top_srcdir)/common \
  $(FREERDP_CFLAGS)

if XRDP_DEBUG
AM_CPPFLAGS += -DXRDP_DEBUG
else
AM_CPPFLAGS += -DXRDP_NODEBUG
endif

module_LTLIBRARIES = \
  libxrdpneutrinordp.la

libxrdpneutrinordp_la_SOURCES = \
  xrdp-color.c \
  xrdp-neutrinordp.c \
  xrdp-neutrinordp.h

libxrdpneutrinordp_la_LIBADD = \
  $(top_builddir)/common/libcommon.la \
  $(FREERDP_LIBS)
