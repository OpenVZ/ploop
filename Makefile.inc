PLOOPROOT ?= .

include $(PLOOPROOT)/Makefile.incl

NAME=ploop
VERSION=$(shell cat $(PLOOPROOT)/Makefile.version)
RELEASE=

CC=gcc
INSTALL=install
SBINDIR=/sbin
USRSBINDIR=/usr/sbin
INCDIR=/usr/include/ploop
LIBDIR=/usr/lib
# For DEB-based systems
DEB_HOST_MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)
ifneq "$(DEB_HOST_MULTIARCH)" ""
LIBDIR=/usr/lib/$(DEB_HOST_MULTIARCH)
# For RPM-based systems
else ifeq "$(shell uname -m)" "x86_64"
LIBDIR=/usr/lib64
endif
LOCKDIR=/var/lock/ploop
MANDIR=/usr/share/man
DOCDIR=/usr/share/doc/$(NAME)-$(VERSION)
LDOCDIR=/usr/share/doc/$(NAME)-lib-$(VERSION)
DDOCDIR=/usr/share/doc/$(NAME)-devel-$(VERSION)
MAN8DIR=$(MANDIR)/man8
TMPFILESDIR=/usr/lib/tmpfiles.d
LOGROTATEDIR=/etc/logrotate.d
COMPLETIONDIR=/etc/bash_completion.d
MODULESLOADDIR=/etc/modules-load.d
LIBSCRIPTDIR=/usr/libexec/ploop
DEBUG=yes

CFLAGS := $(if $(DEBUG),-g -O0 -DDEBUG,-O2) $(CFLAGS)
CFLAGS += -I. -I../include -fno-strict-aliasing \
	-Wall -Wstrict-prototypes -Werror -Wformat-security \
	-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 \
	-DPRODUCT_NAME_SHORT=\"$(PRODUCT_NAME_SHORT)\"
CFLAGS += $(RPM_OPT_FLAGS) $(CPPFLAGS)
CFLAGS += $(if $(PLOOP_LOG_FILE), -DPLOOP_LOG_FILE=\"$(PLOOP_LOG_FILE)\")
#CFLAGS += -DDEBUG_TIMES

LDFLAGS += $(if $(DEBUG),-g -rdynamic,)

export CFLAGS CC

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif
export E Q

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -c $< -o $@

.depend:
	$(E) "  DEP     " $@
	$(Q) $(CC) $(CFLAGS) -M $^ > $@
