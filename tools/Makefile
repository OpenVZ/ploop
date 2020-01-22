PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

PROGS =	ploop \
	ploop-balloon \
	ploop-cbt \
	ploop-test \
	ploop-volume 

BINS	= $(PROGS)

MAN8	= ploop.8
MANS	= $(MAN8)

PLOOP_OBJS = \
	  common.o \
	  ploop-check.o \
	  ploop-grow.o \
	  ploop-merge.o \
	  ploop-stat.o \
	  ploop-copy.o \
	  ploop-snapshot.o

OBJS	= $(addsuffix .o,$(PROGS)) $(PLOOP_OBJS)
SOURCES	= $(OBJS:.o=.c)
CFLAGS	+= -I../lib -I ../include
LDFLAGS	+= -L../lib
LDLIBS	= -lploop -ljson-c

define do_rebrand
	sed -e "s,@PRODUCT_NAME_SHORT@,$(PRODUCT_NAME_SHORT),g" -i $(1) || exit 1;
	sed -e "s,@PRODUCT_URL@,$(PRODUCT_URL),g" -i $(1) || exit 1;
endef

all: $(PROGS) $(MANS)
.PHONY: all

$(PROGS): $(LIBPLOOP)

%: %.o common.o
	$(E) "  LD      " $@
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

ploop: $(PLOOP_OBJS)

.depend: $(SOURCES)
-include .depend

%.8: %.8.in macros.tmac
	$(E) "  GEN     " $@
	$(Q) cat macros.tmac $< > $@

install-man: $(MANS)
	$(E) "  INSTALL " $(MAN8)
	$(Q) $(INSTALL) -d $(DESTDIR)$(MAN8DIR)
	$(Q) $(INSTALL) -m 644 $(MAN8) $(DESTDIR)$(MAN8DIR)/
	$(Q) $(call do_rebrand,$(DESTDIR)$(MAN8DIR)/$(MAN8))

install-bin: $(BINS)
	$(Q) $(INSTALL) -d $(DESTDIR)$(USRSBINDIR)
	$(E) "  INSTALL " $(BINS)
	$(Q) $(INSTALL) -m 755 $(BINS) $(DESTDIR)$(USRSBINDIR)/

install: install-bin install-man
.PHONY: install install-bin install-man

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROGS) $(OBJS) $(MANS) .depend
.PHONY: clean

distclean: clean
	$(Q) rm -f .depend
.PHONY: distclean
