include ../Makefile.inc

PROGS =	ploop \
	ploop-stat \
	ploop-check \
	ploop-merge \
	ploop-copy \
	ploop-grow \
	ploop-balloon

MAN8	= ploop.8
MANS	= $(MAN8)
OBJS	= $(addsuffix .o,$(PROGS)) common.o ploop-snapshot.o
SOURCES	= $(addsuffix .c,$(PROGS)) common.c ploop-snapshot.c
CFLAGS	+= -I../lib
LDFLAGS	+= -L../lib
LDLIBS	+= -lploop

all: $(PROGS) $(MANS)
.PHONY: all

$(PROGS): $(LIBPLOOP)

%: %.o common.o
	$(E) "  LD      " $@
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

ploop: ploop-snapshot.o

.depend: $(SOURCES)
-include .depend

%.8: %.8.in macros.tmac
	$(E) "  GEN     " $@
	$(Q) cat macros.tmac $< > $@

install-man: $(MANS)
	$(E) "  INSTALL " $(MAN8)
	$(Q) $(INSTALL) -d $(DESTDIR)$(MAN8DIR)
	$(Q) $(INSTALL) -m 644 $(MAN8) $(DESTDIR)$(MAN8DIR)/

install-progs: $(PROGS)
	$(Q) $(INSTALL) -d $(DESTDIR)$(USRSBINDIR)
	$(E) "  INSTALL " $(PROGS)
	$(Q) $(INSTALL) -s -m 755 $(PROGS) $(DESTDIR)$(USRSBINDIR)/

install: install-progs install-man
.PHONY: install install-progs install-man

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROGS) $(OBJS) $(MANS)
.PHONY: clean
