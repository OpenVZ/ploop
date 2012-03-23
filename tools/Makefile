include ../Makefile.inc

PROGS =	ploop \
	ploop-stat \
	ploop-fsck \
	ploop-merge \
	ploop-copy \
	ploop-grow \
	ploop-balloon

MANS	= ploop.8
OBJS	= $(addsuffix .o,$(PROGS))
SOURCES	= $(addsuffix .c,$(PROGS))
CFLAGS	+= -I../lib
LDFLAGS	+= -L../lib
LDLIBS	+= -lploop

all: $(PROGS)
.PHONY: all

$(PROGS): $(LIBPLOOP)

%: %.o
	$(E) "  LD      " $@
	$(Q) $(CC) $(LDFLAGS) $< $(LDLIBS) -o $@

.depend: $(SOURCES)
-include .depend

man: $(MANS)
.PHONY: man

%.8: %.sgml
	$(E) "  GEN     " $@
	$(Q) -mkdir .tmpman
	$(Q) set -e; cd .tmpman; LC_ALL=C docbook2man ../$< ; mv $@ ..
	$(Q) -rm -rf .tmpman

install: $(PROGS)
	$(Q) $(INSTALL) -d $(DESTDIR)$(USRSBINDIR)
	$(Q) $(INSTALL) -d $(DESTDIR)/var/lock/ploop
	$(E) "  INSTALL " $(PROGS)
	$(Q) $(INSTALL) -s -m 755 $(PROGS) $(DESTDIR)$(USRSBINDIR)/
.PHONY: install

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROGS) $(OBJS) $(MANS)
.PHONY: clean
