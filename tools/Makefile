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

$(PROGS): $(LIBPLOOP)

%: %.o
	$(E) "  LD      " $@
	$(Q) $(CC) $(LDFLAGS) $< $(LDLIBS) -o $@

.depend: $(SOURCES)
-include .depend

man: $(MANS)

%.8: %.sgml
	$(E) "  GEN     " $@
	$(Q) -mkdir .tmpman
	$(Q) set -e; cd .tmpman; LC_ALL=C docbook2man ../$< ; mv $@ ..
	$(Q) -rm -rf .tmpman

install: $(PROGS)
	$(INSTALL) -d $(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -d $(DESTDIR)/var/lock/ploop
	for file in $(PROGS); do \
		$(INSTALL) -s -m 755 $$file $(DESTDIR)$(USRSBINDIR)/$$file; \
	done
clean:
	rm -f $(PROGS) $(OBJS) $(MANS)
