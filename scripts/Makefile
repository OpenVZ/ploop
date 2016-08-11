include ../Makefile.inc

SCRIPTS=mount.ploop umount.ploop

all: $(SCRIPTS)
.PHONY: all

clean distclean:
.PHONY: clean distclean

install:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(LIBSCRIPTDIR)
	$(INSTALL) -m 755 $(SCRIPTS) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 crypt.sh $(DESTDIR)$(LIBSCRIPTDIR)
.PHONY: install
