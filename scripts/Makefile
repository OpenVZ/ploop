PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

SCRIPTS=mount.ploop umount.ploop

all: $(SCRIPTS)
.PHONY: all

clean distclean:
.PHONY: clean distclean

install:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(LIBSCRIPTDIR)
	$(INSTALL) -d $(DESTDIR)$(LIBSCRIPTDIR)/crypt.d
	$(INSTALL) -m 755 $(SCRIPTS) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 crypthelper $(DESTDIR)$(LIBSCRIPTDIR)
.PHONY: install
