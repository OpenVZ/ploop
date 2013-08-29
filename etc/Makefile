include ../Makefile.inc

all clean distclean:
.PHONY: all clean distclean

install:
	$(Q) $(INSTALL) -d $(DESTDIR)$(TMPFILESDIR)
	$(Q) $(INSTALL) -m 644 tmpfiles.d/ploop.conf $(DESTDIR)$(TMPFILESDIR)
.PHONY: install
