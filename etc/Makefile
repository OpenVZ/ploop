include ../Makefile.inc

all clean:
.PHONY: all clean

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(TMPFILESDIR)
	$(Q) $(INSTALL) -m 644 tmpfiles.d/ploop.conf $(DESTDIR)/$(TMPFILESDIR)
.PHONY: install
