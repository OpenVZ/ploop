include ../Makefile.inc

SCRIPTS=mount.ploop umount.ploop

all: $(SCRIPTS)
.PHONY: all

clean:
.PHONY: clean

install:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 $(SCRIPTS) $(DESTDIR)$(SBINDIR)
.PHONY: install
