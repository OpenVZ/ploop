include ../Makefile.inc

SCRIPTS=mount.ploop umount.ploop

all: $(SCRIPTS)

clean:

install:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 $(SCRIPTS) $(DESTDIR)$(SBINDIR)
