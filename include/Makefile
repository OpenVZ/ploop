include ../Makefile.inc
INCLUDES=libploop.h ploop_if.h ploop1_image.h

all:

clean:

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(INCDIR)
	$(E) "  INSTALL " $(INCLUDES)
	$(Q) $(INSTALL) -m 644 $(INCLUDES) $(DESTDIR)/$(INCDIR)

.PHONY: all install
