include ../Makefile.inc
INCLUDES=libploop.h ploop_if.h ploop1_image.h libploop-sym.h

all: $(INCLUDES)

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f libploop-sym.h

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(INCDIR)
	$(E) "  INSTALL " $(INCLUDES)
	$(Q) $(INSTALL) -m 644 $(INCLUDES) $(DESTDIR)/$(INCDIR)

libploop-sym.h: ../gensym.sh libploop.h
	$(E) "  GEN     " $@
	$(Q) $^ $@

.PHONY: all install
