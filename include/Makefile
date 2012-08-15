include ../Makefile.inc
INCLUDES=libploop.h ploop_if.h ploop1_image.h dynload.h

all: $(INCLUDES)

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f dynload.h

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(INCDIR)
	$(E) "  INSTALL " $(INCLUDES)
	$(Q) $(INSTALL) -m 644 $(INCLUDES) $(DESTDIR)/$(INCDIR)

dynload.h: ../gensym.sh libploop.h
	$(E) "  GEN     " $@
	$(Q) $^ $@

.PHONY: all install
