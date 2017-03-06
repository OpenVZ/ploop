PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

all:
	$(Q) CFLAGS= python setup.py build
.PHONY: all

clean:
	$(E) "  CLEAN   "
	$(Q) rm -rf build/
.PHONY: clean

distclean: clean
.PHONY: distclean

install:
	$(Q) CFLAGS= python setup.py install \
		$(if $(DESTDIR), --root $(DESTDIR))
.PHONY: install
