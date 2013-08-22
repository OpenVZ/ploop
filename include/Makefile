include ../Makefile.inc
INCLUDES=libploop.h ploop_if.h ploop1_image.h dynload.h

all: $(INCLUDES) check-api
.PHONY: all

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f new-dynload.h
.PHONY: clean

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(INCDIR)
	$(E) "  INSTALL " $(INCLUDES)
	$(Q) $(INSTALL) -m 644 $(INCLUDES) $(DESTDIR)/$(INCDIR)
.PHONY: install

check-api: ../gensym.sh libploop.h
	$(E) "  CHECK     " dynload.h
	$(Q) $^ new-dynload.h
	$(Q) sed -e '1,/^struct ploop_functions {$$/d' \
		 -e '/\/\* struct ploop_functions \*\/$$/,$$d' dynload.h | \
		grep -vE '^[[:space:]]*/\*.**/$$' | sort > cur-dynload.h
	$(Q) diff -u cur-dynload.h new-dynload.h || \
		( echo "*** API CHANGED, PLEASE UPDATE dynload.h"; exit 1 )
	$(Q) rm -f cur-dynload.h new-dynload.h
.PHONY: check-api
