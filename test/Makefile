PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

FILES=functions test-snapshot

all clean distclean:
.PHONY: all clean distclean

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(TESTDIR)
	$(E) "  INSTALL " $(FILES)
	$(Q) $(INSTALL) -m 755 $(FILES) $(DESTDIR)/$(TESTDIR)

