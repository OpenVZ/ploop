PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

FILES=functions \
	test-change-fmt_version \
	test-device-grow \
	test-device-snapshot \
	test-fs-resize \
	test-pcopy.py \
	test-snapshot \
	test-sparse \

all clean distclean:
.PHONY: all clean distclean

install:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(TESTDIR)
	$(E) "  INSTALL " $(FILES)
	$(Q) $(INSTALL) -m 755 $(FILES) $(DESTDIR)/$(TESTDIR)

