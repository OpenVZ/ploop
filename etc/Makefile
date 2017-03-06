PLOOPROOT = ..

include $(PLOOPROOT)/Makefile.inc

all clean distclean:
.PHONY: all clean distclean

install_tmpfiles:
	$(Q) $(INSTALL) -d $(DESTDIR)$(TMPFILESDIR)
	$(Q) $(INSTALL) -m 644 tmpfiles.d/ploop.conf $(DESTDIR)$(TMPFILESDIR)

install_logrotate:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(LOGROTATEDIR)
	$(Q) $(INSTALL) -m 644 logrotate.d/ploop $(DESTDIR)/$(LOGROTATEDIR)

install: install_tmpfiles $(if $(PLOOP_LOG_FILE), install_logrotate)

.PHONY: install install_tmpfiles install_logrotate
