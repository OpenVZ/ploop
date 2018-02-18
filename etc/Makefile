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

install_bash_completion:
        $(Q) $(INSTALL) -d $(DESTDIR)/$(COMPLETIONDIR)
        $(Q) $(INSTALL) -m 644 bash_completion.d/ploop $(DESTDIR)/$(COMPLETIONDIR)

install_modulesload:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(MODULESLOADDIR)
	$(Q) $(INSTALL) -m 644 modules-load.d/ploop.conf $(DESTDIR)/$(MODULESLOADDIR)

install: install_tmpfiles install_bash_completion install_modulesload $(if $(PLOOP_LOG_FILE), install_logrotate)

.PHONY: install install_tmpfiles install_bash_completion install_logrotate install_modulesload
