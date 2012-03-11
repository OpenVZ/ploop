include Makefile.inc

SUBDIRS=include lib tools scripts

all install clean:
	@set -e; \
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done

rpms: clean
	cd .. && tar -cvjf ploop.tar.bz2 ploop --exclude-vcs && \
		rpmbuild -ta ploop.tar.bz2 ${RPMB_ARGS}

