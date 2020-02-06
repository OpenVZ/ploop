include Makefile.inc

NAMEVER=$(NAME)-$(VERSION)$(RELEASE)
TARBALL=$(NAMEVER).tar.bz2
LICENSES=COPYING GPL-2.0
LLICENSES=$(LICENSES) LGPL-2.1

SUBDIRS=include lib tools scripts etc python test

all install clean distclean:
	@set -e; \
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
.PHONY: all install clean

check-api:
	$(MAKE) -C include $@
.PHONY: check-api

dist: check-api tar
tar: $(TARBALL)
.PHONY: dist tar

$(TARBALL): clean
	rm -f ../$(NAMEVER)
	ln -s `pwd | awk -F / '{print $$NF}'` ../$(NAMEVER)
	tar --directory .. --exclude-vcs --exclude .depend \
		--exclude-from .gitignore \
		-cvhjf ../$(TARBALL) $(NAMEVER)
	rm -f $(TARBALL)
	mv ../$(TARBALL) .
	rm -f ../$(NAMEVER)

rpms: tar
	rpmbuild -ta $(TARBALL) ${RPMB_ARGS}
.PHONY: rpms

cov: clean
	rm -rf cov-int
	cov-build --dir cov-int make
	tar czf cov.tgz cov-int
	rm -rf cov-int
	git describe --tags HEAD
.PHONY: cov

install-licenses:
	for f in $(LLICENSES); do \
		for tdir in $(DDOCDIR) $(LDOCDIR); do \
			mkdir -p $(DESTDIR)$$tdir; \
			install -m 644 $$f $(DESTDIR)$$tdir; \
		done; \
	done
	mkdir -p $(DESTDIR)$(DOCDIR); \
	for f in $(LICENSES); do \
		install -m 644 $$f $(DESTDIR)$(DOCDIR); \
	done

# Add optional local rules
-include Makefile.local
