include Makefile.inc

SPEC=$(NAME).spec
VERSION=$(shell awk '/^Version:/{print $$2}' $(SPEC))
RELEASE=$(shell awk '/^%define rel / {if ($$3 != 1) print "-"$$3}' $(SPEC))
NAMEVER=$(NAME)-$(VERSION)$(RELEASE)
TARBALL=$(NAMEVER).tar.bz2

SUBDIRS=include lib tools scripts etc

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
