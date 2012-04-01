include Makefile.inc

NAME=ploop
SPEC=$(NAME).spec
VERSION=$(shell awk '/^Version:/{print $$2}' $(SPEC))
RELEASE=$(shell awk '/^%define rel / {if ($$3 != 1) print "-"$$3}' $(SPEC))
NAMEVER=$(NAME)-$(VERSION)$(RELEASE)
TARBALL=$(NAMEVER).tar.bz2

SUBDIRS=include lib tools scripts

all install clean:
	@set -e; \
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
.PHONY: all install clean

dist: tar
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
