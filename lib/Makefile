include ../Makefile.inc

LIBPLOOP=libploop.a
LIBPLOOP_DYN = libploop.so
LIBOBJS=uuid.o \
	delta_read.o \
	delta_sysfs.o \
	balloon_util.o \
	fsck_util.o \
	ploop.o \
	xml.o \
	logger.o \
	balloon.o \
	lock.o \
	fsutils.o \
	gpt.o \
	crc32.o \
	merge.o \
	util.o \
	pcopy.o \
	di.o \
	cleanup.o

SOURCES=$(LIBOBJS:.o=.c)

CFLAGS += $(shell pkg-config libxml-2.0 --cflags) -fPIC -fvisibility=hidden
LDFLAGS += -L.
LDLIBS += $(shell pkg-config libxml-2.0 --libs) -lrt

all: $(LIBPLOOP) $(LIBPLOOP_DYN)
.PHONY: all

$(LIBPLOOP): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(AR) rcs $@ $+
	$(Q) ranlib $@

$(LIBPLOOP_DYN): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $(INC) $(LDFLAGS) -shared  $^ ${LDLIBS} -o $@

.depend: $(SOURCES)
-include .depend

install-lockdir:
	$(Q) $(INSTALL) -d $(DESTDIR)/$(LOCKDIR)
.PHONY: install-lockdir

install: all install-lockdir
	$(Q) $(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(E) "  INSTALL " $(LIBPLOOP)
	$(Q) $(INSTALL) -m 644 $(LIBPLOOP) $(DESTDIR)/$(LIBDIR)
	$(E) "  INSTALL " $(LIBPLOOP_DYN)
	$(Q) $(INSTALL) -m 755 $(LIBPLOOP_DYN) $(DESTDIR)/$(LIBDIR)
.PHONY: install

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROGS) *.o *.a *.so
.PHONY: clean
