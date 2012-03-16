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
	di.o

SOURCES=$(LIBOBJS:.o=.c)

CFLAGS += $(shell pkg-config libxml-2.0 --cflags) -fPIC
LDFLAGS += -L.
LDLIBS += $(shell pkg-config libxml-2.0 --libs)

all: $(LIBPLOOP) $(LIBPLOOP_DYN)

$(LIBPLOOP): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(AR) rcs $@ $+
	$(Q) ranlib $@

$(LIBPLOOP_DYN): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $(INC) $(LDFLAGS) -shared  $^ ${LDLIBS} -o $@

-include .depend

install: all
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -m 644 $(LIBPLOOP) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -m 755 $(LIBPLOOP_DYN) $(DESTDIR)/$(LIBDIR)

clean:
	rm -f $(PROGS) *.o *.a *.so
