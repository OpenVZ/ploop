include ../Makefile.inc

V_MAJOR := $(word 1,$(subst ., ,$(VERSION)))
V_MINOR := $(patsubst $(V_MAJOR).%,%,$(VERSION))

LIBPLOOP        := libploop.a
LIBPLOOP_SO     := libploop.so
LIBPLOOP_SO_X   := $(LIBPLOOP_SO).$(V_MAJOR)
LIBPLOOP_SO_X_Y := $(LIBPLOOP_SO_X).$(V_MINOR)

PC=$(NAME).pc
PCDIR=$(LIBDIR)/pkgconfig

LIBOBJS=uuid.o \
	delta_read.o \
	delta_sysfs.o \
	balloon_util.o \
	check.o \
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
	ploop-copy.o \
	di.o \
	cleanup.o \
	deprecated.o \
	snapshot.o \
	symbols.o

SOURCES=$(LIBOBJS:.o=.c)
GENERATED=symbols.c

CFLAGS += $(shell pkg-config libxml-2.0 --cflags) -fPIC -fvisibility=hidden
LDFLAGS+= -shared -Wl,-soname,$(LIBPLOOP_SO_X)
LDLIBS += $(shell pkg-config libxml-2.0 --libs) -lpthread -lrt

all: $(LIBPLOOP) $(LIBPLOOP_SO) $(PC)
.PHONY: all

$(PC): $(PC).in
	$(E) "  GEN     " $@
	$(Q) sed \
		-e 's|@VERSION@|$(VERSION)|g' \
		-e 's|@LIBDIR@|$(LIBDIR)|g' \
		$^ > $@

symbols.c: ../gensym.sh ../include/libploop.h
	$(E) "  GEN     " $@
	$(Q) $^ $@


$(LIBPLOOP): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(AR) rcs $@ $+
	$(Q) ranlib $@

$(LIBPLOOP_SO_X_Y): $(LIBOBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) $^ ${LDLIBS} -o $@

$(LIBPLOOP_SO_X): $(LIBPLOOP_SO_X_Y)
	$(E) "  LN_S    " $@
	$(Q) ln -sf $^ $@

$(LIBPLOOP_SO): $(LIBPLOOP_SO_X)
	$(E) "  LN_S    " $@
	$(Q) ln -sf $^ $@

.depend: $(filter-out $(GENERATED),$(SOURCES))
-include .depend

install-lockdir:
	$(Q) $(INSTALL) -d $(DESTDIR)$(LOCKDIR)
.PHONY: install-lockdir

install-pc: $(PC)
	$(E) "  INSTALL " $(PC)
	$(Q) $(INSTALL) -d $(DESTDIR)$(PCDIR)
	$(Q) $(INSTALL) $(PC) $(DESTDIR)$(PCDIR)
.PHONY: install-pc

install: all install-lockdir install-pc
	$(Q) $(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(E) "  INSTALL " $(LIBPLOOP)
	$(Q) $(INSTALL) -m 644 $(LIBPLOOP) $(DESTDIR)$(LIBDIR)
	$(E) "  INSTALL " $(LIBPLOOP_SO_X_Y)
	$(Q) $(INSTALL) -m 755 $(LIBPLOOP_SO_X_Y) $(DESTDIR)$(LIBDIR)
	$(E) "  INSTALL " $(LIBPLOOP_SO_X) $(LIBPLOOP_SO)
	$(Q) cp -a $(LIBPLOOP_SO_X) $(LIBPLOOP_SO) $(DESTDIR)$(LIBDIR)
.PHONY: install

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(GENERATED) *.o *.a *.so *.so.*
.PHONY: clean

distclean: clean
	$(Q) rm -f .depend
.PHONY: distclean
