CC=gcc
INSTALL=install
SBINDIR=/sbin
USRSBINDIR=/usr/sbin
INCDIR=/usr/include/ploop
DEBUG=yes

CFLAGS = -I. -I../include -Wall -fno-strict-aliasing -Wstrict-prototypes \
	-Werror -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS += $(if $(DEBUG),-g -O0 -DDEBUG,-O2)

LDFLAGS += $(if $(DEBUG),-g -rdynamic,)

export CFLAGS CC

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif
export E Q

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS) -c $< -o $@

.depend: $(SOURCES)
	$(E) "  DEP     " $@
	$(Q) $(CC) $(CFLAGS) -M $^ > $@
