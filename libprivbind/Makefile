DESTDIR=/
PREFIX=/usr/local
CFLAGS=-O2

PYCFLAGS=$(shell pkg-config --cflags python)
PYLIBS=$(shell pkg-config --libs python)

all: libprivbind-helper pyprivbind.so

libprivbind-helper: libprivbind-helper.c

pyprivbind.c: pyprivbind.pyx libprivbind.h
	cython $<

pyprivbind.so: pyprivbind.c
	$(CC) -shared -fPIC $(CFLAGS) $(PYCFLAGS) -o $@ $< $(PYLIBS)

clean:
	rm -f pyprivbind.so pyprivbind.c libprivbind-helper

# WARNING: If you use suid instead of setcap, fix the access() check in libprivbind-helper to account for the suid bit!!
install:
	install -sD libprivbind-helper $(DESTDIR)$(PREFIX)/bin/libprivbind-helper
	setcap 'cap_net_bind_service=ep' $(DESTDIR)$(PREFIX)/bin/libprivbind-helper
	install -D pyprivbind.so $(DESTDIR)$(PREFIX)/lib/python2.7/dist-packages/pyprivbind.so
	[ -d /etc/privbind ] || mkdir /etc/privbind

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/libprivbind-helper $(DESTDIR)$(PREFIX)/lib/python2.7/dist-packages/pyprivbind.so
