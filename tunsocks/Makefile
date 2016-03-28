DESTDIR=/
PREFIX=/usr/local/

CCFLAGS=-std=c++11 -Ilibtins/include/ -Llibtins/lib -g -pthread
LDLIBS=-ltins -lboost_system
CXX=clang++

ifndef HAS_SHARED_TINS
PREREQS+=libtins/lib/libtins.a
endif

.PHONY: all install

all: tunsocks

tunsocks: tunsocks.cc $(PREREQS)
	$(CXX) $(CCFLAGS) -o $@ $< $(LDLIBS)

libtins/lib/libtins.a:
	[ -d libtins ] || git clone --depth=1 https://github.com/mfontanini/libtins
	cd libtins && cmake -DLIBTINS_BUILD_SHARED=0
	$(MAKE) -C libtins

install: tunsocks
	install -sD ./tunsocks $(DESTDIR)$(PREFIX)/bin/tunsocks
	chown root:root $(DESTDIR)$(PREFIX)/bin/tunsocks
	chmod u+s $(DESTDIR)$(PREFIX)/bin/tunsocks

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/tunsocks

clean:
	rm -f tunsocks

distclean: clean
	rm -rf libtins/
