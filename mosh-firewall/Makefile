OPERATING_SYSTEM=$(shell uname -s)
CFLAGS=-std=c99

SOURCES=mosh-server-firewall.c
ifeq ($(OPERATING_SYSTEM),Linux)
	SOURCES+=mywaitpid.c
endif

mosh-server-firewall: $(SOURCES)

.PHONY: install
install: mosh-server-firewall
	dpkg-divert --add --rename --divert /usr/bin/mosh-server-real /usr/bin/mosh-server
	install mosh-server-firewall /usr/bin/mosh-server
	chown root:root /usr/bin/mosh-server
	chmod u+s /usr/bin/mosh-server
