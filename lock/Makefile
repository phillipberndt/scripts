CFLAGS=-O3
LDLIBS=-lX11 -lpam -lXext
PREFIX=/usr/bin/

lock: lock.c
	$(CC) -std=c99 $(CFLAGS) -o $@ $< $(LDLIBS)

install: lock
	install -s lock $(PREFIX)

clean:
	rm -f lock
