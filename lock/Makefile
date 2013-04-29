CFLAGS=-O3
LDLIBS=-lX11 -lpam

lock: lock.c
	$(CC) -std=c99 $(CFLAGS) -o $@ $< $(LDLIBS)
