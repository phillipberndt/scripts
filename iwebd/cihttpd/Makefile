CFLAGS=-O2 -g -DLOG_LEVEL=4 -Wall -Wno-unused-result
USE=$(CFLAGS) -DUSE_MAGIC -DWITH_CGI -DWITH_REWRITE
LIBS=-lmagic -lz -pthread

ihttpd: ihttpd.c
	$(CC) ihttpd.c -o ihttpd $(USE) $(LIBS)

clean:
	rm -f ihttpd
