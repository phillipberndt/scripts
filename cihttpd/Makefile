CFLAGS=-g -DUSE_MAGIC -DWITH_CGI -DLOG_LEVEL=5
ihttpd: ihttpd.c
	$(CC) ihttpd.c -o ihttpd $(CFLAGS) -lmagic -pthread
