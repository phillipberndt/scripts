import socket, pyprivbind, sys

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

if len(sys.argv) == 1:
    host, port = "", 80
elif len(sys.argv) == 2:
    host, port = "", int(sys.argv[1])
elif len(sys.argv) == 3:
    host, port = sys.argv[1], int(sys.argv[2])

pyprivbind.bind(sock, (host, port))
sock.listen(1)
m, l = sock.accept()
m.send(`l`)
m.close()
