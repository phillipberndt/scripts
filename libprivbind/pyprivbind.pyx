cdef extern from "libprivbind.h":
    int privbind(int sockfd, char *address, unsigned int port)

import socket as _sock
import os

__all__ = [ "bind", "gensocket" ]
__doc__ = "Bind sockets to a privileged port"

def bind(socket, address):
    """
        Bind a socket to a specific port on 0.0.0.0

        Parameters:
            socket  A socket.socket() instance
            address A host and port number tuple for the AF_INET family (tcp/udp)

        Returns nothing, but raises a RuntimeError if binding failed.

        Only ports that have user-executable files in /etc/pyprivbind/
        are allowed, i.e. if you want to bind to port 80, run
          $ touch /etc/pyprivbind/80
          $ chmod a+x /etc/pyprivbind/80
        once before trying to invoke this.
    """
    if type(socket) is not _sock._socketobject:
        raise TypeError("socket must be a socket.socket() instance")

    host, port = address
    port = int(port)
    if not host:
        host = "0.0.0.0"

    retval = privbind(socket.fileno(), host, port)
    if retval == 255:
        raise RuntimeError("Failed to bind socket to port %d: General failure" % port)
    elif retval == 254:
        raise IOError("Failed to bind socket to port %(port)d: Access denied (create /etc/pyprivbind/%(port)d and make it executable)" % { "port": port })
    elif retval == 253:
        raise RuntimeError("Failed to bind socket to port %d: Failed to run helper program `libprivbind-helper'" % port)
    elif retval != 0:
        raise RuntimeError("Failed to bind socket to port %d: error %d (%s)" % (port, retval, os.strerror(retval)))

def gensocket(address, type=_sock.SOCK_STREAM):
    """
        Create a TCP o UDP socket bound to a given port

        Parameters:
            address A host and port number tuple for the AF_INET family (tcp/udp)
            type    The type of the socket to create, i.e. SOCK_STREAM or SOCK_DGRAM

    """
    socket = _sock.socket(type=type)
    socket.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)

    bind(socket, address)
    return socket
