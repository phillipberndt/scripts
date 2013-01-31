#!/bin/bash
#
../unpack/unpack "http://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.32.tar.gz"
cd lighttpd-1.4.32
./configure --prefix=`cd ..; pwd`/_lighttpd || exit 1
make || exit 1
make install || exit 1
cd ..
rm -rf lighttpd-1.4.32

