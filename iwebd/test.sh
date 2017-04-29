#!/bin/bash
#
fail() {
	echo -e "\033[1;31m$@\033[0m" >&2
}

python3 ./iwebd.py3 -h 1234 -f 1235 -cd &
PID=$!
sleep 1

if ! curl -q http://localhost:1234 2>/dev/null | grep -q "Directory contents for /"; then
	fail "Directory contents on /"
fi

if ! curl -q "http://localhost:1234/?action=download" 2>/dev/null | tar tj >/dev/null 2>&1; then
	fail "Download / as TAR"
fi

kill $PID
wait
