#!/bin/sh
#

# Guess a setup directory
SETUP_DIRECTORY=~/.local/
IFS=:
set $PATH
for DIR; do
	[ -w $DIR ] || continue
	SETUP_DIRECTORY=$DIR
	break
done
[ $UID == 0 ] && SETUP_DIRECTORY=/usr/local/
echo "I will install venv into $SETUP_DIRECTORY"
while true; do
	echo -n "Is this okay? [yes or no] "
	read yesno
	[ "x$yesno" == "xyes" ] && break
	if [ "x$yesno" == "xno" ]; then
		echo -n "Enter a different directory: "
		read SETUP_DIRECTORY
		break
	fi
	echo "Enter yes or no."
done

# Install
install -D venv/venv.py $SETUP_DIRECTORY/bin/venv
