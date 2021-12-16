#!/bin/zsh
#

cd $HOME

IS_UPDATE=
if [ -d .local/_scripts ]; then
	IS_UPDATE=1
fi

if [ -z "$IS_UPDATE" ]; then
	echo
	echo "This script will initialize your home directory $HOME according to my preferences."
	echo
	echo "That is:"
	echo " * .local/ is heavily used. Especially, .local/bin is used as a per-user \$PATH."
	echo " * .vim/ is initialized with my vim repository and .vimrc is placed in \$HOME"
	echo " * .zshrc is linked to the version from this repository. Local changes should go into"
	echo "   your .zsh directory, into an executable file in .zsh/scripts/"
	echo " * The binaries from this repository will be placed into .local/bin/"
	echo
	echo "Continue? (C-c to stop, anything to continue)"
	read YES
fi

if grep -q pberndt .ssh/id_rsa.pub >/dev/null 2>&1 && git ls-remote git@github.com:phillipberndt/scripts 2>&1 > /dev/null; then
	echo "Cloning using r/w SSH connection ..."
	CLONE_BASE=git@github.com:phillipberndt/
else
	echo "Cloning using read-only git connection ..."
	CLONE_BASE=git://github.com/phillipberndt/
fi

# Clone scripts directory
[ -d .local ] || mkdir .local
cd .local
if [ -d _scripts ]; then
	cd _scripts
	git pull
	cd ..
else
	git clone ${CLONE_BASE}scripts.git _scripts
fi

# Initialize submodules
cd _scripts
git submodule init
git submodule update --init
cd ..

# Install fonts and colors
./_scripts/setup_gui_fontsandcolors.sh

# Link binaries
[ -d bin ] || mkdir bin
cd bin
for BINARY in gdo/gdo passwrd/passwrd.py unpack/unpack pydoce/pydoce on/on.py pskill/pskill.py sshproxy/sshp.py paxel/paxel.py emoji/emoji.py errno/errno; do
	[ -e ${BINARY:t:r} ] || ln -s ../_scripts/$BINARY ${BINARY:t:r}
done
cd ..

# Initialize Python virtual environment
	[ -e get-pip.py ] || wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py

if ! [ -e bin/ipython3 ]; then
	PIPBIN=pip3
	if ! which $PIPBIN; then
		wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
		python3 get-pip.py --user
		rm -f get-pip.py
		PIPBIN=bin/pip3
	fi
	$PIPBIN install ipython requests flask jedi pexpect psutil
fi

cd ..

# Initialize zsh
cd $HOME
if [ -z "$IS_UPDATE" ]; then
	[ -e .zshrc ] && mv .zshrc zshrc-old
	[ -d .zsh ] && mv .zsh zsh-old
	mkdir .zsh
	cd .zsh
	ln -s ../.local/_scripts/zshrc/{site,zshrc,zgen} .
	mkdir scripts
	ln -s ../.local/_scripts/zshrc/scripts/* scripts/
	cd ..
	ln -s .zsh/zshrc .zshrc
	source .zshrc
else
	cd .zsh
	for FILE in ../.local/_scripts/zshrc/scripts/*; do
		[ -e scripts/${FILE:t} ] || ln -s $FILE scripts/
	done
	cd ..
fi

# Other dotfiles
for FILE in .local/_scripts/dotfiles/*; do
	[ -e .${FILE:t} ] || ln -s $FILE .${FILE:t}
done

# Initialize vim
if [ -z "$IS_UPDATE" ]; then
	[ -e .vimrc ] && mv .vimrc vimrc-old
	git clone ${CLONE_BASE}vimconfig .vim
	ln -s .vim/vimrc .vimrc
	cd .vim
	./init-after-clone.sh
	cd ..
else
	cd .vim
	git pull
	git submodule update --init
	cd ..
fi

# Initialize or update fzf
cd .local
mkdir -p tmp
cd tmp
version=$(wget -qO - https://github.com/junegunn/fzf/releases  | grep -oE 'fzf-[^"]+-linux_amd64.tar.gz' | cut -d- -f2 | head -n1)
wget -O fzf https://github.com/junegunn/fzf/releases/download/$version/fzf-$version-linux_amd64.tar.gz
tar xzf fzf
mv -f fzf ../bin
cd ..
rm -rf tmp
cd ..
wget -O ~/.zsh/scripts/fzf.zsh https://raw.githubusercontent.com/junegunn/fzf/master/shell/key-bindings.zsh

# Initialize or update iwebd
cd .local
mkdir -p tmp
cd tmp
version=$(wget -qO - https://github.com/phillipberndt/iwebd/releases  | grep -oE 'iwebd-[^"]+-linux-amd64.tar.gz' | cut -d- -f2 | head -n1)
wget -O iwebd https://github.com/phillipberndt/iwebd/releases/download/$version/iwebd-$version-linux-amd64.tar.gz
tar xzf iwebd
mv -f iwebd ../bin
cd ..
rm -rf tmp
cd ..
