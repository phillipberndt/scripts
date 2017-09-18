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
for BINARY in gdo/gdo nonroot_apt/nonroot_apt.py passwrd/passwrd.py runGraphical/runGraphical.py todo/todo unpack/unpack venv/venv/venv.py pydoce/pydoce iwebd/iwebd.py on/on.py pskill/pskill.py sshproxy/sshp.py paxel/paxel.py emoji/emoji.py colors/color_codes; do
	[ -e ${BINARY:t:r} ] || ln -s ../_scripts/$BINARY ${BINARY:t:r}
done
cd ..

# Initialize Python virtual environment
if ! [ -e bin/python2 ]; then
	wget -O virtualenv https://raw.github.com/pypa/virtualenv/master/virtualenv.py
	chmod a+x virtualenv
	./virtualenv --system-site-packages .
	rm -f virtualenv
fi

if ! [ -e bin/easy_setup ]; then
	wget -O ez_setup.py https://bootstrap.pypa.io/ez_setup.py
	./bin/python2 ez_setup.py
	rm -f ez_setup.py
fi

if ! [ -e bin/pip2 ]; then
	[ -e get-pip.py ] || wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
	./bin/python2 get-pip.py
fi

if ! [ -e bin/virtualenv ]; then
	bin/pip2 install virtualenv
fi

bin/pip2 install ipython requests flask jedi pexpect psutil

if ! [ -e bin/python3 ]; then
	if python3 -m venv --system-site-packages .; then
		[ -e bin/pip3 ] || ./bin/python3 get-pip.py
		bin/pip3 install ipython requests flask jedi pexpect psutil
	fi
fi

rm -f get-pip.py
rm -f bin/pip
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

# Initialize Perl CPAN
if ! [ -e .local/bin/cpanm ]; then
	wget -O .local/bin/cpanm http://cpanmin.us
	chmod a+x .local/bin/cpanm
	.local/bin/cpanm -l `pwd`/.local local::lib
	.local/bin/cpanm -l `pwd`/.local Term::ProgressBar
	.local/bin/cpanm -l `pwd`/.local Net::Netmask
	.local/bin/cpanm -l `pwd`/.local Term::Size
fi

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

# Initialize fzf
if which go &>/dev/null; then
	cd .local
	git clone https://github.com/junegunn/fzf
	cd fzf
	make
	if [ -e fzf ]; then
		rm -f ../bin/fzf
		mv target/fzf* ../bin/fzf
		rm -f ~/.zsh/scripts/fzf.zsh
		mv shell/key-bindings.zsh ~/.zsh/scripts/fzf.zsh
		chmod +x ~/.zsh/scripts/fzf.zsh
	fi
	cd ..
	rm -rf fzf
else
	echo "\033[32mgo is not installed; skipping fzf\033[0m"
fi
