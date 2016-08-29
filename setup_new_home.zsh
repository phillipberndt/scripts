#!/bin/zsh
#

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

echo
cd $HOME

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
for BINARY in gdo/gdo nonroot_apt/nonroot_apt.py passwrd/passwrd.py runGraphical/runGraphical.py todo/todo unpack/unpack venv/venv/venv.py pydoce/pydoce iwebd/iwebd.py on/on.py pskill/pskill.py sshproxy/sshp.py; do
	ln -s ../_scripts/$BINARY ${BINARY:t:r}
done
cd ..

# Initialize Python virtual environment
if ! which virtualenv > /dev/null; then
	wget -O bin/virtualenv https://raw.github.com/pypa/virtualenv/master/virtualenv.py
	chmod a+x bin/virtualenv
	./bin/virtualenv --system-site-packages .
else
	virtualenv --system-site-packages .
fi

if ! [ -e bin/pip ]; then
	wget -O ez_setup.py https://bootstrap.pypa.io/ez_setup.py
	python ez_setup.py
	rm -f ez_setup.py

	wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
	python get-pip.py
	rm -f get-pip.py
fi

cd ..

# Initialize zsh
cd $HOME
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

# Other dotfiles
for FILE in .local/_scripts/dotfiles/*; do
	ln -s $FILE .${FILE:t}
done

# Initialize Perl CPAN
wget -O .local/bin/cpanm http://cpanmin.us
chmod a+x .local/bin/cpanm
.local/bin/cpanm -l `pwd`/.local local::lib
.local/bin/cpanm -l `pwd`/.local Term::ProgressBar
.local/bin/cpanm -l `pwd`/.local Net::Netmask
.local/bin/cpanm -l `pwd`/.local Term::Size

# Initialize vim
[ -e .vimrc ] && mv .vimrc vimrc-old
git clone ${CLONE_BASE}vimconfig .vim
ln -s .vim/vimrc .vimrc
cd .vim
./init-after-clone.sh
cd ..
