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

if grep -q pberndt .ssh/id_rsa.pub >/dev/null 2>&1; then
	CLONE_BASE=git@github.com:phillipberndt/
else
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

# Link binaries
[ -d bin ] || mkdir bin
cd bin
for BINARY in gdo/gdo nonroot_apt/nonroot_apt.py passwrd/passwrd.py runGraphical/runGraphical.py todo/todo unpack/unpack venv/venv/venv.py; do
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
cd ..

# Initialize zsh
cd $HOME
[ -e .zshrc ] && mv .zshrc zshrc-old
[ -d .zsh ] && mv .zsh zsh-old
mkdir .zsh
cd .zsh
ln -s ../.local/_scripts/zshrc/{site,zshrc} .
mkdir scripts
cd ..
ln -s .zsh/zshrc .zshrc
source .zshrc

# Initialize Perl CPAN
wget -O .local/bin/cpanm http://cpanmin.us
.local/bin/cpanm -l `pwd`/.local local::lib
.local/bin/cpanm -l `pwd`/.local Term::ProgressBar

# Initialize vim
[ -e .vimrc ] && mv .vimrc vimrc-old
git clone ${CLONE_BASE}vimconfig .vim
ln -s .vim/vimrc .
cd .vim
./init-after-clone.sh
cd ..
