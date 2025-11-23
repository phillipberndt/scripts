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
	echo " * .config/nvim is initialized with my nvim repository"
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
for BINARY in gdo/gdo passwrd/passwrd.py unpack/unpack pydoce/pydoce on/on.py pskill/pskill.py sshproxy/sshp.py paxel/paxel.py emoji/emoji.py errno/errno cache/cache ipatch/ipatch; do
	[ -e ${BINARY:t:r} ] || ln -s ../_scripts/$BINARY ${BINARY:t:r}
done
cd ..

# Initialize zsh
cd $HOME
if [ -z "$IS_UPDATE" ]; then
	[ -e .zshrc ] && mv .zshrc zshrc-old
	[ -d .zsh ] && mv .zsh zsh-old
	mkdir .zsh
	cd .zsh
	ln -s ../.local/_scripts/zshrc/{site,zshrc,zgen,p10k.zsh} .
	mkdir scripts
	ln -s ../.local/_scripts/zshrc/scripts/* scripts/
	cd ..
	ln -s .zsh/zshrc .zshrc
	ln -s .zsh/p10k.zsh .p10k.zsh
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

# Initialize neovim
if [ -d ~/.config/nvim ]; then
	git -C ~/.config/nvim pull
else
	git clone ${CLONE_BASE}nvimconfig ~/.config/nvim
fi

# Initialize or update fzf
cd .local
mkdir -p tmp
cd tmp
version=$(wget -qO - https://github.com/junegunn/fzf/releases  | grep -oE 'fzf-[^"]+-linux_amd64.tar.gz' | cut -d- -f2 | head -n1)
wget -O fzf https://github.com/junegunn/fzf/releases/download/v$version/fzf-$version-linux_amd64.tar.gz
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
version=$(wget -qO - https://github.com/phillipberndt/iwebd/releases  | grep -oE '/tag/v[0-9.]{5,}' | cut -d/ -f3 | head -n1)
wget -O iwebd https://github.com/phillipberndt/iwebd/releases/download/$version/iwebd-$version-linux-amd64.tar.gz
tar xzf iwebd
mv -f iwebd ../bin
cd ..
rm -rf tmp
cd ..

# Initialize or update lf
cd .local
mkdir -p tmp
cd tmp
version=$(wget -qO - https://github.com/gokcehan/lf/releases  | grep -oE '/r[0-9]+/' | head -n1)
wget -O lf https://github.com/gokcehan/lf/releases/download/$version/lf-linux-amd64.tar.gz
tar xzf lf
mv -f lf ../bin
cd ..
rm -rf tmp
cd ..

# Initialize or update neovim
cd .local
mkdir -p tmp
cd tmp
version=$(wget -qO - 'https://github.com/neovim/neovim/releases?page=2'  | grep -oE '/v[0-9.]+/' | head -n1)
wget -O nvim https://github.com/neovim/neovim/releases/download${version}nvim-linux-x86_64.tar.gz
tar xzf nvim
[ -d ../_apps ] || mkdir ../_apps
mv -f nvim-linux-x86_64 ../_apps/
cd ..
rm -rf tmp
ln -s ../_apps/nvim-linux-86_64/bin/nvim bin/nvim
cd ..

# Initialize uv
[ -e ~/.local/bin/uv ] || ( curl -LsSf https://astral.sh/uv/install.sh | sh )
ln -s ../_scripts/python_env/{ipython,jupyter} .local/bin
