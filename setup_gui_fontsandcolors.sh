#!/bin/bash
#

# Install Inconsolata
mkdir -p ~/.local/share/fonts/
if ! [ -e ~/.local/share/fonts/InconsolataNerdFont-Regular.ttf ]; then
	wget https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/Inconsolata.zip
	unzip Inconsolata.zip "*.ttf" -d ~/.local/share/fonts
	rm -f Inconsolata.zip
fi
dconf write /org/gnome/desktop/interface/monospace-font-name "'Inconsolata Nerd Font Regular 13'"

# Install colorscheme for gnome-terminal
# Based on Base16/Colors
# https://github.com/chriskempson/base16-gnome-terminal
GCONF_PATH=/apps/gnome-terminal/profiles/Default
DCONF_PATH=/org/gnome/terminal/legacy/profiles:/$(dconf list /org/gnome/terminal/legacy/profiles:/)

PALETTE="#FFFFFFFFFFFF:#FFFF41413636:#2E2ECCCC4040:#FFFFDCDC0000:#00007474D9D9:#B1B10D0DC9C9:#7F7FDBDBFFFF:#BBBBBBBBBBBB:#777777777777:#FFFF41413636:#2E2ECCCC4040:#FFFFDCDC0000:#00007474D9D9:#B1B10D0DC9C9:#7F7FDBDBFFFF:#111111111111"
BG_COLOR="#ffffff"
FG_COLOR="#555555555555"
BD_COLOR="#555555"

gconftool -t string -s ${GCONF_PATH}/palette $PALETTE
gconftool -t string -s ${GCONF_PATH}/background_color $BG_COLOR
gconftool -t string -s ${GCONF_PATH}/bold_color $BD_COLOR
gconftool -t string -s ${GCONF_PATH}/foreground_color $FG_COLOR
gconftool -t bool -s ${GCONF_PATH}/use_theme_background false
gconftool -t bool -s ${GCONF_PATH}/use_theme_colors false

dconf write ${DCONF_PATH}palette "['"${PALETTE//:/','/}"']"
dconf write ${DCONF_PATH}background-color "'"$BG_COLOR"'"
dconf write ${DCONF_PATH}bold-color "'"$BD_COLOR"'"
dconf write ${DCONF_PATH}foreground-color "'"$FG_COLOR"'"
dconf write ${DCONF_PATH}use_theme_background false
dconf write ${DCONF_PATH}use_theme_colors false
