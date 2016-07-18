#!/bin/sh
#

# Install Inconsolata
mkdir -p ~/.local/share/fonts/Inconsolata.otf
[ -e ~/.local/share/fonts/Inconsolata.otf ] || wget http://www.levien.com/type/myfonts/Inconsolata.otf -O ~/.local/share/fonts/Inconsolata.otf
gconftool -t string -s /desktop/gnome/interface/monospace_font_name "Inconsolata 11"
dconf write /org/gnome/desktop/interface/monospace-font-name "'Inconsolata Medium 11'"

# Install colorscheme for gnome-terminal
# Based on Base16/Colors
# https://github.com/chriskempson/base16-gnome-terminal
CONF_PATH=/apps/gnome-terminal/profiles/Default

gconftool -t string -s ${CONF_PATH}/palette "#FFFFFFFFFFFF:#FFFF41413636:#2E2ECCCC4040:#FFFFDCDC0000:#00007474D9D9:#B1B10D0DC9C9:#7F7FDBDBFFFF:#BBBBBBBBBBBB:#777777777777:#FFFF41413636:#2E2ECCCC4040:#FFFFDCDC0000:#00007474D9D9:#B1B10D0DC9C9:#7F7FDBDBFFFF:#111111111111<"
gconftool -t string -s ${CONF_PATH}/background_color "#ffffff"
gconftool -t string -s ${CONF_PATH}/bold_color "#555555"
gconftool -t string -s ${CONF_PATH}/foreground_color "#555555555555"
gconftool -t bool -s ${CONF_PATH}/use_theme_background false
gconftool -t bool -s ${CONF_PATH}/use_theme_colors false
