
Debian
====================
This directory contains files used to package dapscoind/dapscoin-qt
for Debian-based Linux systems. If you compile dapscoind/dapscoin-qt yourself, there are some useful files here.

## dapscoin: URI support ##


dapscoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install dapscoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your dapscoinqt binary to `/usr/bin`
and the `../../share/pixmaps/dapscoin128.png` to `/usr/share/pixmaps`

dapscoin-qt.protocol (KDE)

