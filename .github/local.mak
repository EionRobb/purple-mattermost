SHELL := /bin/bash
CC := /usr/bin/i686-w64-mingw32-gcc
GMSGFMT := msgfmt
MAKENSIS := /usr/bin/makensis
WINDRES := /usr/bin/i686-w64-mingw32-windres
STRIP := /usr/bin/i686-w64-mingw32-strip
INTLTOOL_MERGE := /usr/bin/intltool-merge
GCC_SSP_TOP := $(PIDGIN_TREE_TOP)/../win32-dev/mingw-4.7.2/bin/

INCLUDE_PATHS := -I$(PIDGIN_TREE_TOP)/../win32-dev/w32api/include
LIB_PATHS := -L$(PIDGIN_TREE_TOP)/../win32-dev/w32api/lib
