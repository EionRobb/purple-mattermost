
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc

PROTOC_C ?= protoc-c
PKG_CONFIG ?= pkg-config
MAKENSIS ?= makensis
MAKERPM ?= rpmbuild
RPMDIR ?= $(shell pwd)/rpmdir
RPMSPEC = purple-mattermost.spec

COMMIT_ID = $(shell git log -1 --pretty=format:"%h")
ifneq ($(COMMIT_ID),)
PLUGIN_VERSION ?= 1.1.$(shell date +%Y.%m.%d).git.$(COMMIT_ID)
else
PLUGIN_VERSION ?= 1.1.$(shell date +%Y.%m.%d)
endif

CFLAGS	?= -O2 -g -pipe -Wall -DMATTERMOST_PLUGIN_VERSION='"$(PLUGIN_VERSION)"'
LDFLAGS ?= -Wl,-z,relro 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  MATTERMOST_TARGET = libmattermost.dll
  MATTERMOST_DEST = "$(PROGRAMFILES)/Pidgin/plugins"
  MATTERMOST_ICONS_DEST = "$(PROGRAMFILES)/Pidgin/pixmaps/pidgin/protocols"
  MAKENSIS = "$(PROGRAMFILES)/NSIS/makensis.exe"
else

  UNAME_S := $(shell uname -s)
  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    CFLAGS += -I/opt/local/include 
	# gcc does not support relro
    LDFLAGS = -lz $(OS)

    CC = gcc
    CPP = cpp
  else
    CC ?= gcc
    CPP ?= cpp
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      MATTERMOST_TARGET = FAILNOPURPLE
      MATTERMOST_DEST =
	  MATTERMOST_ICONS_DEST =
    else
      MATTERMOST_TARGET = libmattermost.so
      MATTERMOST_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  MATTERMOST_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    MATTERMOST_TARGET = libmattermost3.so
    MATTERMOST_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	MATTERMOST_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists glib-2.0 json-glib-1.0 2>/dev/null && echo "true"),)
    MATTERMOST_TARGET = FAILNOLIBS
  endif

  # no pkg-config for libmarkdown, just try if header is on include path.
  ifeq ($(shell echo "" | $(CPP) $(CFLAGS) -include mkdio.h - -o /dev/null 2>/dev/null && echo "true"),)
    MATTERMOST_TARGET = FAILNODISCOUNT
  endif

endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -I$(WIN32_DEV_TOP)/discount-2.2.1 -DENABLE_NLS -DMATTERMOST_PLUGIN_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz -L$(WIN32_DEV_TOP)/discount-2.2.1 -lmarkdown
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES := 
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := purplecompat.c libmattermost-helpers.c libmattermost-json.c libmattermost-markdown.c libmattermost.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE FAILNOLIBS FAILNODISCOUNT clean install-icons installer

all: $(MATTERMOST_TARGET)

libmattermost.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 --libs --cflags` -Ipurple2compat -g -ggdb -lmarkdown

libmattermost3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 --libs --cflags` -g -ggdb -lmarkdown

libmattermost.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libmattermost3.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(MATTERMOST_TARGET) install-icons
	mkdir -p $(MATTERMOST_DEST)
	install -p $(MATTERMOST_TARGET) $(MATTERMOST_DEST)

install-icons: mattermost16.png mattermost22.png mattermost48.png
	mkdir -p $(MATTERMOST_ICONS_DEST)/16
	mkdir -p $(MATTERMOST_ICONS_DEST)/22
	mkdir -p $(MATTERMOST_ICONS_DEST)/48
	install -m644 mattermost16.png $(MATTERMOST_ICONS_DEST)/16/mattermost.png
	install -m644 mattermost22.png $(MATTERMOST_ICONS_DEST)/22/mattermost.png
	install -m644 mattermost48.png $(MATTERMOST_ICONS_DEST)/48/mattermost.png

installer: purple-mattermost.nsi libmattermost.dll mattermost16.png mattermost22.png mattermost48.png
	$(MAKENSIS) purple-mattermost.nsi

	
rpm: clean 
	mkdir -p $(RPMDIR)/{BUILD,RPMS,SRPMS,SOURCES,SPECS}
	cp $(RPMSPEC).in $(RPMSPEC)
	sed -i 's|@PLUGIN_VERSION@|$(PLUGIN_VERSION)|' $(RPMSPEC)
	tar -czf $(RPMDIR)/SOURCES/purple-mattermost-$(PLUGIN_VERSION).tar.gz --exclude-vcs --transform 's|^\.|purple-mattermost-$(PLUGIN_VERSION)|' --exclude purple-mattermost-$(PLUGIN_VERSION).tar.gz .	
	$(MAKERPM) -ta $(RPMDIR)/SOURCES/purple-mattermost-$(PLUGIN_VERSION).tar.gz --define '_topdir $(RPMDIR)'

FAILNOPURPLE:
	@echo "Error: You need libpurple (2 or 3) development headers installed to be able to compile this plugin"

FAILNOLIBS:
	@echo "Error: You need GLib 2 and JSON-GLib development headers installed to be able to compile this plugin"

FAILNODISCOUNT:
	@echo "Error: You need libmarkdown (discount) development headers installed to be able to compile this plugin"

clean:
	rm -f $(MATTERMOST_TARGET) 
	rm -rf $(RPMDIR)
	rm -f $(RPMSPEC)


