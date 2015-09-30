#this should point at where you want to install janus,
#/usr/local is probably not a bad choice

PREFIX = /usr/local

#where janus will live
export BINDIR = $(PREFIX)/sbin

#where the janus manpage will live
export MANDIR = $(PREFIX)/man/man1

#where mod_janus will live
export MODDIR = /lib/modules/`uname -r`/misc


#No need to touch stuff below this line

export VERSION = 2.0.1

all: Makefile 
	$(MAKE) -C mod_janus
	$(MAKE) -C janus

install: all
	$(MAKE) -C mod_janus install -e
	$(MAKE) -C janus install -e
	$(MAKE) -C docs install -e
clean:
	$(MAKE) -C janus clean
	$(MAKE) -C mod_janus clean
