# where fcap lives

FCAP_PATH = ../mod_janus

INCLUDE = $(FCAP_PATH)
LDPATH =   $(FCAP_PATH)

####
# no need to edit anything below here
####

OS = linux
LIBS = -lfcap
DEVEL_FLAGS = 

# This enables insecure functionality (see manual before enabling!):
# DEVEL_FLAGS = -DINSECURE_FLAGS

ifndef VERSION
	VERSION=2-alpha
endif

CC = gcc
CFLAGS = -O2 -I$(INCLUDE) -L$(LDPATH) -g -Wall -Wshadow -DLIBDIR=\"$(LIBDIR)\" -DBINDIR=\"$(BINDIR)\" $(DEVEL_FLAGS) -DVERSION=\"$(VERSION)\"
INDEX = tags 
BIN = janus 

# Important: this must NEVER be compiled with NDEBUG defined.
# We rely on the assert()-checking!

.SUFFIXES: .c .o 

HEADERS = childstate.h debug.h glob.h module.h systable.h sysxlat.h trace.h bsdstring.h
MODULES =  path.o basic.o net.o force_allow.o uid.o group.o
OBJS = main.o setup.o trace.o sysxlat.o glob.o childstate.o bsdstring.o \
	$(MODULES)

all: $(BIN) 

devel: all $(INDEX)

#code browsing stuff

tags: $(OBJS) $(MODULES)
	ctags -R * ../mod_janus/*.h

install: all
	install -d -m 755 $(BINDIR)
	install -m 755 janus $(BINDIR)

$(OBJS) : $(HEADERS)

janus: $(OBJS) 
	$(CC) $(CFLAGS) -o janus $(OBJS) $(LIBS) 

.c.o: .c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm -f *.o $(INDEX) $(BIN)
