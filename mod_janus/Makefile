#use the following to set debug level 
#0-none
#1-more debug message,unusual condition notification, and no usage count
#2-still more debug messages

DEBUG = 0

#general

CC = gcc
LD = ld
AR = ar


#kernel module

KERNELDIR = /usr/src/linux
CFLAGS =  -I. -I../../include -I$(KERNELDIR)/include 
CFLAGS += -D__LINUX__  -DLINUX -D__KERNEL__ -DCPU=586 -DMODULE 

#Warnings 
CFLAGS += -Wall	-Wshadow -Wwrite-strings 
CFLAGS +=-DFC_DEBUG=$(DEBUG) 


#usefull/important stuff for kernel builds, -O, or -O2 needed to expand inlines
CFLAGS += -O2 -fomit-frame-pointer -fno-strength-reduce 

#added optimizations
CFLAGS += -m486 -malign-loops=2 -malign-jumps=2 -malign-functions=2  

CFLAGS += -include $(KERNELDIR)/include/linux/modversions.h 

TARGETS =  fcap.o libfcap.a watch test_getuid mod_janus.o

HEADERS = fcap.h modtools.h callnames.h fcap_kernel.h lock.h task.h
OBJS = main.o sock.o lock.o ent.o task.o

.S.o :
	$(CC) -D__ASSEMBLY__  -traditional -c $< -o $*.o

all : $(TARGETS) tags

$(OBJS) : $(HEADERS)

mod_janus.o : fcap.o
	cp fcap.o mod_janus.o

fcap.o : $(OBJS) 
	$(LD) -r $^ -o $@

#user lib

UFLAGS = -Wall -O2

libfcap.a : lib.o fcap.h fcap_kernel.h
	rm -rf $@
	$(AR) rc $@ $< 

lib.o : lib.c fcap.h fcap_kernel.h
	$(CC) $(UFLAGS) -c $< -o $@ 

#test

INTERFACE = libfcap.a fcap.h 

watch : watch.c $(INTERFACE)
	$(CC) $(UFLAGS) -L. $< -o $@ -lfcap

test_getuid : test_getuid.c
	$(CC) $(UFLAGS) $< -o $@

install : mod_janus.o
	install -d -m 755 $(MODDIR)
	install -m 644 mod_janus.o $(MODDIR)

clean:
	rm -f *.o *.s $(TARGETS) tags 

tags: $(TARGETS)
	ctags *.{c,h}
