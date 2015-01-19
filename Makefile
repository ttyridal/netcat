ifndef PREFIX
PREFIX=i386-mingw32-
endif

CC=$(PREFIX)gcc
STRIP=$(PREFIX)strip
LD=$(CC)

#link=link
CFLAGS=-DWIN32 -DTELNET -DGAPING_SECURITY_HOLE
LDFLAGS=-lws2_32 -lshlwapi

all: nc.exe

#getopt.obj: getopt.c
#    $(cc) $(cflags) getopt.c
#
#doexec.obj: doexec.c
#    $(cc) $(cflags) doexec.c
#
#netcat.obj: netcat.c
#    $(cc) $(cflags) netcat.c
#

nc.exe: getopt.o doexec.o netcat.o
	$(LD) $^ $(LDFLAGS) -o $@ 
	$(STRIP) $@


clean:
	-rm *.o nc.exe
