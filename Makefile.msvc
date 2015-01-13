
cc=cl
link=link

cflags=/nologo /ML /W3 /GX /O2 /ZD /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "TELNET" /D "GAPING_SECURITY_HOLE" /YX /FD /c 
lflags=kernel32.lib user32.lib wsock32.lib winmm.lib /nologo /subsystem:console /incremental:yes /machine:I386 /debug /out:nc.exe /PDB:nc.pdb

all: nc.exe

getopt.obj: getopt.c
    $(cc) $(cflags) getopt.c

doexec.obj: doexec.c
    $(cc) $(cflags) doexec.c

netcat.obj: netcat.c
    $(cc) $(cflags) netcat.c


nc.exe: getopt.obj doexec.obj netcat.obj
    $(link) getopt.obj doexec.obj netcat.obj $(lflags)
