
CFLAGS = -DUNICODE -D_UNICODE
LDFLAGS = /MD advapi32.lib shell32.lib shlwapi.lib

all: nls_iconv.exe

nls_iconv.exe: nls_iconv.c
	$(CC) $(CFLAGS) $** $(LDFLAGS)
