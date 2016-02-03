// License: This file is placed in the public domain

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>
#include <tchar.h>
#include <locale.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NICE_LENGTH_OF_TEMPORARY_BUFFER 1000

#define MB_CHAR_MAX 16

#define UNICODE_MODE_BOM_DONE   1
#define UNICODE_MODE_SWAPPED    2

#define FLAG_USE_BOM            1
#define FLAG_TRANSLIT           2
#define FLAG_IGNORE             4

struct NLS_FILE_HEADER {
    WORD wSize;                     // in words 0x000D
    WORD CodePage;
    WORD MaxCharSize;               // 1 or 2
    WORD DefaultChar;
    WORD UnicodeDefaultChar;
    WORD DefaultCharWC;
    WORD UnicodeDefaultCharMB;
    BYTE LeadByte[MAX_LEADBYTES];
};

struct NLS_FILE_PRIMARY {
    WORD wSize;
    WORD PrimaryTable[256];
};

struct NLS_FILE_OEM {
    WORD OEMTableSize;
    WORD OEMTable[256];
};

struct NLS_FILE_DBCS {
    WORD DBCSTableSize;
    WORD DBCSTableOffset[256];
    WORD DBCSTable[256][256];       // WORD[DBCSTableSize][256]
                                    // DBCSTable[(DBCSTableOffset[hi] / 256) - 1][lo]
};

struct NLS_FILE_UNICODE {
    WORD Unknown;
    union {
        BYTE UnicodeTableByte[65536];
        WORD UnicodeTableWord[65536];
    };
};

struct NLS_FILE {
    void *data;
    size_t size;
    struct NLS_FILE_HEADER *header;
    struct NLS_FILE_PRIMARY *primary;
    struct NLS_FILE_OEM *oem;
    struct NLS_FILE_DBCS *dbcs;
    struct NLS_FILE_UNICODE *unicode;
};

typedef void* iconv_t;

typedef struct csconv_t csconv_t;
typedef struct rec_iconv_t rec_iconv_t;


typedef int (*f_mbtowc)(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize);
typedef int (*f_wctomb)(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize);
typedef int (*f_mblen)(csconv_t *cv, const uint8_t *buf, int bufsize);
typedef int (*f_flush)(csconv_t *cv, uint8_t *buf, int bufsize);

struct csconv_t {
    int codepage;
    int flags;
    f_mbtowc mbtowc;
    f_wctomb wctomb;
    f_mblen mblen;
    f_flush flush;
    DWORD mode;
    struct NLS_FILE nls;
};

struct rec_iconv_t {
    csconv_t from;
    csconv_t to;
};

iconv_t iconv_open(const _TCHAR *tocode, const _TCHAR *fromcode);
int iconv_close(iconv_t _cd);
size_t iconv(iconv_t _cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
static int nls_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize);
static int nls_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize);
static bool utf8_checkbyte(uint8_t c);
static int utf8_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize);
static int utf8_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize);
static int utf16_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize);
static int utf16_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize);
static int utf32_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize);
static int utf32_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize);
static uint32_t utf16_to_ucs4(const uint16_t *wbuf);
static void ucs4_to_utf16(uint32_t wc, uint16_t *wbuf, int *wbufsize);
static bool make_csconv(const _TCHAR *name, csconv_t *cv);
static bool endswith(_TCHAR *a, _TCHAR *b);
static size_t fsize(FILE *f);
static void *readfile(_TCHAR *path, size_t *psize);
static bool readnlsfile(_TCHAR *path, struct NLS_FILE *nls);
static _TCHAR *nlspath(const _TCHAR *cpname);
static void print_system_error(DWORD errcode);
static int list_codepage();
static int usage();

iconv_t iconv_open(const _TCHAR *tocode, const _TCHAR *fromcode)
{
    rec_iconv_t *cd;

    cd = calloc(1, sizeof(rec_iconv_t));
    if (cd == NULL)
        return (iconv_t)-1;

    if (!make_csconv(tocode, &cd->to) || !make_csconv(fromcode, &cd->from)) {
        if (cd->to.nls.data != NULL)
            free(cd->to.nls.data);
        if (cd->from.nls.data != NULL)
            free(cd->from.nls.data);
        free(cd);
        return (iconv_t)-1;
    }

    return cd;
}

int iconv_close(iconv_t _cd)
{
    rec_iconv_t *cd = (rec_iconv_t *)_cd;

    if (cd->to.nls.data != NULL)
        free(cd->to.nls.data);
    if (cd->from.nls.data != NULL)
        free(cd->from.nls.data);
    free(cd);

    return 0;
}

size_t iconv(iconv_t _cd, const char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
    rec_iconv_t *cd = (rec_iconv_t *)_cd;
    uint16_t wbuf[MB_CHAR_MAX]; /* enough room for one character */
    int insize;
    int outsize;
    int wsize;
    DWORD frommode;
    DWORD tomode;
    uint32_t wc;
    int i;

    if (inbuf == NULL || *inbuf == NULL)
    {
        if (outbuf != NULL && *outbuf != NULL && cd->to.flush != NULL)
        {
            tomode = cd->to.mode;
            outsize = cd->to.flush(&cd->to, (uint8_t *)*outbuf, *outbytesleft);
            if (outsize == -1)
            {
                if ((cd->to.flags & FLAG_IGNORE) && errno != E2BIG)
                {
                    outsize = 0;
                }
                else
                {
                    cd->to.mode = tomode;
                    return (size_t)(-1);
                }
            }
            *outbuf += outsize;
            *outbytesleft -= outsize;
        }
        cd->from.mode = 0;
        cd->to.mode = 0;
        return 0;
    }

    while (*inbytesleft != 0)
    {
        frommode = cd->from.mode;
        tomode = cd->to.mode;
        wsize = MB_CHAR_MAX;

        insize = cd->from.mbtowc(&cd->from, (const uint8_t *)*inbuf, *inbytesleft, wbuf, &wsize);
        if (insize == -1)
        {
            if (cd->to.flags & FLAG_IGNORE)
            {
                cd->from.mode = frommode;
                insize = 1;
                wsize = 0;
            }
            else
            {
                cd->from.mode = frommode;
                return (size_t)(-1);
            }
        }

        if (wsize == 0)
        {
            *inbuf += insize;
            *inbytesleft -= insize;
            continue;
        }

        outsize = cd->to.wctomb(&cd->to, wbuf, wsize, (uint8_t *)*outbuf, *outbytesleft);
        if (outsize == -1)
        {
            if ((cd->to.flags & FLAG_IGNORE) && errno != E2BIG)
            {
                cd->to.mode = tomode;
                outsize = 0;
            }
            else
            {
                cd->from.mode = frommode;
                cd->to.mode = tomode;
                return (size_t)(-1);
            }
        }

        *inbuf += insize;
        *outbuf += outsize;
        *inbytesleft -= insize;
        *outbytesleft -= outsize;
    }

    return 0;
}

static int nls_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize)
{
    uint16_t mb;
    int len;

    if (cv->nls.header->MaxCharSize == 1 || cv->nls.dbcs->DBCSTableOffset[buf[0]] == 0) {
        len = 1;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        mb = buf[0];
        wbuf[0] = cv->nls.primary->PrimaryTable[buf[0]];
        if (wbuf[0] == cv->nls.header->UnicodeDefaultChar && mb != cv->nls.header->UnicodeDefaultCharMB) {
            errno = EILSEQ;
            return -1;
        }
        *wbufsize = 1;
    } else {
        len = 2;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        mb = (buf[0] << 8) | buf[1];
        wbuf[0] = cv->nls.dbcs->DBCSTable[(cv->nls.dbcs->DBCSTableOffset[buf[0]] / 256) - 1][buf[1]];
        if (wbuf[0] == cv->nls.header->UnicodeDefaultChar && mb != cv->nls.header->UnicodeDefaultCharMB) {
            errno = EILSEQ;
            return -1;
        }
        *wbufsize = 1;
    }
    return len;
}

static int nls_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize)
{
    uint32_t wc;
    uint16_t mb;
    int len;

    wc = utf16_to_ucs4(wbuf);
    if (wc > 0xFFFF) {
        errno = EILSEQ;
        return -1;
    }

    if (cv->nls.header->MaxCharSize == 1)
        mb = cv->nls.unicode->UnicodeTableByte[wc];
    else
        mb = cv->nls.unicode->UnicodeTableWord[wc];

    if (mb == cv->nls.header->DefaultChar && wc == cv->nls.header->DefaultCharWC) {
        errno = EILSEQ;
        return -1;
    }

    if (mb & 0xFF00) {
        len = 2;
        if (bufsize < len) {
            errno = E2BIG;
            return -1;
        }
        buf[0] = (mb >> 8) & 0xFF;
        buf[1] = mb & 0xFF;
    } else {
        len = 1;
        if (bufsize < len) {
            errno = E2BIG;
            return -1;
        }
        buf[0] = mb;
    }

    return len;
}

static bool utf8_checkbyte(uint8_t c)
{
    return c >= 0x80 && ((c - 0x80) < 0x40);
}

static int utf8_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize)
{
    int32_t wc;
    int len;

    if (buf[0] < 0x80) {
        len = 1;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        wc = buf[0];
    } else if ((buf[0] & 0xE0) == 0xC0) {
        len = 2;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        if (!utf8_checkbyte(buf[1])) {
            errno = EILSEQ;
            return -1;
        }
        wc = ((buf[0] & 0x1F) << 6)
            | buf[1] & 0x3F;
    } else if ((buf[0] & 0xF0) == 0xE0) {
        len = 3;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        if (!( utf8_checkbyte(buf[1])
                    && utf8_checkbyte(buf[2])
                    && (buf[0] >= 0xE1 || buf[1] >= 0xA0) )) {
            errno = EILSEQ;
            return -1;
        }
        wc = ((buf[0] & 0xF) << 12)
            | ((buf[1] & 0x3F) << 6)
            | (buf[2] & 0x3F);
    } else if ((buf[0] & 0xF8) == 0xF0) {
        len = 4;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        if (!( utf8_checkbyte(buf[1])
                    && utf8_checkbyte(buf[2])
                    && utf8_checkbyte(buf[3])
                    && (buf[0] >= 0xF1 || buf[1] >= 0x90) )) {
            errno = EILSEQ;
            return -1;
        }
        wc = ((buf[0] & 0x7) << 18)
            | ((buf[1] & 0x3F) << 12)
            | ((buf[2] & 0x3F) << 6)
            | (buf[3] & 0x3F);
    } else if ((buf[0] & 0xFC) == 0xF8) {
        len = 5;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        if (!( utf8_checkbyte(buf[1])
                    && utf8_checkbyte(buf[2])
                    && utf8_checkbyte(buf[3])
                    && utf8_checkbyte(buf[4])
                    && (buf[0] >= 0xF9 || buf[1] >= 0x88) )) {
            errno = EILSEQ;
            return -1;
        }
        wc = ((buf[0] & 0x3) << 24)
            | ((buf[1] & 0x3F) << 18)
            | ((buf[2] & 0x3F) << 12)
            | ((buf[3] & 0x3F) << 6)
            | (buf[4] & 0x3F);
    } else if ((buf[0] & 0xFE) == 0xFC) {
        len = 6;
        if (bufsize < len) {
            errno = EINVAL;
            return -1;
        }
        if (!( utf8_checkbyte(buf[1])
                    && utf8_checkbyte(buf[2])
                    && utf8_checkbyte(buf[3])
                    && utf8_checkbyte(buf[4])
                    && utf8_checkbyte(buf[5])
                    && (buf[0] >= 0xFD || buf[1] >= 0x84) )) {
            errno = EILSEQ;
            return -1;
        }
        wc = ((buf[0] & 0x1) << 30)
            | ((buf[1] & 0x3F) << 24)
            | ((buf[2] & 0x3F) << 18)
            | ((buf[3] & 0x3F) << 12)
            | ((buf[4] & 0x3F) << 6)
            | (buf[5] & 0x3F);
    } else {
        errno = EILSEQ;
        return -1;
    }

    ucs4_to_utf16(wc, wbuf, wbufsize);

    return len;
}

static int utf8_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize)
{
    uint32_t wc;
    int len = 0;
    int i;

    wc = utf16_to_ucs4(wbuf);

    if (wc < 0x80)
        len = 1;
    else if (wc < 0x800)
        len = 2;
    else if (wc < 0x10000)
        len = 3;
    else if (wc < 0x200000)
        len = 4;
    else if (wc < 0x4000000)
        len = 5;
    else if (wc <= 0x7fffffff)
        len = 6;

    if (len == 0) {
        errno = EILSEQ;
        return -1;
    } else if (bufsize < len) {
        errno = E2BIG;
        return -1;
    }

    i = len;
    if (i >= 6) {
        buf[--i] = 0x80 | (wc & 0x3F);
        wc = (wc >> 6) | 0x4000000;
    }
    if (i >= 5) {
        buf[--i] = 0x80 | (wc & 0x3F);
        wc = (wc >> 6) | 0x200000;
    }
    if (i >= 4) {
        buf[--i] = 0x80 | (wc & 0x3F);
        wc = (wc >> 6) | 0x10000;
    }
    if (i >= 3) {
        buf[--i] = 0x80 | (wc & 0x3F);
        wc = (wc >> 6) | 0x800;
    }
    if (i >= 2) {
        buf[--i] = 0x80 | (wc & 0x3F);
        wc = (wc >> 6) | 0xC0;
    }
    buf[0] = wc;

    return len;
}

static int utf16_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize)
{
    int codepage = cv->codepage;

    /* swap endian: 1200 <-> 1201 */
    if (cv->mode & UNICODE_MODE_SWAPPED)
        codepage ^= 1;

    if (bufsize < 2) {
        errno = EINVAL;
        return -1;
    }
    if (codepage == 1200) /* little endian */
        wbuf[0] = (buf[1] << 8) | buf[0];
    else if (codepage == 1201) /* big endian */
        wbuf[0] = (buf[0] << 8) | buf[1];

    if ((cv->flags & FLAG_USE_BOM) && !(cv->mode & UNICODE_MODE_BOM_DONE))
    {
        cv->mode |= UNICODE_MODE_BOM_DONE;
        if (wbuf[0] == 0xFFFE)
        {
            cv->mode |= UNICODE_MODE_SWAPPED;
            *wbufsize = 0;
            return 2;
        }
        else if (wbuf[0] == 0xFEFF)
        {
            *wbufsize = 0;
            return 2;
        }
    }

    if (0xDC00 <= wbuf[0] && wbuf[0] <= 0xDFFF) {
        errno = EILSEQ;
        return -1;
    }
    if (0xD800 <= wbuf[0] && wbuf[0] <= 0xDBFF)
    {
        if (bufsize < 4) {
            errno = EINVAL;
            return -1;
        }
        if (codepage == 1200) /* little endian */
            wbuf[1] = (buf[3] << 8) | buf[2];
        else if (codepage == 1201) /* big endian */
            wbuf[1] = (buf[2] << 8) | buf[3];
        if (!(0xDC00 <= wbuf[1] && wbuf[1] <= 0xDFFF)) {
            errno = EILSEQ;
            return -1;
        }
        *wbufsize = 2;
        return 4;
    }
    *wbufsize = 1;
    return 2;
}

static int utf16_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize)
{
    if ((cv->flags & FLAG_USE_BOM) && !(cv->mode & UNICODE_MODE_BOM_DONE))
    {
        int r;

        cv->mode |= UNICODE_MODE_BOM_DONE;
        if (bufsize < 2) {
            errno = E2BIG;
            return -1;
        }
        if (cv->codepage == 1200) /* little endian */
            memcpy(buf, "\xFF\xFE", 2);
        else if (cv->codepage == 1201) /* big endian */
            memcpy(buf, "\xFE\xFF", 2);

        r = utf16_wctomb(cv, wbuf, wbufsize, buf + 2, bufsize - 2);
        if (r == -1)
            return -1;
        return r + 2;
    }

    if (bufsize < 2) {
        errno = E2BIG;
        return -1;
    }
    if (cv->codepage == 1200) /* little endian */
    {
        buf[0] = (wbuf[0] & 0x00FF);
        buf[1] = (wbuf[0] & 0xFF00) >> 8;
    }
    else if (cv->codepage == 1201) /* big endian */
    {
        buf[0] = (wbuf[0] & 0xFF00) >> 8;
        buf[1] = (wbuf[0] & 0x00FF);
    }
    if (0xD800 <= wbuf[0] && wbuf[0] <= 0xDBFF)
    {
        if (bufsize < 4) {
            errno = E2BIG;
            return -1;
        }
        if (cv->codepage == 1200) /* little endian */
        {
            buf[2] = (wbuf[1] & 0x00FF);
            buf[3] = (wbuf[1] & 0xFF00) >> 8;
        }
        else if (cv->codepage == 1201) /* big endian */
        {
            buf[2] = (wbuf[1] & 0xFF00) >> 8;
            buf[3] = (wbuf[1] & 0x00FF);
        }
        return 4;
    }
    return 2;
}

static int utf32_mbtowc(csconv_t *cv, const uint8_t *buf, int bufsize, uint16_t *wbuf, int *wbufsize)
{
    int codepage = cv->codepage;
    uint32_t wc = 0xD800;

    /* swap endian: 12000 <-> 12001 */
    if (cv->mode & UNICODE_MODE_SWAPPED)
        codepage ^= 1;

    if (bufsize < 4) {
        errno = EINVAL;
        return -1;
    }
    if (codepage == 12000) /* little endian */
        wc = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
    else if (codepage == 12001) /* big endian */
        wc = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

    if ((cv->flags & FLAG_USE_BOM) && !(cv->mode & UNICODE_MODE_BOM_DONE))
    {
        cv->mode |= UNICODE_MODE_BOM_DONE;
        if (wc == 0xFFFE0000)
        {
            cv->mode |= UNICODE_MODE_SWAPPED;
            *wbufsize = 0;
            return 4;
        }
        else if (wc == 0x0000FEFF)
        {
            *wbufsize = 0;
            return 4;
        }
    }

    if ((0xD800 <= wc && wc <= 0xDFFF) || 0x10FFFF < wc) {
        errno = EILSEQ;
        return -1;
    }
    ucs4_to_utf16(wc, wbuf, wbufsize);
    return 4;
}

static int utf32_wctomb(csconv_t *cv, uint16_t *wbuf, int wbufsize, uint8_t *buf, int bufsize)
{
    uint32_t wc;

    if ((cv->flags & FLAG_USE_BOM) && !(cv->mode & UNICODE_MODE_BOM_DONE))
    {
        int r;

        cv->mode |= UNICODE_MODE_BOM_DONE;
        if (bufsize < 4) {
            errno = E2BIG;
            return -1;
        }
        if (cv->codepage == 12000) /* little endian */
            memcpy(buf, "\xFF\xFE\x00\x00", 4);
        else if (cv->codepage == 12001) /* big endian */
            memcpy(buf, "\x00\x00\xFE\xFF", 4);

        r = utf32_wctomb(cv, wbuf, wbufsize, buf + 4, bufsize - 4);
        if (r == -1)
            return -1;
        return r + 4;
    }

    if (bufsize < 4) {
        errno = E2BIG;
        return -1;
    }
    wc = utf16_to_ucs4(wbuf);
    if (cv->codepage == 12000) /* little endian */
    {
        buf[0] = wc & 0x000000FF;
        buf[1] = (wc & 0x0000FF00) >> 8;
        buf[2] = (wc & 0x00FF0000) >> 16;
        buf[3] = (wc & 0xFF000000) >> 24;
    }
    else if (cv->codepage == 12001) /* big endian */
    {
        buf[0] = (wc & 0xFF000000) >> 24;
        buf[1] = (wc & 0x00FF0000) >> 16;
        buf[2] = (wc & 0x0000FF00) >> 8;
        buf[3] = wc & 0x000000FF;
    }
    return 4;
}

static uint32_t utf16_to_ucs4(const uint16_t *wbuf)
{
    uint32_t wc = wbuf[0];
    if (0xD800 <= wbuf[0] && wbuf[0] <= 0xDBFF)
        wc = ((wbuf[0] & 0x3FF) << 10) + (wbuf[1] & 0x3FF) + 0x10000;
    return wc;
}

static void ucs4_to_utf16(uint32_t wc, uint16_t *wbuf, int *wbufsize)
{
    if (wc < 0x10000)
    {
        wbuf[0] = wc;
        *wbufsize = 1;
    }
    else
    {
        wc -= 0x10000;
        wbuf[0] = 0xD800 | ((wc >> 10) & 0x3FF);
        wbuf[1] = 0xDC00 | (wc & 0x3FF);
        *wbufsize = 2;
    }
}

static bool make_csconv(const _TCHAR *name, csconv_t *cv)
{
    _TCHAR *path;

    memset((void *)cv, 0, sizeof(csconv_t));

    if (_tcscmp(name, _T("65001")) == 0) {
        // UTF-8
        cv->codepage = 65001;
        cv->mbtowc = utf8_mbtowc;
        cv->wctomb = utf8_wctomb;
        return true;
    } else if (_tcscmp(name, _T("1200")) == 0) {
        // UTF-16LE
        cv->codepage = 1200;
        cv->mbtowc = utf16_mbtowc;
        cv->wctomb = utf16_wctomb;
        cv->flags = FLAG_USE_BOM;
        return true;
    } else if (_tcscmp(name, _T("1201")) == 0) {
        // UTF-16BE
        cv->codepage = 1201;
        cv->mbtowc = utf16_mbtowc;
        cv->wctomb = utf16_wctomb;
        cv->flags = FLAG_USE_BOM;
        return true;
    } else if (_tcscmp(name, _T("12000")) == 0) {
        // UTF-32LE
        cv->codepage = 12000;
        cv->mbtowc = utf32_mbtowc;
        cv->wctomb = utf32_wctomb;
        cv->flags = FLAG_USE_BOM;
        return true;
    } else if (_tcscmp(name, _T("12001")) == 0) {
        // UTF-32BE
        cv->codepage = 12001;
        cv->mbtowc = utf32_mbtowc;
        cv->wctomb = utf32_wctomb;
        cv->flags = FLAG_USE_BOM;
        return true;
    } else {
        cv->codepage = _tstoi(name);
        if (cv->codepage == 0)
            return false;
        path = nlspath(name);
        if (path == NULL)
            return false;
        if (!readnlsfile(path, &cv->nls))
            return false;
        cv->mbtowc = nls_mbtowc;
        cv->wctomb = nls_wctomb;
        return true;
    }
}

static bool endswith(_TCHAR *base, _TCHAR *part)
{
    _TCHAR *b = base + _tcslen(base);
    _TCHAR *p = part + _tcslen(part);
    while (base <= b && part <= p && b[0] == p[0]) {
        --b;
        --p;
    }
    return (p < part);
}

static size_t fsize(FILE *f)
{
    struct _stat64 st;

    if (_fstat64(_fileno(f), &st) != 0)
        return (size_t)-1;

    return st.st_size;
}

static void *readfile(_TCHAR *path, size_t *psize)
{
    FILE *f;
    size_t size;
    void *p;

    f = _tfopen(path, _T("rb"));
    if (f == NULL)
        return NULL;

    size = fsize(f);
    if (size == (size_t)-1) {
        fclose(f);
        return NULL;
    }

    p = calloc(size, sizeof(char));
    if (p == NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(p, sizeof(char), size, f) != size) {
        fclose(f);
        free(p);
        return NULL;
    }

    if (psize != NULL)
        *psize = size;

    return p;
}

static bool readnlsfile(_TCHAR *path, struct NLS_FILE *nls)
{
    nls->data = readfile(path, &nls->size);
    if (nls->data == NULL)
        return false;

    nls->header = (struct NLS_FILE_HEADER*)(nls->data);
    nls->primary = (struct NLS_FILE_PRIMARY *)((WORD *)nls->header + nls->header->wSize);
    nls->oem = (struct NLS_FILE_OEM *)((WORD *)nls->primary + 1 + 256);
    nls->dbcs = (struct NLS_FILE_DBCS *)((WORD *)nls->oem + 1 + nls->oem->OEMTableSize);
    nls->unicode = (struct NLS_FILE_UNICODE *)((WORD *)nls->primary + nls->primary->wSize);

    return true;
}

// C:\Windows\System32\C_<CODEPAGE>.nls
static _TCHAR *nlspath(const _TCHAR *cpname)
{
    HKEY hKey;
    DWORD SubKeys;
    DWORD MaxSubKeyLen;
    DWORD Values;
    DWORD MaxValueNameLen;
    _TCHAR Name[NICE_LENGTH_OF_TEMPORARY_BUFFER];
    DWORD NameSize;
    DWORD ValueType;
    _TCHAR Value[NICE_LENGTH_OF_TEMPORARY_BUFFER];
    DWORD ValueSize;
    DWORD r;
    int i;
    _TCHAR system32[NICE_LENGTH_OF_TEMPORARY_BUFFER];
    static _TCHAR path[NICE_LENGTH_OF_TEMPORARY_BUFFER];

    if (!SHGetSpecialFolderPath(NULL, system32, CSIDL_SYSTEM, FALSE))
        return NULL;

    r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"), 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        return NULL;
    }

    r = SHQueryInfoKey(hKey, &SubKeys, &MaxSubKeyLen, &Values, &MaxValueNameLen);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return NULL;
    }

    for (i = 0; i < Values; ++i) {
        NameSize = NICE_LENGTH_OF_TEMPORARY_BUFFER;
        ValueSize = NICE_LENGTH_OF_TEMPORARY_BUFFER;
        r = SHEnumValue(hKey, i, Name, &NameSize, &ValueType, Value, &ValueSize);
        if (r != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return NULL;
        }
        if (_tcscmp(Name, cpname) == 0 && endswith(Value, _T(".nls"))) {
            RegCloseKey(hKey);
            _stprintf(path, _T("%s\\%s"), system32, Value);
            return path;
        }
    }

    r = RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) {
        return NULL;
    }

    return NULL;
}

static void print_system_error(DWORD errcode)
{
    LPVOID lpMessageBuffer;

    if (FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            errcode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMessageBuffer,
            0,
            NULL) == 0)
    {
        _ftprintf(stderr, _T("FormatMessage() failed\n"));
        return;
    }

    _ftprintf(stderr, _T("%s\n"), (_TCHAR *)lpMessageBuffer);

    LocalFree(lpMessageBuffer);
}

// print codepage which have .nls file
static int list_codepage()
{
    HKEY hKey;
    DWORD SubKeys;
    DWORD MaxSubKeyLen;
    DWORD Values;
    DWORD MaxValueNameLen;
    _TCHAR Name[NICE_LENGTH_OF_TEMPORARY_BUFFER];
    DWORD NameSize;
    DWORD ValueType;
    _TCHAR Value[NICE_LENGTH_OF_TEMPORARY_BUFFER];
    DWORD ValueSize;
    DWORD r;
    int i;

    r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"), 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        print_system_error(r);
        return 1;
    }

    r = SHQueryInfoKey(hKey, &SubKeys, &MaxSubKeyLen, &Values, &MaxValueNameLen);
    if (r != ERROR_SUCCESS) {
        print_system_error(r);
        RegCloseKey(hKey);
        return 1;
    }

    for (i = 0; i < Values; ++i) {
        NameSize = NICE_LENGTH_OF_TEMPORARY_BUFFER;
        ValueSize = NICE_LENGTH_OF_TEMPORARY_BUFFER;
        r = SHEnumValue(hKey, i, Name, &NameSize, &ValueType, Value, &ValueSize);
        if (r != ERROR_SUCCESS) {
            print_system_error(r);
            RegCloseKey(hKey);
            return 1;
        }
        if (endswith(Value, _T(".nls")))
            _tprintf(_T("%s\n"), Name);
    }

    r = RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) {
        print_system_error(r);
        return 1;
    }

    // additional codepage
    _tprintf(_T("1200\n"));
    _tprintf(_T("1201\n"));
    _tprintf(_T("12000\n"));
    _tprintf(_T("12001\n"));
    _tprintf(_T("65001\n"));

    return 0;
}

int usage()
{
    _tprintf(_T("nls_iconv [-l] -f fromcodepage -t tocodepage [-o outputfile] [inputfile]\n"));
    _tprintf(_T("  --help, -h       show help\n"));
    _tprintf(_T("  --list, -l       list codepage\n"));
    _tprintf(_T("  --from-code, -f  from codepage\n"));
    _tprintf(_T("  --to-code, -t    to codepage\n"));
    _tprintf(_T("  --output, -o     outputfile (default: stdout)\n"));
    _tprintf(_T("  inputfile        inputfile (default: stdin)\n"));
    return 0;
}

int _tmain(int argc, _TCHAR **argv)
{
    _TCHAR *fromcode = NULL;
    _TCHAR *tocode = NULL;
    char inbuf[BUFSIZ];
    char outbuf[BUFSIZ];
    const char *pin;
    char *pout;
    size_t inbytesleft;
    size_t outbytesleft;
    size_t rest = 0;
    iconv_t cd;
    size_t r;
    FILE *in = stdin;
    FILE *out = stdout;

    _tsetlocale(LC_ALL, _T(""));

    if (argc == 1) {
        return usage();
    }

    for (int i = 1; i < argc; ++i) {
        if (_tcscmp(argv[i], _T("--help")) == 0 || _tcscmp(argv[i], _T("-h")) == 0) {
            return usage();
        } else if (_tcscmp(argv[i], _T("--list")) == 0 || _tcscmp(argv[i], _T("-l")) == 0) {
            return list_codepage();
        } else if (_tcscmp(argv[i], _T("--from-code")) == 0 || _tcscmp(argv[i], _T("-f")) == 0) {
            if (++i >= argc)
                return usage();
            fromcode = argv[i];
        } else if (_tcscmp(argv[i], _T("--to-code")) == 0 || _tcscmp(argv[i], _T("-t")) == 0) {
            if (++i >= argc)
                return usage();
            tocode = argv[i];
        } else if (_tcscmp(argv[i], _T("--output")) == 0 || _tcscmp(argv[i], _T("-o")) == 0) {
            if (++i >= argc)
                return usage();
            out = _tfopen(argv[i], _T("wb"));
            if (out == NULL) {
                _ftprintf(stderr, _T("cannot open %s\n"), argv[i]);
            }
        } else if (argv[i][0] == _T('-')) {
            return usage();
        } else {
            in = _tfopen(argv[i], _T("rb"));
            if (in == NULL) {
                _ftprintf(stderr, _T("cannot open %s\n"), argv[i]);
                return 1;
            }
        }
    }

    if (tocode == NULL || fromcode == NULL)
        return usage();

    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);

    cd = iconv_open(tocode, fromcode);
    if (cd == (iconv_t)(-1))
    {
        _tperror(_T("iconv_open error"));
        return 1;
    }

    while ((inbytesleft = fread(inbuf + rest, 1, sizeof(inbuf) - rest, in)) != 0 || rest != 0)
    {
        inbytesleft += rest;
        pin = inbuf;
        pout = outbuf;
        outbytesleft = sizeof(outbuf);
        r = iconv(cd, &pin, &inbytesleft, &pout, &outbytesleft);
        fwrite(outbuf, 1, sizeof(outbuf) - outbytesleft, out);
        if (r == (size_t)(-1) && errno != E2BIG && (errno != EINVAL || feof(in)))
        {
            _tperror(_T("conversion error"));
            return 1;
        }
        memmove(inbuf, pin, inbytesleft);
        rest = inbytesleft;
    }
    pout = outbuf;
    outbytesleft = sizeof(outbuf);
    r = iconv(cd, NULL, NULL, &pout, &outbytesleft);
    fwrite(outbuf, 1, sizeof(outbuf) - outbytesleft, out);
    if (r == (size_t)(-1))
    {
        _tperror(_T("conversion error"));
        return 1;
    }

    iconv_close(cd);

    return 0;
}

