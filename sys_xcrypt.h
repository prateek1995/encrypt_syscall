#ifndef _SYSCRYPT_H
#define _SYSCRYPT_H

struct  __attribute__((__packed__))kargs {
        char *infile;
        char *outfile;
        char *keybuf;
        unsigned int keylen;
        unsigned int flags;
};

#endif