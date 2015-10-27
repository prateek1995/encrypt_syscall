#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sys_xcrypt.h"
#include <openssl/sha.h>

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

int main(int argc, char *argv[])
{

        struct stat st_infile, st_outfile;
        int rc_in = 0, rc_out = 0;
        int rc = 0;
        struct kargs args;
        int ret = 0;
        unsigned char buf[SHA_DIGEST_LENGTH];
        args.keybuf = 0;
        args.infile = 0;
        args.outfile = 0;
        args.flags = 2;
        if(argc < 2) {
                errno = EINVAL;
                perror("Very few arguments entered. Refer to help");
                goto out;
        }

        opterr = 1, optind = 1;
        while((ret = getopt(argc, argv, "p:edh")) != -1) {
                switch(ret) {
                case 'p' :
                        if(optind <= argc || optarg == 0) {
                                if(strlen(optarg) < 6) {
                                        errno = EINVAL;
                                        perror("Passkey length is less than 6, try a passkey with length >= 6");
                                        goto out;
                                }
                                args.keybuf = malloc(SHA_DIGEST_LENGTH + 1);
                                SHA1((unsigned char *)optarg, strlen(optarg), buf);
                                args.keylen = SHA_DIGEST_LENGTH;
                                memcpy(args.keybuf, buf, SHA_DIGEST_LENGTH);

                                if(args.keybuf == 0) {
                                        errno = ENOMEM;
                                        perror("Keybuf memory allocation failed");
                                        goto out;
                                }
                        }
                        else {
                                errno = EINVAL;
                                perror("key is not provided");
                                goto out;
                        }
                        break;
                case 'e' :
                        args.flags = 1;
                        break;
                case 'd' :
                        args.flags = 0;
                        break;
                case 'h' :
                        printf("\nSyntax:\n     ./xcipher -p \"passkey\" [-e -d] infile outfile\n");
                        printf("\nDescription:\n        xcipher takes an input file and [encypts decrypts] it ");
                        printf("with SHA1 hash of passkey passed by user.\n\n");
                        printf("Options:\n      -h:     Display a help message and exit.\n");
                        printf("        -e:     encrypts the input file.\n");
                        printf("        -d:     decrypts the input file.\n");
                        printf("        -p:     next argument after this option is a passkey of at least 6 characters long used to encrypt or decrypt input file.\n");
                        printf("\nExample:\n    ./xcipher -h\n");
                        printf("        ./xcipher -p \"This is my Key\" -e input.txt output.txt\n\n");
                        goto out;
                case '?' :
                        printf("%s is not part of optstring: Unkown argument.\n", optarg);
                        goto out;
                default :
                        break;
                }
        }
        if(args.flags == 2) {
                errno = EINVAL;
                perror("Encryption/Decryption option is not provided. Refer help");
                goto out;
        }

        if(optind + 2 == argc) {
                args.infile = strdup(argv[optind]);
                if(args.infile == 0) {
                        errno = ENOMEM;
                        perror("Infile memory allocation failed");
                        goto out;
                }
                args.outfile = strdup(argv[optind + 1]);
                if(args.outfile == 0) {
                        errno = ENOMEM;
                        perror("Outfile memory allocation failed");
                        goto out;
                }
        }
        else {
                errno = EINVAL;
                perror("Input/Output file is not provided. Refer help");
                goto out;
        }

        rc_in = stat(args.infile, &st_infile);
        if(rc_in == -1) {
                printf("WARNING: %s file does not exist.\n", args.infile);
        }
        else {
                if(!(st_infile.st_mode & S_IRUSR)) {
                        printf("WARNING:%s file does not have read permission for user.\n", args.infile);
                }

                if(!S_ISREG(st_infile.st_mode)) {
                printf("WARNING:%s file is not a regular file..\n", args.infile);
                }
        }

        rc_out = stat(args.outfile, &st_outfile);
        if(rc_out != -1) {
                if(!(st_outfile.st_mode & S_IWUSR)) {
                        printf("WARNING:%s file does not have write permission for user.\n", args.outfile);
                }

                if(!S_ISREG(st_outfile.st_mode)) {
                        printf("WARNING:%s file is not a regular file..\n", args.outfile);
                }

                if(st_infile.st_ino == st_outfile.st_ino)
                        printf("WARNING: input and out file maybe same.\n");
        }

        rc = syscall(__NR_xcrypt, (void *) &args);
        if (rc == 0)
                printf("syscall returned %d\n", rc);
        else
                perror("syscall returned with error");
        out:
                if(args.keybuf)
                        free(args.keybuf);
                if(args.infile)
                        free(args.infile);
                if(args.outfile)
                        free(args.outfile);
                exit(rc);
}
                                                                                                                                                                                              154,1         Bot
