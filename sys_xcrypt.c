#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include "sys_xcrypt.h"
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>

#define HEADER_SIZE 20
#define HASH_LEN 20

asmlinkage extern long (*sysptr)(void *arg);

/*
 * decrypt - Decrypt a file
 * @infile: input file that need to be decrypted
 * @outfile: decrypted file
 * @keybuf: key used for decryption
 *
 * The decrypt() checks if symmetric key used for encrypting the file is same as key being used for decryption.
 * If key is same, it will decrypt the input file using ctr(aes), otherwise returns the error.
 *
 *
 */

int decrypt(const char* infile, const char* outfile, char *keybuf) {
        struct file *fp_infile = 0, *fp_outfile = 0, *fp_tempfile = 0;
        struct kstat stat_s;
        char *buf = 0;
        mm_segment_t oldfs_status;
        int err = 0;
        size_t len = PAGE_SIZE;
        size_t numbytes_read = PAGE_SIZE, numbytes_written = 0;
        char *temp_file = 0;
        int v_ret = 0;
        /*
         * Data Structures for SHA1 hash
         */
        struct scatterlist sg;
        struct hash_desc desc_hash;
        char *hashtext = 0;
        char *hashbuf = 0;

        char cipher[] = "ctr(aes)";
        unsigned char *dst = 0;
        size_t blk_len = 16;
        int ret = 0;
        struct blkcipher_desc desc_cipher;
        struct scatterlist src_sg;
        struct scatterlist dst_sg;
        size_t dst_size = PAGE_SIZE;

        fp_infile = filp_open(infile, O_RDONLY, 0);

        if (!fp_infile || IS_ERR(fp_infile)) {
                err = PTR_ERR(fp_infile);
                goto out_infile;
        }

        if(!fp_infile->f_op->read) {
                err = -EPERM;
                goto out_infile;
        }

        oldfs_status = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_stat (infile, &stat_s);
        set_fs(oldfs_status);

        if(ret < 0) {
                err = -EPERM;
                goto out_infile;
        }

        if(!(stat_s.mode & S_IRUSR)) {
                err = -EPERM;
                goto out_infile;
        }

        if(!S_ISREG(fp_infile->f_inode->i_mode)) {
                err = -EINVAL;
                goto out_infile;
        }

        fp_outfile = filp_open(outfile, O_WRONLY, 0);

        if (!fp_outfile || IS_ERR(fp_outfile)) {
                ;
                /* Output file does not exist. Do nothing.*/
        }
        else {
                if(!fp_outfile->f_op->write) {
                        err = -EPERM;
                        goto out_outfile;
                        }

                oldfs_status = get_fs();
                set_fs(KERNEL_DS);
                ret = vfs_stat (outfile, &stat_s);
                set_fs(oldfs_status);

                if(ret < 0) {
                        err = -EPERM;
                        goto out_outfile;
                }

                if(!(stat_s.mode & S_IWUSR)) {
                        err = -EPERM;
                        goto out_outfile;
                }

                if((fp_infile->f_inode->i_ino == fp_outfile->f_inode->i_ino) && (fp_infile->f_inode->i_sb->s_type->name == fp_outfile->f_inode->i_sb->s_type->name) ) {
                        err = -EINVAL;
                        goto out_outfile;
                }

                filp_close(fp_outfile, NULL);
                fp_outfile = 0;
        }

        fp_infile->f_pos = 0;

        hashtext = kmalloc(HASH_LEN + 1, GFP_KERNEL);
        if(!hashtext) {
                err = -ENOMEM;
                goto out_tempfile;
        }

        hashbuf = kmalloc(HASH_LEN, GFP_KERNEL);
        if(!hashbuf) {
                err = -ENOMEM;
                goto out_hashtext;
        }

        sg_init_one(&sg, keybuf, HASH_LEN);

        desc_hash.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
        if (!desc_hash.tfm)   {
                err = -ENOMEM;
                goto out_hashbuf;
        }

        crypto_hash_init(&desc_hash);
        crypto_hash_update(&desc_hash, &sg, HASH_LEN);
        crypto_hash_final(&desc_hash, hashtext);
        crypto_free_hash(desc_hash.tfm);

        oldfs_status = get_fs();
        set_fs(KERNEL_DS);

        numbytes_read = vfs_read(fp_infile, hashbuf, HASH_LEN, &fp_infile->f_pos);
        set_fs(oldfs_status);
        if(numbytes_read == 0) {
                err = -EINVAL;
                goto out_hashbuf;
        }

        if(strncmp(hashbuf, hashtext, HASH_LEN) != 0) {
                err = -EINVAL;
                goto out_hashbuf;
        }

        kfree(hashbuf);
        hashbuf = 0;
        kfree(hashtext);
        hashtext = 0;

        temp_file = (char *) kmalloc(strlen(outfile) + 5, GFP_KERNEL);
        if(!temp_file) {
                err = -ENOMEM;
                goto out_outfile;
        }

        strcpy(temp_file, outfile);
        strncat(temp_file, ".tmp", 4);
        temp_file[strlen(temp_file)] = '\0';
        fp_tempfile = filp_open(temp_file, O_WRONLY | O_CREAT, fp_infile->f_inode->i_mode | S_IWUSR);

        if (!fp_tempfile || IS_ERR(fp_tempfile)) {
                err = PTR_ERR(fp_tempfile);
                goto out_tempfile;
        }

        if(!fp_tempfile->f_op->write) {
                err = -EPERM;
                goto out_tempfile;
        }
        fp_tempfile->f_pos = 0;

        numbytes_read = PAGE_SIZE;

        while(numbytes_read != 0) {
                buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
                if(!buf) {
                        err = -ENOMEM;
                        goto out_tempfile;
                }
                dst = kmalloc(PAGE_SIZE, GFP_KERNEL);
                if (!dst) {
                        err = -ENOMEM;
                        goto out_buf;
                }

                oldfs_status = get_fs();
                set_fs(KERNEL_DS);
                numbytes_read = vfs_read(fp_infile, buf, len, &fp_infile->f_pos);

                if(numbytes_read != 0) {
                        dst_size = numbytes_read;
                        desc_cipher.tfm = crypto_alloc_blkcipher(cipher, 0, CRYPTO_ALG_ASYNC);
                        if (!desc_cipher.tfm)   {
                                err = -ENOMEM;
                                goto out_unlink;
                        }

                        desc_cipher.flags = 0;
                        if(crypto_blkcipher_setkey(desc_cipher.tfm, keybuf, blk_len) < 0) {
                                err = -EINVAL;
                                crypto_free_blkcipher(desc_cipher.tfm);
                                goto out_unlink;
                        }

                        sg_init_one(&src_sg, buf, dst_size);
                        sg_init_one(&dst_sg, dst, dst_size);
                        ret = crypto_blkcipher_decrypt(&desc_cipher, &dst_sg, &src_sg, dst_size);

                        if (ret < 0) {
                                err = -EINVAL;
                                crypto_free_blkcipher(desc_cipher.tfm);
                                goto out_unlink;
                        }

                        numbytes_written = vfs_write(fp_tempfile, dst, dst_size, &fp_tempfile->f_pos);
                        crypto_free_blkcipher(desc_cipher.tfm);
                        if(numbytes_written == 0) {
                                err = -EINVAL;
                                goto out_unlink;
                        }
                }

                set_fs(oldfs_status);
                kfree(dst);
                dst = NULL;
                kfree(buf);
                buf = NULL;
                }

        fp_outfile = filp_open(outfile, O_WRONLY | O_CREAT, fp_infile->f_inode->i_mode | S_IWUSR);
        lock_rename(fp_tempfile->f_path.dentry->d_parent, fp_outfile->f_path.dentry->d_parent);
        v_ret = vfs_rename(fp_tempfile->f_path.dentry->d_parent->d_inode, fp_tempfile->f_path.dentry, fp_outfile->f_path.dentry->d_parent->d_inode, fp_outfile->f_path.dentry, NULL, 0);
        unlock_rename(fp_tempfile->f_path.dentry->d_parent, fp_outfile->f_path.dentry->d_parent);
        goto out_tempfile;

        out_unlink:
                mutex_lock(&fp_tempfile->f_path.dentry->d_parent->d_inode->i_mutex);
                vfs_unlink(fp_tempfile->f_path.dentry->d_parent->d_inode, fp_tempfile->f_path.dentry, NULL);
                mutex_unlock(&fp_tempfile->f_path.dentry->d_parent->d_inode->i_mutex);
                set_fs(oldfs_status);
                if(dst)
                        kfree(dst);
        out_buf:
                if(buf)
                        kfree(buf);
        out_hashbuf:
                if(hashbuf)
                        kfree(hashbuf);
        out_hashtext:
                if(hashtext)
                        kfree(hashtext);
        out_tempfile:
                if (fp_tempfile && !IS_ERR(fp_tempfile)) {
                        filp_close(fp_tempfile, NULL);
                }
                if(temp_file)
                        kfree(temp_file);
        out_outfile:
                if (fp_outfile && !IS_ERR(fp_outfile)) {
                        filp_close(fp_outfile, NULL);
                }
        out_infile:
                if (fp_infile && !IS_ERR(fp_infile)) {
                        filp_close(fp_infile, NULL);
                }
                return err;
}

/*
 * encrypt - Encrypt a file
 * @infile: input file that need to be encrypted
 * @outfile: encrypted file
 * @keybuf: key used for encryption
 *
 * The encrypt() uses ctr(aes) and encrypts the input file with symmetric key, keybuf.
 *
 */

 int encrypt(const char* infile, const char* outfile, char *keybuf) {
        struct file *fp_infile = 0, *fp_outfile = 0, *fp_tempfile = 0;
        struct kstat stat_s;
        char *buf = 0;
        mm_segment_t oldfs_status;
        int err = 0;
        size_t len = PAGE_SIZE;
        size_t numbytes_read = PAGE_SIZE, numbytes_written = 0;
        char *temp_file = 0;

        // Declaration of Hashing
        struct scatterlist sg;
        struct hash_desc desc_hash;
        char *hashtext = 0;

        char cipher[] = "ctr(aes)";
        unsigned char *dst = 0;
        size_t blk_len=16;
        int ret = 0;
        struct blkcipher_desc desc_cipher;
        struct scatterlist src_sg;
        struct scatterlist dst_sg;
        size_t dst_size = PAGE_SIZE;

        fp_infile = filp_open(infile, O_RDONLY, 0);
        if (!fp_infile || IS_ERR(fp_infile)) {
                err = PTR_ERR(fp_infile);
                goto out_infile;
        }
        if(!fp_infile->f_op->read) {
                err = -EPERM;
                goto out_infile;
        }

        oldfs_status = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_stat (infile, &stat_s);
        set_fs(oldfs_status);

        if(ret < 0) {
                err = -EPERM;
                goto out_infile;
        }

        if(!(stat_s.mode & S_IRUSR)) {
                err = -EPERM;
                goto out_infile;
        }
        if(!S_ISREG(fp_infile->f_inode->i_mode)) {
                err = -EINVAL;
                goto out_infile;
        }

        fp_outfile = filp_open(outfile, O_WRONLY, 0);
        if (!fp_outfile || IS_ERR(fp_outfile)) {
                ; /* Output file does not exist. Don nothing.   */
        }
        else {
                if(!fp_outfile->f_op->write) {
                        err = -EPERM;
                        goto out_outfile;
                }

                oldfs_status = get_fs();
                set_fs(KERNEL_DS);
                ret = vfs_stat (outfile, &stat_s);
                set_fs(oldfs_status);

                if(ret < 0) {
                        err = -EPERM;
                        goto out_outfile;
                }

                if(!(stat_s.mode & S_IWUSR)) {
                        err = -EPERM;
                        goto out_outfile;
                }

                if((fp_infile->f_inode->i_ino == fp_outfile->f_inode->i_ino) && (fp_infile->f_inode->i_sb->s_type->name == fp_outfile->f_inode->i_sb->s_type->name) ) {
                        err = -EINVAL;
                        goto out_outfile;
                }

                filp_close(fp_outfile, NULL);
                fp_outfile = 0;
        }

        temp_file = (char *) kmalloc(strlen(outfile) + 5, GFP_KERNEL);

        if(!temp_file) {
                err = -ENOMEM;
                goto out_tempbuf;
        }

        strcpy(temp_file, outfile);
        strncat(temp_file, ".tmp", 4);
        temp_file[strlen(temp_file)] = '\0';

        fp_tempfile = filp_open(temp_file, O_WRONLY | O_CREAT, fp_infile->f_inode->i_mode | S_IWUSR);
        if (!fp_tempfile || IS_ERR(fp_tempfile)) {
                err = PTR_ERR(fp_tempfile);
                goto out_tempfile;
        }

        if(!fp_tempfile->f_op->write) {
                err = -EPERM;
                goto out_tempfile;
        }

        fp_infile->f_pos = 0;
        fp_tempfile->f_pos = HEADER_SIZE;

        while(numbytes_read != 0) {
                buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
                if(!buf) {
                        err = -ENOMEM;
                        goto out_tempfile;
                }

                dst = kmalloc(PAGE_SIZE, GFP_KERNEL);
                if (!dst) {
                        err = -ENOMEM;
                        goto out_buf;
                }

                oldfs_status = get_fs();
                set_fs(KERNEL_DS);

                numbytes_read = vfs_read(fp_infile, buf, len, &fp_infile->f_pos);
                if(numbytes_read != 0) {
                        dst_size = numbytes_read;
                        desc_cipher.tfm = crypto_alloc_blkcipher(cipher, 0, CRYPTO_ALG_ASYNC);

                        if (!desc_cipher.tfm)   {
                                err = -ENOMEM;
                                goto out_unlink;
                        }

                        desc_cipher.flags = 0;
                        if(crypto_blkcipher_setkey(desc_cipher.tfm, keybuf, blk_len) < 0) {
                                err = -EINVAL;
                                crypto_free_blkcipher(desc_cipher.tfm);
                                goto out_unlink;
                        }
                        sg_init_one(&src_sg, buf, dst_size);
                        sg_init_one(&dst_sg, dst, dst_size);
                        ret = crypto_blkcipher_encrypt(&desc_cipher, &dst_sg, &src_sg, dst_size);
                        if (ret < 0) {
                                err = -EINVAL;
                                crypto_free_blkcipher(desc_cipher.tfm);
                                goto out_unlink;
                        }
                        numbytes_written = vfs_write(fp_tempfile, dst, dst_size, &fp_tempfile->f_pos);
                        crypto_free_blkcipher(desc_cipher.tfm);
                        if(numbytes_written == 0) {
                                err = -EINVAL;
                                goto out_unlink;
                        }
                }
                set_fs(oldfs_status);
                kfree(dst);
                dst = NULL;
                kfree(buf);
                buf = NULL;
        }

        fp_tempfile->f_pos = 0;
        hashtext = kmalloc(HASH_LEN + 1, GFP_KERNEL);
        if(!hashtext) {
                err = -ENOMEM;
                goto out_tempfile;
        }

        sg_init_one(&sg, keybuf, 20);
        desc_hash.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

        if (!desc_hash.tfm)   {
                err = -ENOMEM;
                goto out_hashtext;
        }

        crypto_hash_init(&desc_hash);
        crypto_hash_update(&desc_hash, &sg, 20);
        crypto_hash_final(&desc_hash, hashtext);
        crypto_free_hash(desc_hash.tfm);

        oldfs_status = get_fs();
        set_fs(KERNEL_DS);

        /* encyption header */
        numbytes_written = vfs_write(fp_tempfile, hashtext, 20, &fp_tempfile->f_pos);
        set_fs(oldfs_status);

        kfree(hashtext);
        hashtext = 0;

        fp_outfile = filp_open(outfile, O_WRONLY | O_CREAT, fp_infile->f_inode->i_mode | S_IWUSR);
        lock_rename(fp_tempfile->f_path.dentry->d_parent, fp_outfile->f_path.dentry->d_parent);
        vfs_rename(fp_tempfile->f_path.dentry->d_parent->d_inode, fp_tempfile->f_path.dentry, fp_outfile->f_path.dentry->d_parent->d_inode, fp_outfile->f_path.dentry, NULL, 0);
        unlock_rename(fp_tempfile->f_path.dentry->d_parent, fp_outfile->f_path.dentry->d_parent);
        goto out_tempfile;

        out_unlink:
                mutex_lock(&fp_tempfile->f_path.dentry->d_parent->d_inode->i_mutex);
                vfs_unlink(fp_tempfile->f_path.dentry->d_parent->d_inode, fp_tempfile->f_path.dentry, NULL);
                mutex_unlock(&fp_tempfile->f_path.dentry->d_parent->d_inode->i_mutex);
                set_fs(oldfs_status);
                if(dst)
                        kfree(dst);
        out_buf:
                if(buf)
                        kfree(buf);
        out_hashtext:
                if(hashtext)
                        kfree(hashtext);
        out_tempfile:
                if (fp_tempfile && !IS_ERR(fp_tempfile))
                        filp_close(fp_tempfile, NULL);
        out_tempbuf:
                if(temp_file)
                        kfree(temp_file);
        out_outfile:
                if (fp_outfile && !IS_ERR(fp_outfile))
                        filp_close(fp_outfile, NULL);
        out_infile:
                if (fp_infile && !IS_ERR(fp_infile))
                        filp_close(fp_infile, NULL);
                return err;
}

asmlinkage long xcrypt( __user void *u_arg)
{
        struct kargs k_data;
        struct filename* k_fname = NULL;
        long err = 0;
        int ret = 0;

        if (u_arg == NULL) {
                err =  -EINVAL;
                goto out_ok;
        }

        if(access_ok(VERIFY_READ, u_arg, sizeof(struct kargs)) == 0) {
                err = -EFAULT;
                goto out_ok;
                }

        if (copy_from_user(&k_data, (struct kargs *)u_arg,sizeof(struct kargs)) > 0) {
                err = -EFAULT;
                goto out_ok;
        }

        k_fname = getname(((struct kargs *)u_arg)->keybuf);
        if(!k_fname) {
                err = -EFAULT;
                goto out_ok;
        }

        k_data.keybuf = kstrdup(k_fname->name, GFP_KERNEL);
        if(!k_data.keybuf) {
                err = -ENOMEM;
                putname(k_fname);
                goto out_keybuf;
        }
        putname(k_fname);

        k_fname = getname(((struct kargs *)u_arg)->infile);
        if(!k_fname) {
                err = -EFAULT;
                goto out_keybuf;
        }

        k_data.infile = kstrdup(k_fname->name, GFP_KERNEL);
        if(!k_data.infile) {
                err = -ENOMEM;
                putname(k_fname);
                goto out_infile;
        }
        putname(k_fname);

        k_fname = getname(((struct kargs *)u_arg)->outfile);
        if(!k_fname) {
                err = -EFAULT;
                goto out_infile;
        }

        k_data.outfile = kstrdup(k_fname->name, GFP_KERNEL);
        if(!k_data.outfile) {
                err = -ENOMEM;
                putname(k_fname);
                goto out_outfile;
        }
        putname(k_fname);
        if(k_data.flags & 1) {
                ret = encrypt(k_data.infile, k_data.outfile, k_data.keybuf);
                if(ret < 0) {
                        printk("Encryption failed. %d\n", ret);
                }
                else
                        printk("Encryption succeeded\n");
                err = ret;
                goto out_outfile;
        }
        else if((k_data.flags & 1) == 0) {
                ret = decrypt(k_data.infile, k_data.outfile, k_data.keybuf);
                if(ret < 0) {
                        printk("Decryption failed. %d\n", ret);
                }
                else
                        printk("Decryption succeeded\n");
                err = ret;
                goto out_outfile;
        }

        out_outfile:
                if(k_data.outfile)
                        kfree(k_data.outfile);
        out_infile:
                if(k_data.infile)
                        kfree(k_data.infile);
        out_keybuf:
                if(k_data.keybuf)
                        kfree(k_data.keybuf);
        out_ok:
                return err;

}

static int __init init_sys_xcrypt(void)
{
        printk("installed new sys_xcrypt module\n");
        if (sysptr == NULL)
                sysptr = xcrypt;
        return 0;
}

static void  __exit exit_sys_xcrypt(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
