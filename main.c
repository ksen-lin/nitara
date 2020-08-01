#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>  // kallsyms_lookup_name(), ~on_each_sym()
#include <linux/fs.h>        // vfs_read()
#include <asm/uaccess.h>     // set_fs(), get_ds()
#include <linux/string.h>    // strlen()
#include <linux/version.h>

/* nbytes of prologue to be shown when DEBUG */
#ifdef DEBUG
    #define NBYTES 8
#endif
// #define MODS_FILE "/etc/modules"
#define N_SYMS 11

const char *syms[] = { "vfs_read",
                       "vfs_readdir",
                       "filldir",
                       "proc_readdir",
                       "fillonedir",
                       "inet_ioctl",
                       "tcp4_seq_show",
                       "udp4_seq_show",
                       "tcp_sendmsg",
                       "tcp_push_one",
                       "kallsyms_lookup_name" };
#define N_MODS_FILES 4
const char *mods_files[] = {"/etc/modules",
                            "/etc/rc.local",
                            "/etc/inittab",
                            "/etc/rc.d/rc.sysinit" };

unsigned long  func_addr = 0xCACACACACBCBCBCB;
unsigned char  i, j, count, *byte;



/*
 * checks the 1st byte of func for jmp instruction
 */
int splicechk(void *func, const char *name)
{
     if (((*(char *)func)&0xFF ) == 0xe9) {
         printk("nitara ***WARN***: %s() at %p seems to be spliced\n",
                name, func);
         return 1;
     } else {
         printk("nitara: %s() is ok: first byte=0x%02X\n", name, (*(char *)func)&0xFF );
         return 0;
     }
    /* TODO: maybe checking for the place to go after jmp */
}


loff_t get_i_size(struct file *f)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
    return f->f_mapping->host->i_size;
#else
    return f->f_inode->i_size;
#endif
}


/*
 * checks for hidden contents by comparing
 * length and size of MODS_FILE (/etc/modules)
 */
int modsfile_chk(void)
{
    short res=0;

    struct       file *f = NULL;
    long         f_len, f_count, f_vfs_count;
    char         buf[360];
    mm_segment_t fs;

    for (i = 0; i < N_MODS_FILES; i += 1){

        f_len = f_count = f_vfs_count = 0;
        f = filp_open(mods_files[i], O_RDONLY, 0);

        if ( f == NULL || IS_ERR(f) ){
            printk("nitara: %s: error opening %s, f=0x%p \n", __func__, mods_files[i], f);
            continue;
        }
#ifdef DEBUG
        else {
            printk("nitara: %s: f = \"%s\" opened\n", __func__, mods_files[i]);
        }
#endif
        /* get the true filesize */
        f_len = (long)get_i_size(f);

        fs = get_fs();
        set_fs(get_ds());

        memset(buf, 0, 360);
        /* read the file via file operations according to f_len */
        f_count = f->f_op->read(f, buf, f_len, &f->f_pos);

        if( f_count > 0 ) {
             buf[f_count + 1] = '\0';
    #ifdef DEBUG
             printk("nitara DEBUG: %s: read %lu bytes via file_ops. strlen(buf)=%d,"
                    " f_len=%li, f_count=%li :\n%s###EOF\n",  __func__, (unsigned long)f_count,
                    (int)strlen(buf), f_len, f_count, buf);
    #endif
        } else {
            printk("nitara: %s: error reading %s via file_ops, f_count = %li\n",
                   __func__, mods_files[i], f_count);
        }

        /* try to read the file via vfs_read according to f_len.  *
         * Let's see if we get less this time                     */
        f->f_op->llseek(f, (loff_t)0, 0);
        memset(buf, 0, 360);
        f_vfs_count = vfs_read(f, buf, f_len, &f->f_pos);

        set_fs(fs);
        if( f_vfs_count > 0 ) {
             buf[f_vfs_count + 1] = '\0';
    #ifdef DEBUG
             printk("nitara DEBUG: %s: read %lu bytes via vfs_read. strlen(buf)=%d,"
                    " f_len=%li, f_vfs_count=%li, vfs_read at %p :\n%s###EOF\n",
                     __func__, (unsigned long)f_vfs_count, (int)strlen(buf),
                     f_len, f_vfs_count, &vfs_read, buf);
    #endif
        } else {
            printk("nitara: %s: error reading %s via vfs_read, f_vfs_count = %li\n",
                    __func__, mods_files[i], f_vfs_count);
        }

        if (f_count != f_vfs_count ){
            printk("nitara ***WARN***: %s is of %li bytes but only %li (%li bytes less) "
                   "can be read via vfs_read(). possible contents hiding\n",
                    mods_files[i], f_len, f_vfs_count, (f_len - f_vfs_count) );
            res+=1;
        } else {
            printk("nitara: %s is of %lu bytes indeed\n", mods_files[i], f_count);
        }
        filp_close(f, NULL);
        set_fs(fs);
    } // end loop
#ifdef DEBUG
    printk("nitara: found %i vulnerable files\n", res);
#endif
    return res;
}


/*
 * replacement for kallsyms_lookup_name() which is not yet being
 * exported in ~2.6.32 kernel. taken from github.com/milabs/khook
 */
static int kh_lookup_cb(long data[], const char *name, void *module, long addr)
{
    int i = 0; while (!module && (((const char *)data[0]))[i] == name[i]) {
        if (!name[i++]) return !!(data[1] = addr);
    } return 0;
}

static void *kh_lookup_name(const char *name)
{
    long data[2] = { (long)name, 0 };
    kallsyms_on_each_symbol((void *)kh_lookup_cb, data);
    return (void *)data[1];
}


void lkm_chk(void)
{
    count = 0;
    for(i = 0; i < N_SYMS; i += 1){
        func_addr = (unsigned long)kh_lookup_name(syms[i]);

        if (func_addr){
            byte = (unsigned char *)func_addr;
#ifdef DEBUG
            printk("nitara DEBUG: func_addr is 0x%p\nnitara: prologue bytes: ",
                    (void *)func_addr);
            for (j = 0; j < NBYTES; j += 1)
                printk("0x%02x ", 0xFF&(char)(*(byte + j)));
            printk("\n");
#endif
            count += splicechk((void *) func_addr, syms[i]);
        }
#ifdef DEBUG
        else printk("nitara DEBUG: function %s() not found\n", syms[i]);
#endif
    }

    if (modsfile_chk()) count += 1;

    if (count > 0)
        printk("nitara: %s: malicious LKM may reside, vuln.count=%i\n", __func__, count);
    else
        printk("nitara: nothing to see here\n");
}


int init_module(void)
{
    printk("\nnitara: init_module().\n");
    lkm_chk();
    return -5;
}


void cleanup_module(void)
{
    printk("\nnitara: cleanup_module()\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ksen-lin");
