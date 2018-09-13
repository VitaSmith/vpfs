/*
  VPFS - Vita PKG File System, kernel module
  Copyright © 2018 VitaSmith

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _PSP2_KERNEL_CLIB_H_
#include "../vpfs.h"
#include "../vpfs_utils.h"
#include "module.h"

#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2/io/dirent.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <taihen.h>
#include <vitasdkkern.h>

#define LOG_PATH                                "ux0:data/vpfs.log"
#define ROUNDUP(n, width)                       (((n) + (width) - 1) & (~(unsigned int)((width) - 1)))
#define ROUNDUP_SIZE                            4096    // Malloc size for kernel must be a multiple of 4K
#define ARRAYSIZE(A)                            (sizeof(A)/sizeof((A)[0]))
#define NO_THUMB_UINT32_PTR(p)                  ((uint32_t*)((uintptr_t)p & ~1))
#define _STR(s)                                 #s
#define STR(s)                                  _STR(s)
#define min(a,b)                                ({ typeof (a) _a = (a);     \
                                                typeof (b) _b = (b);        \
                                                _a < _b ? _a : _b; })
#define max(a,b)                                ({ typeof (a) _a = (a);     \
                                                typeof (b) _b = (b);        \
                                                _a > _b ? _a : _b; })
#define MAX_PATH                                122
// TODO: Increase this for apps with loads of DLC
#define MAX_VPKG                                16
#define MAX_FD                                  256
#define VPFD_MAGIC                              0x5FF5
#define ASM_RETURN_0                            0x47702000      // movs r0, #0; bx lr
#define ASM_JUMP_TO_ADDRESS_BELOW               0xF000F8DF      // ldr.w pc, [pc, #0]
#define ASM_BLX_LONG_FORM                       0xE800F000

#define SCE_ERROR_ERRNO_ENOENT                  0x80010002
#define SCE_ERROR_ERRNO_EIO                     0x80010005
#define SCE_ERROR_ERRNO_ENOMEM                  0x8001000C
#define SCE_ERROR_ERRNO_EACCES                  0x8001000D
#define SCE_ERROR_ERRNO_EFAULT                  0x8001000E
#define SCE_ERROR_ERRNO_ENOTDIR                 0x80010014
#define SCE_ERROR_ERRNO_EINVAL                  0x80010016
#define SCE_ERROR_ERRNO_ENFILE                  0x80010017
#define SCE_ERROR_ERRNO_EROFS                   0x8001001E
#define SCE_ERROR_ERRNO_EBADFD                  0x80010051
#define SCE_ERROR_ERRNO_ENOSYS                  0x80010058
#define SCE_KERNEL_ERROR_INVALID_ARGUMENT       0x80020003

#define SceSblSsMgrForDriver_NID                0x61E9428D
#define SceSblSsMgrAESCTRDecryptForDriver_NID   0x7D46768C
#define SceSblSsMgrSHA1ForDriver_NID            0xEB3AF9B5
#define SceIofilemgrForDriver_NID               0x40FD29C7
#define SceIofilemgr_NID                        0xF2FF276E
#define SceIoClose_NID                          0XC70B8886

// Ther following avoids a lot of boilerplate
#define HOOK_INIT()                             tai_hook_ref_t hook_ref = hooks[__COUNTER__].ref;   \
                                                if (hook_ref == 0)                                  \
                                                    return SCE_ERROR_ERRNO_EFAULT;                  \
                                                int state;                                          \
                                                ENTER_SYSCALL(state);
#define HOOK_EXIT(r)                            EXIT_SYSCALL(state);                                \
                                                return r;

typedef struct
{
    uint32_t unk_0;
    uint32_t unk_4;
} sceIoDopenOpt, sceIoGetstatOpt, sceIoOpenOpt;

typedef struct
{
    SceOff   offset;
    int      whence;
    uint32_t unk;
} sceIoLseekOpt;

typedef struct
{
    SceOff offset;
    uint32_t unk_8;
    uint32_t unk_C;
} sceIoPreadOpt;

typedef int (sceSblSsMgrAESCTRDecryptForDriver_t)(uint8_t *src, uint8_t *dst, const uint32_t size, const uint8_t *key, const uint32_t key_size, uint8_t *iv, uint32_t mask_enable);
sceSblSsMgrAESCTRDecryptForDriver_t*            sceSblSsMgrAESCTRDecryptForDriver = NULL;
typedef int (sceSblSsMgrSHA1ForDriver_t)(const char *src, uint8_t *dst, size_t size, uint8_t *iv, uint32_t mask_enable, uint32_t command_bit);
sceSblSsMgrSHA1ForDriver_t*                     sceSblSsMgrSHA1ForDriver = NULL;

static uint8_t empty_sha1sum[20] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};
static char    vpfs_ext[] = ".vpfs";

typedef struct
{
    // TODO: Is path actually needed?
    char            path[MAX_PATH + sizeof(vpfs_ext)];
    SceUID          kalloc_uid;
    uint8_t*        data;
    SceDateTime     pkg_time;
    uint32_t        refcount;
} vpkg_t;

typedef struct
{
    vpkg_t*         vpkg;
    vpfs_item_t*    item;
    SceUID          fd;
    uint64_t        offset;
} vfd_t;

typedef struct {
    void*           func;
    uint32_t        nid;
    SceUID          id;
    tai_hook_ref_t  ref;
    bool            import;
} hook_t;

hook_t hooks[];

static vpkg_t   vpkgs[MAX_VPKG] = { 0 };
static vfd_t    vfds[MAX_FD] = { 0 };
static uint16_t vfd_index = 0;
static SceUID   vfd_mutex = -1, vpkg_mutex = -1, log_mutex = -1;
static void*    sceIoClose_Addr = NULL;
static uint32_t sceIoClose_Backup[2];

// Missing taihen exports
extern int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

//
// Keep non-overridden kernel calls for our internal usage
//
SceUID _ksceIoOpen(const char *filename, int flag, SceIoMode mode)
{
    // Hook may not be set yet, in which case use the original
    return (hooks[0].ref) ? TAI_CONTINUE(SceUID, hooks[0].ref, filename, flag, mode) : ksceIoOpen(filename, flag, mode);
}

int _ksceIoClose(SceUID fd)
{
    return (hooks[1].ref) ? TAI_CONTINUE(int, hooks[1].ref, fd) : ksceIoClose(fd);
}

// Log functions
static char log_msg[256];
static SceUID log_fd = 0;
static void log_print(const char* msg)
{
    log_fd = _ksceIoOpen(LOG_PATH, SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0777);
    if (log_fd >= 0) {
        ksceIoWrite(log_fd, msg, strlen(msg));
        _ksceIoClose(log_fd);
    }
}

#define printf(...) do { ksceKernelLockMutex(log_mutex, 1, NULL); snprintf(log_msg, sizeof(log_msg), __VA_ARGS__); log_print(log_msg); ksceKernelUnlockMutex(log_mutex, 1); } while(0)
#define perr        printf

// Kernel alloc/free functions
int kalloc(const char* path, uint32_t size, SceUID* uid, uint8_t** dest)
{
    int r;
    *uid = ksceKernelAllocMemBlock(path, SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, ROUNDUP(size, ROUNDUP_SIZE), 0);
    if (*uid < 0) {
        perr("kalloc: Could not allocate buffer: 0x%08X (size: 0x%X)\n", *uid, size);
        return *uid;
    }

    r = ksceKernelGetMemBlockBase(*uid, (void**)dest);
    if (r < 0) {
        perr("kalloc: Could not get block base: 0x%08X\n", r);
        return r;
    }

    return 0;
}

int kfree(SceUID uid)
{
    int r = -1;
    if (uid < 0)
        return 0;
    r = ksceKernelFreeMemBlock(uid);
    if (r < 0) {
        perr("kfree: Could not deallocate buffer: 0x%08X\n", r);
        return r;
    }
    return 0;
}

// Kernel functions we want to export

/**
 * Decrypt an AES CTR encrypted stream
 *
 * @param src - The buffer containing the encrypted content.
 * @param dst - The buffer to receive the decrypted content.
 * @parma size - The size of the destination buffer.
 * @parma key - The AES key (0x10 / 0x18 / 0x20 length in byes).
 * @parma key_size - The AES key size in bits (0x80 / 0xC0 / 0x100).
 * @parma iv - The AES IV. Length is 0x10 and it is updated after decryption.
 * @param mask_enable - Should be set to 1.
 *
 * @return 0 on success, != 0 on error
 */
int ksceSblSsMgrAESCTRDecrypt(uint8_t *src, uint8_t *dst, const uint32_t size, const uint8_t *key, const uint32_t key_size, uint8_t *iv, uint32_t mask_enable)
{
    return sceSblSsMgrAESCTRDecryptForDriver(src, dst, size, key, key_size, iv, mask_enable);
}

int usceSblSsMgrAESCTRDecrypt(usceSblSsMgrAESCTRDecrypt_args* args)
{
    int r;
    SceUID aes_src_uid = -1, aes_dst_uid = -1, aes_key_uid = -1, aes_iv_uid = -1;
    uint8_t *aes_src = NULL, *aes_dst = NULL, *key = NULL, *iv = NULL;
    usceSblSsMgrAESCTRDecrypt_args kargs;

    printf("usceSblSsMgrAESCTRDecrypt\n");

    // Copy arguments to kernel
    r = ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(usceSblSsMgrAESCTRDecrypt_args));
    if (r < 0) {
        perr("usceSblSsMgrAESCTRDecrypt: failed to ksceKernelMemcpyUserToKernel: 0x%08X\n", r);
        goto out;
    }

    // Check args
    if (kargs.src == NULL || kargs.dst == NULL || kargs.size == 0 || kargs.key == NULL || kargs.key_size == 0 || kargs.iv == NULL || kargs.mask_enable != 1) {
        perr("usceSblSsMgrAESCTRDecrypt: Invalid arguments\n");
        r = -1;
        goto out;
    }

    // Allocate source buffer
    r = kalloc("aes_src", kargs.size, &aes_src_uid, &aes_src);
    if (r < 0)
        goto out;

    // Allocate dest buffer
    r = kalloc("aes_dst", kargs.size, &aes_dst_uid, &aes_dst);
    if (r < 0)
        goto out;

    // Allocate key buffer
    r = kalloc("aes_key", (kargs.key_size / 8), &aes_key_uid, &key);
    if (r < 0)
        goto out;

    // Allocate iv buffer
    r = kalloc("aes_ic", 0x10, &aes_iv_uid, &iv);
    if (r < 0)
        goto out;

    // Copy source to kernel
    r = ksceKernelMemcpyUserToKernel(aes_src, (uintptr_t)kargs.src, kargs.size);
    if (r < 0)
        goto out;

    // Copy key to kernel
    r = ksceKernelMemcpyUserToKernel(key, (uintptr_t)kargs.key, kargs.key_size / 8);
    if (r < 0)
        goto out;

    // Copy iv to kernel
    r = ksceKernelMemcpyUserToKernel(iv, (uintptr_t)kargs.iv, 0x10);
    if (r < 0)
        goto out;

    // Call function
    r = sceSblSsMgrAESCTRDecryptForDriver(aes_src, aes_dst, kargs.size, key, kargs.key_size, iv, kargs.mask_enable);
    if (r < 0)
        goto out;

    // Copy result to dest
    r = ksceKernelMemcpyKernelToUser((uintptr_t)kargs.dst, aes_dst, kargs.size);
    if (r < 0)
        goto out;

out:
    kfree(aes_src_uid);
    kfree(aes_dst_uid);
    kfree(aes_key_uid);
    kfree(aes_iv_uid);
    return r;
}

//
// Helper functions
//
static int vpkg_open(const char *path)
{
    int i;
    // Try to find an existing opened cached VPFS and return its index if found
    for (i = 0; i < MAX_VPKG; i++) {
        if (strcmp(path, vpkgs[i].path) == 0) {
            ksceKernelLockMutex(vpkg_mutex, 1, NULL);
            vpkgs[i].refcount++;
            ksceKernelUnlockMutex(vpkg_mutex, 1);
            return i;
        }
    }

    // Not alreay open -> Try to create a new one
    ksceKernelLockMutex(vpkg_mutex, 1, NULL);
    for (i = 0; i < MAX_VPKG; i++) {
        if (vpkgs[i].path[0] == 0) {
            uint8_t* data;
            vpfs_header_t header;
            SceIoStat stat;

            // First, check if the VPFS path exists and is a regular file
            if ((ksceIoGetstat(path, &stat) < 0) || (!SCE_S_ISREG(stat.st_mode))) {
                i = SCE_ERROR_ERRNO_ENOENT;
                goto out;
            }

            SceUID fd = _ksceIoOpen(path, SCE_O_RDONLY, 0);
            if (fd < 0) {
                perr("Could not open '%s': 0x%08X\n", path, fd);
                kfree(vpkgs[i].kalloc_uid);
                i = fd;
                goto out;
            }
            // Sanity check
            if (stat.st_size < sizeof(vpfs_header_t) + sizeof(vpfs_pkg_t) + sizeof(uint32_t) + sizeof(vpfs_item_t)) {
                perr("VPFS file is too small\n");
                _ksceIoClose(fd);
                kfree(vpkgs[i].kalloc_uid);
                i = SCE_ERROR_ERRNO_EACCES;
                goto out;
            }

            // Read the header to find the size of the data we need to cache
            int read = ksceIoRead(fd, &header, sizeof(header));
            if (read != sizeof(header)) {
                perr("Could not read VPFS header: 0x%08X\n", read);
                _ksceIoClose(fd);
                i = SCE_ERROR_ERRNO_EIO;
                goto out;
            }

            if (header.magic != VPFS_MAGIC) {
                perr("Invalid VPFS magic\n");
                _ksceIoClose(fd);
                i = SCE_ERROR_ERRNO_EACCES;
                goto out;
            }

            // Allocate memory to cache the VPFS data.
            // Note that we don't cache any data past the directory listing.
            if (kalloc(path, (SceOff)header.size, &vpkgs[i].kalloc_uid, &data) < 0) {
                _ksceIoClose(fd);
                i = SCE_ERROR_ERRNO_ENOMEM;
                goto out;
            }
            memcpy(data, &header, sizeof(header));

            // Now copy the rest of the data
            read = ksceIoRead(fd, &data[sizeof(header)], header.size - sizeof(header));
            _ksceIoClose(fd);
            if (read != (header.size - sizeof(header))) {
                perr("Could not read VPFS data: 0x%08X\n", read);
                kfree(vpkgs[i].kalloc_uid);
                ksceKernelUnlockMutex(vpkg_mutex, 1);
                i = SCE_ERROR_ERRNO_EIO;
                goto out;
            }

            vpkgs[i].refcount = 1;
            vpkgs[i].data = data;
            vpkgs[i].pkg_time = stat.st_ctime;
            strncpy(vpkgs[i].path, path, sizeof(vpkgs[i].path));
            goto out;
        }
    }
    // All vpkgs slots are taken
    i = SCE_ERROR_ERRNO_ENFILE;

out:
    ksceKernelUnlockMutex(vpkg_mutex, 1);
    return i;
}

static int vpkg_close(vpkg_t* vpkg)
{
    if (vpkg == NULL)
        return SCE_ERROR_ERRNO_EBADFD;
    ksceKernelLockMutex(vpkg_mutex, 1, NULL);
    vpkg->refcount--;
    if (vpkg->refcount == 0) {
        if (vpkg->kalloc_uid >= 0)
            kfree(vpkg->kalloc_uid);
        vpkg->kalloc_uid = 0;
        vpkg->data = NULL;
        vpkg->path[0] = 0;
    }
    ksceKernelUnlockMutex(vpkg_mutex, 1);
    return 0;
}

static uint16_t vfd_get_index(void)
{
    ksceKernelLockMutex(vfd_mutex, 1, NULL);
    for (uint16_t i = 0; i < ARRAYSIZE(vfds); i++) {
        if (vfds[i].vpkg == NULL) {
            // Set to non NULL to prevent duplicate use of this index
            // after relinquishing the mutex
            vfds[i].vpkg = (vpkg_t*)-1;
            ksceKernelUnlockMutex(vfd_mutex, 1);
            return i;
        }
    }
    ksceKernelUnlockMutex(vfd_mutex, 1);
    return 0xFFFF;
}

static inline vfd_t* get_vfd(SceUID fd)
{
    if ((fd >> 16) != VPFD_MAGIC)
        return NULL;
    return ((uint16_t)fd < MAX_FD) ? &vfds[(uint16_t)fd] : NULL;
}

static SceUID vpfs_open(const char *path)
{
    int vpkg_index = vpkg_open(path);
    if (vpkg_index < 0)
        return (SceUID)vpkg_index;
    uint16_t index = vfd_get_index();
    vfd_t* vfd = (index == 0xFFFF) ? NULL : &vfds[index];
    if (vfd == NULL) {
        vpkg_close(&vpkgs[vpkg_index]);
        return SCE_ERROR_ERRNO_ENFILE;
    }
    vfd->vpkg = &vpkgs[vpkg_index];
    return (VPFD_MAGIC << 16) | index;
}

static int vpfs_close(SceUID fd)
{
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL)
        return SCE_ERROR_ERRNO_EBADFD;
    ksceKernelLockMutex(vfd_mutex, 1, NULL);
    int r = vpkg_close(vfd->vpkg);
    vfd->vpkg = NULL;
    ksceKernelUnlockMutex(vfd_mutex, 1);
    return r;
}

static int sha1sum(const char* path, uint8_t* sum)
{
    char kpath[256];
    if ((sum == NULL) || (path == NULL) || (sceSblSsMgrSHA1ForDriver == NULL))
        return SCE_KERNEL_ERROR_INVALID_ARGUMENT;

    if (path[0] == 0) {
        // sceSblSsMgrSHA1ForDriver doesn't like a size of zero for the source
        memcpy(sum, empty_sha1sum, 20);
        return 0;
    }

    // If you don't duplicate the path to a region of memory that belongs
    // to our module, the SHA-1 gets computed improperly!!!
    memcpy(kpath, path, strlen(path));
    return sceSblSsMgrSHA1ForDriver(kpath, sum, strlen(path), NULL, 1, 0);
}

static const char* basename(const char* path)
{
    size_t index;

    if (path == NULL)
        return NULL;

    for (index = strlen(path) - 1; index > 0; index--)
    {
        if ((path[index] == '/') || (path[index] == '\\'))
        {
            index++;
            break;
        }
    }
    return &path[index];
}

static vpfs_item_t* vpfs_find_item(uint8_t* vpfs, const char* path)
{
    uint32_t i;
    uint8_t sha1[20];
    vpfs_header_t* header = (vpfs_header_t*)vpfs;
    uint32_t* sha_table = (uint32_t*)&vpfs[sizeof(vpfs_header_t) + header->nb_pkgs * sizeof(vpfs_pkg_t)];

    int r = sha1sum(path, sha1);
    if (r < 0) {
        perr("Could not compute SHA1: 0x%08X\n", r);
        return NULL;
    }

    uint32_t short_sha = get32be(sha1);

    // TODO: Speed this up through dichotomy
    for (i = 0; (i < header->nb_items) && (sha_table[i] != short_sha); i++);
    if (i >= header->nb_items)
        return NULL;
    vpfs_item_t* item = (vpfs_item_t*)&vpfs[sizeof(vpfs_header_t) +
        header->nb_pkgs * sizeof(vpfs_pkg_t) + header->nb_items * sizeof(uint32_t) + i *sizeof(vpfs_item_t)];
    if (memcmp(item->xsha, &sha1[4], 16) == 0)
        return item;

    // Full SHA-1 doesn't match -> Try next items until we get a match or short SHA-1 doesn't match
    while ((++i < header->nb_items) && (sha_table[i] == short_sha)) {
        item = (vpfs_item_t*)&vpfs[sizeof(vpfs_header_t) +
            header->nb_pkgs * sizeof(vpfs_pkg_t) + header->nb_items * sizeof(uint32_t) + i * sizeof(vpfs_item_t)];
        if (memcmp(item->xsha, &sha1[4], 16) == 0)
            return item;
    }
    return NULL;
}

//
// Common code for hooks
//
SceUID open_hook_internal(const char* name, char* path, int flag, SceUID tai_fd)
{
    char bck[sizeof(vpfs_ext)];
    size_t i, len = strlen(path);
    SceUID fd = SCE_ERROR_ERRNO_EBADFD;

    // We may already have a valid VPFS fd
    if ((tai_fd >> 16) == VPFD_MAGIC)
        return tai_fd;

    for (i = strlen(path); i > 0; i--) {
        if ((path[i] == '/') || (path[i] == 0)) {
            memcpy(bck, &path[i], sizeof(vpfs_ext));
            memcpy(&path[i], vpfs_ext, sizeof(vpfs_ext));
            fd = vpfs_open(path);
            memcpy(&path[i], bck, sizeof(vpfs_ext));
            if (fd >= 0)
                break;
        }
    }
    if (i == 0) {
        // Couldn't find a relevant VPFS => use the original function call
        printf("- %s('%s') [ORG]: 0x%08X\n", name, path, tai_fd);
        return tai_fd;
    }

    // Filter out flags that are incompatible with the read-only nature of VPFS
    if (flag & (SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND | SCE_O_TRUNC | SCE_O_DIROPEN)) {
        printf("- %s('%s') [OVL]: 0x%08X flags are incompatible with read-only VPFS\n", name, path, flag);
        return SCE_ERROR_ERRNO_EROFS;
    }

    // We have an opened vfd -> process it
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL)
        return SCE_ERROR_ERRNO_EFAULT;

    vfd->item = vpfs_find_item(vfd->vpkg->data, &path[i + 1]);
    if (vfd->item == NULL) {
        printf("- %s('%s') [OVL]: Entry not found in .vpfs\n", name, &path[i + 1]);
        return SCE_ERROR_ERRNO_ENOENT;
    }

    // Check our data
    if (vfd->item->flags & VPFS_ITEM_DELETED) {
        printf("- %s('%s') [OVL]: Item was deleted\n", name, path);
        return SCE_ERROR_ERRNO_ENOENT;
    }

    if (vfd->item->flags & VPFS_ITEM_TYPE_DIR) {
        printf("- %s('%s') [OVL]: This is a directory\n", name, path);
        return SCE_ERROR_ERRNO_ENOENT;
    }

    char* item_path = NULL;
    if (vfd->item->pkg_index < 0) {
        // The item resides in the .vpfs
        memcpy(&path[i], vpfs_ext, sizeof(vpfs_ext));
        item_path = path;
    } else {
        // The item resides in an external PKG file
        vpfs_pkg_t* pkg = (vpfs_pkg_t*)&vfd->vpkg->data[sizeof(vpfs_header_t) + vfd->item->pkg_index * sizeof(vpfs_pkg_t)];
        item_path = pkg->path;
    }
    vfd->fd = _ksceIoOpen(item_path, SCE_O_RDONLY, 0);
    if (vfd->fd < 0) {
        perr("- %s [OVL]: Could not open '%s': 0x%08X\n", name, item_path, vfd->fd);
        return vfd->fd;
    }
    if (vfd->item->pkg_index < 0)
        memcpy(&path[i], bck, sizeof(vpfs_ext));
    vfd->offset = 0;
    ksceIoLseek(vfd->fd, vfd->item->offset, SCE_SEEK_SET);
    printf("- %s('%s') [OVL]: 0x%08X\n", name, path, fd);
    return fd;
}

//
// Hooks
//
SceUID ksceIoOpen_Hook(const char *filename, int flag, SceIoMode mode)
{
    HOOK_INIT();
    char path[MAX_PATH + sizeof(vpfs_ext)];
    memcpy(path, filename, sizeof(path) - sizeof(vpfs_ext));
    HOOK_EXIT(open_hook_internal("ksceIoOpen", path, flag, TAI_CONTINUE(SceUID, hook_ref, filename, flag, mode)));
}

int ksceIoClose_Hook(SceUID fd)
{
    HOOK_INIT();

    int r = TAI_CONTINUE(int, hook_ref, fd);
    if ((fd >> 16) == VPFD_MAGIC) {
        r = vpfs_close(fd);
        vfd_t* vfd = get_vfd(fd);
        if ((vfd != NULL) && (vfd->fd > 0))
            _ksceIoClose(vfd->fd);
        vfd->fd = 0;
        printf("- ksceIoClose(0x%08X) [OVL]: 0x%08X\n", fd, r);
    }

    HOOK_EXIT(r)
}

SceUID sceIoDopen_Hook(const char *dirname, sceIoDopenOpt *opt)
{
    HOOK_INIT();
    char path[MAX_PATH + sizeof(vpfs_ext)];
    char bck[sizeof(vpfs_ext)];
    size_t i;
    SceUID fd = SCE_ERROR_ERRNO_ENOENT;

    // Always invoke TAI_CONTINUE
    SceUID tai_fd = TAI_CONTINUE(SceUID, hook_ref, dirname, opt);

    // Copy the user pointer to kernel space for processing
    ksceKernelStrncpyUserToKernel(path, (uintptr_t)dirname, sizeof(path) - sizeof(vpfs_ext));
    size_t len = strlen(path);
    if (path[len - 1] == '/')
        path[--len] = 0;
    for (i = len; i > 0; i--) {
        if ((path[i] == '/') || (path[i] == 0)) {
            memcpy(bck, &path[i], sizeof(vpfs_ext));
            memcpy(&path[i], vpfs_ext, sizeof(vpfs_ext));
            fd = vpfs_open(path);
            if (fd >= 0)
                break;
            memcpy(&path[i], bck, sizeof(vpfs_ext));
        }
    }
    if (i == 0) {
        // Couldn't find a relevant VPFS => use the original function call
//        printf("- sceIoDopen('%s') [ORG]: 0x%08X\n", path, tai_fd);
        fd = tai_fd;
        goto out;
    }

    memcpy(&path[i], bck, sizeof(vpfs_ext));
    // We have an opened vfd -> process it
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL) {
        fd = SCE_ERROR_ERRNO_EFAULT;
        goto out;
    }
    vfd->item = vpfs_find_item(vfd->vpkg->data, &path[i + 1]);
    if (vfd->item == NULL) {
        printf("- sceIoDopen('%s') [OVL]: Entry not found in .vpfs\n", &path[i + 1]);
        fd = SCE_ERROR_ERRNO_ENOENT;
        goto out;
    }

    // Check our data
    if (!(vfd->item->flags & VPFS_ITEM_TYPE_DIR)) {
        printf("- sceIoDopen('%s') [OVL]: Item found is not a directory\n", path);
        fd = SCE_ERROR_ERRNO_ENOTDIR;
        goto out;
    }
    if (vfd->item->flags & VPFS_ITEM_DELETED) {
        printf("- sceIoDopen('%s') [OVL]: Item was deleted\n", path);
        fd = SCE_ERROR_ERRNO_ENOENT;
        goto out;
    }
    if (vfd->item->pkg_index > 0) {
        printf("- sceIoDopen('%s') [OVL]: Directory offset is not in VPFS file\n", path);
        fd = SCE_ERROR_ERRNO_EFAULT;
        goto out;
    }
    vfd->offset = vfd->item->offset;
    printf("- sceIoDopen('%s') [OVL]: 0x%08X\n", path, fd);

out:
    HOOK_EXIT(fd);
}

int sceIoDread_Hook(SceUID fd, SceIoDirent *dir)
{
    HOOK_INIT();

    // Always invoke TAI_CONTINUE
    int r = TAI_CONTINUE(int, hook_ref, fd, dir);
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL) {
        // Regular directory -> use standard call while converting any '.vpfs' file to a virtual directory
        if (r == 1) {
            // Check if one of the files has a .vpfs extension and alter its properties
            // so that the querying application will see it as a virtual directory.
            char path[sizeof(dir->d_name)];
            ksceKernelMemcpyUserToKernel(path, (uintptr_t)dir->d_name, sizeof(dir->d_name));
            size_t len = strlen(path);
            if (len >= sizeof(vpfs_ext)) {
                if (strcmp(&path[len - sizeof(vpfs_ext) + 1], vpfs_ext) == 0) {
                    // Copy the path back with the ".vpfs" extension removed
                    path[len - sizeof(vpfs_ext) + 1] = 0;
                    ksceKernelMemcpyKernelToUser((uintptr_t)dir->d_name, path, len - sizeof(vpfs_ext) + 2);
                    // Remove the regular file mode and set the directory mode
                    SceIoStat stat;
                    ksceKernelMemcpyUserToKernel(&stat, (uintptr_t)dir, sizeof(stat));
                    stat.st_mode &= ~SCE_S_IFREG;
                    stat.st_mode |= SCE_S_IFDIR;
                    ksceKernelMemcpyKernelToUser((uintptr_t)dir, &stat, sizeof(stat));
                }
            }
        }
//        printf("- sceIoDread(0x%08X) [ORG]: 0x%08X\n", fd, r);
        goto out;
    }

    // Virtual directory
    const char* path = (const char*)&vfd->vpkg->data[vfd->offset];
    size_t len = strlen(path);
    if (len == 0) {
        // No more content in this directory
        r = 0;
        goto out;
    }

    SceIoStat stat = { 0 };
    vpfs_item_t* item = vpfs_find_item(vfd->vpkg->data, path);
    if (item == NULL) {
        printf("- sceIoDread('%s') [OVL]: Entry not found in .vpfs\n", path);
        r = SCE_ERROR_ERRNO_ENOENT;
        goto out;
    }
    // TODO: Check for VPFS_ITEM_DELETED and skip deleted items
    const char* name = basename(path);
    ksceKernelMemcpyKernelToUser((uintptr_t)dir->d_name, name, strlen(name) + 1);
    stat.st_ctime = vfd->vpkg->pkg_time;
    stat.st_atime = vfd->vpkg->pkg_time;
    stat.st_mtime = vfd->vpkg->pkg_time;
    if (item->flags & VPFS_ITEM_TYPE_DIR) {
        stat.st_mode = SCE_S_IFDIR | SCE_S_IRUSR | SCE_S_IROTH;
    } else {
        stat.st_mode = SCE_S_IFREG | SCE_S_IRUSR | SCE_S_IROTH;
        stat.st_size = item->size;
    }
    ksceKernelMemcpyKernelToUser((uintptr_t)dir, &stat, sizeof(stat));
    vfd->offset += len + 1;
    r = 1;
//    printf("- sceIoDread(0x%08X) [OVL]: '%s'\n", fd, name);

out:
    HOOK_EXIT(r);
}

int sceIoDclose_Hook(SceUID fd)
{
    HOOK_INIT();

    // Always invoke TAI_CONTINUE
    int r = TAI_CONTINUE(int, hook_ref, fd);
    vfd_t* vfd = get_vfd(fd);
    if (vfd != NULL) {
        r = vpfs_close(fd);
        printf("- sceIoDclose(0x%08X) [OVL]: 0x%08X\n", fd, r);
    }

    EXIT_SYSCALL(state);
    return r;
}

int sceIoGetstat_Hook(const char* file, SceIoStat* stat, sceIoGetstatOpt *opt)
{
    HOOK_INIT();
    char path[MAX_PATH + sizeof(vpfs_ext)];
    char bck[sizeof(vpfs_ext)];
    size_t i;
    SceUID fd = SCE_ERROR_ERRNO_ENOENT;

    int r = TAI_CONTINUE(int, hook_ref, file, stat, opt);

    // Copy the user pointer to kernel space for processing
    ksceKernelStrncpyUserToKernel(path, (uintptr_t)file, sizeof(path) - sizeof(vpfs_ext));
    size_t len = strlen(path);
    if (path[len - 1] == '/')
        path[--len] = 0;
    for (i = len; i > 0; i--) {
        if ((path[i] == '/') || (path[i] == 0)) {
            memcpy(bck, &path[i], sizeof(vpfs_ext));
            memcpy(&path[i], vpfs_ext, sizeof(vpfs_ext));
            fd = vpfs_open(path);
            if (fd >= 0)
                break;
            memcpy(&path[i], bck, sizeof(vpfs_ext));
        }
    }
    if (i == 0) {
        // Couldn't find a relevant VPFS => use the original function call
//        printf("- sceIoGetstat('%s') [ORG]: 0x%08X\n", path, r);
        goto out;
    }

    memcpy(&path[i], bck, sizeof(vpfs_ext));
    // We have an opened vfd -> process it
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL) {
        r = SCE_ERROR_ERRNO_EFAULT;
        goto out;
    }
    vpfs_item_t* item = vpfs_find_item(vfd->vpkg->data, &path[i + 1]);
    if (item == NULL) {
        printf("- sceIoGetstat('%s') [OVL]: Entry not found in .vpfs\n", &path[i + 1]);
        r = SCE_ERROR_ERRNO_ENOENT;
        goto out;
    }

    // Check our data
    if (item->flags & VPFS_ITEM_DELETED) {
        printf("- sceIoGetstat('%s') [OVL]: Item was deleted\n", path);
        r = SCE_ERROR_ERRNO_ENOENT;
        goto out;
    }
    SceIoStat kstat = { 0 };
    kstat.st_ctime = vfd->vpkg->pkg_time;
    kstat.st_atime = vfd->vpkg->pkg_time;
    kstat.st_mtime = vfd->vpkg->pkg_time;
    if (item->flags & VPFS_ITEM_TYPE_DIR) {
        kstat.st_mode = SCE_S_IFDIR | SCE_S_IRUSR | SCE_S_IROTH;
    } else {
        kstat.st_mode = SCE_S_IFREG | SCE_S_IRUSR | SCE_S_IROTH;
        kstat.st_size = item->size;
    }
    ksceKernelMemcpyKernelToUser((uintptr_t)stat, &kstat, sizeof(kstat));
    printf("- sceIoGetstat('%s') [OVL]: 0x%08X\n", path, 0);
    r = 0;

out:
    HOOK_EXIT(r);
}

SceUID sceIoOpen_Hook(const char *filename, int flag, SceIoMode mode, sceIoOpenOpt *opt)
{
    HOOK_INIT();
    char path[MAX_PATH + sizeof(vpfs_ext)];
    ksceKernelStrncpyUserToKernel(path, (uintptr_t)filename, sizeof(path) - sizeof(vpfs_ext));
    HOOK_EXIT(open_hook_internal("sceIoOpen", path, flag, TAI_CONTINUE(SceUID, hook_ref, filename, flag, mode, opt)));
}

// Workaround for a taiHEN bug when hooking sceIoClose()
// See https://github.com/yifanlu/taiHEN/issues/84
// Note that gcc's inline assembly is very restrictive, which is
// why we can't be as elegant with this code as we'd like...
void sceIoClose_Override(void)
{
    asm volatile (
        "   lsr r1, r0, #16     \n"
        "   mov r2, #" STR(VPFD_MAGIC) "\n"
        "   cmp r1, r2          \n"
        "   beq jmp_to_hook     \n"
        // (uint32_t*) addr[3] -> compare_data (should match the start of the original call)
        "compare_data:          \n"
        "   push {r3-r5,lr}     \n"
        "   mov r4, r0          \n"
        "   ldr.w lr, [pc, #4]  \n"
        "   ldr.w pc, [pc, #4]  \n"
        // (uint32_t*) addr[6] -> override_lr
        "   nop; nop            \n"
        // (uint32_t*) addr[7] -> override_pc
        "   nop; nop            \n"
        "jmp_to_hook:           \n"
        "   ldr.w pc, [pc, #0]  \n"
        // (uint32_t*) addr[9] -> sceIoClose_Hook address
        "   nop; nop            \n"
    );
}

int sceIoClose_Hook(SceUID fd)
{
    int state;
    ENTER_SYSCALL(state);

    int r = vpfs_close(fd);
    vfd_t* vfd = get_vfd(fd);
    if ((vfd != NULL) && (vfd->fd > 0))
        _ksceIoClose(vfd->fd);
    vfd->fd = 0;
    printf("- sceIoClose(0x%08X) [OVL]: 0x%08X\n", fd, r);

    EXIT_SYSCALL(state);
    return r;
}

int sceIoRead_Hook(SceUID fd, void *data, SceSize size)
{
    HOOK_INIT();
    uint8_t kdata[512];

    int r = TAI_CONTINUE(int, hook_ref, fd, data, size);
    if ((fd >> 16) != VPFD_MAGIC)
        goto out;

    vfd_t* vfd = get_vfd(fd);
    // Make sure we don't overflow our content
    if (vfd->offset + size > vfd->item->size)
        size = vfd->item->size - vfd->offset;
    int data_size;
    uintptr_t data_offset;
    switch (vfd->item->flags) {
    case VPFS_ITEM_TYPE_ZERO:
        memset(kdata, 0, sizeof(kdata));
        data_size = size;
        data_offset = 0;
        while (data_size > 0) {
            int read = min(data_size, sizeof(kdata));
            ksceKernelMemcpyKernelToUser((uintptr_t)data + data_offset, &kdata, read);
            data_size -= read;
            data_offset += read;
            vfd->offset += read;
        }
        r = size;
        break;
    case VPFS_ITEM_TYPE_BIN:
        data_size = size;
        data_offset = 0;
        while (data_size > 0) {
            int read = min(data_size, sizeof(kdata));
            read = ksceIoRead(vfd->fd, kdata, read);
            if (read <= 0) {
                r = read;
                goto out;
            }
            data_size -= read;
            ksceKernelMemcpyKernelToUser((uintptr_t)data + data_offset, &kdata, read);
            data_offset += read;
            vfd->offset += read;
        }
        r = size;
        break;
    case VPFS_ITEM_TYPE_AES:
        if (sceSblSsMgrAESCTRDecryptForDriver == NULL) {
            perr("- sceIoRead(0x%08X) [OVL]: sceSblSsMgrAESCTRDecryptForDriver() is not available\n", fd);
            r = SCE_ERROR_ERRNO_EFAULT;
            goto out;
        }

        // TODO: Double buffering with async read into one buffer and CTR decrypt in the other
        SceOff ctr_offset = vfd->offset & 0xFULL;
        if (ctr_offset != 0) {
            // Roll back to the start of our CTR segment
            SceOff new_pos = ksceIoLseek(vfd->fd, -ctr_offset, SCE_SEEK_CUR);
            printf("- sceIoRead(0x%08X)[OVL]: CTR rollback %lld bytes (pos = 0x%llX)\n", fd, ctr_offset, new_pos);
            vfd->offset -= ctr_offset;
        }

        // Set the IV
        vpfs_pkg_t* pkg = (vpfs_pkg_t*)&vfd->vpkg->data[sizeof(vpfs_header_t) + vfd->item->pkg_index * sizeof(vpfs_pkg_t)];
        uint64_t block = (vfd->item->offset + vfd->offset - pkg->enc_offset) / 16;
        uint8_t iv[16];
        // The AES IV used by sceSblSsMgrAESCTRDecryptForDriver() must be inverted from its PKG representation.
        // We take this opportunity to add the relevant data for XOR CTR.
        for (int i = 0; i < 16; i++) {
            block = block + pkg->iv[15 - i];
            iv[i] = (uint8_t)block;
            block >>= 8;
        }

        data_size = size + ctr_offset;
        data_offset = 0;
        bool first_pass = true;
        // TODO: Double buffering with async read into one buffer and CTR decrypt in the other
        while (data_size > 0) {
            int read = min(data_size, sizeof(kdata));
            // All the PKG data is padded to 16 bytes so we can extend short reads
            if (read < 16)
                read = 16;
            read = ksceIoRead(vfd->fd, kdata, read);
            if (read <= 0) {
                r = read;
                goto out;
            }
            // Note: This call updates the iv for us
            r = sceSblSsMgrAESCTRDecryptForDriver(kdata, kdata, read, pkg->key, 0x80, iv, 1);
            if (r < 0) {
                perr("- sceIoRead(0x%08X) [OVL]: Could not decrypt AES CTR 0x%08X\n", fd, r);
                goto out;
            }
            int copied = min(read - (first_pass ? ctr_offset : 0), data_size);
            ksceKernelMemcpyKernelToUser((uintptr_t)data + data_offset, &kdata[first_pass? ctr_offset : 0], copied);
            // CTR offset only applies to the first read
            vfd->offset += read;
            data_offset += copied;
            data_size -= copied;
            first_pass = false;
        }
        r = size;
        break;
    default:
        perr("- sceIoRead(0x%08X) [OVL]: Item type %d is not supported\n", fd, vfd->item->flags);
        r = SCE_ERROR_ERRNO_ENOSYS;
        goto out;
    }
    printf("- sceIoRead(0x%08X) [OVL]: 0x%08X\n", fd, r);

out:
    HOOK_EXIT(r);
}

SceOff sceIoLseek_Hook(SceUID fd, sceIoLseekOpt* opt)
{
    HOOK_INIT();
    sceIoLseekOpt kopt;

    SceOff r = TAI_CONTINUE(SceOff, hook_ref, fd, opt);
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL)
        goto out;
    if (opt == NULL) {
        r = SCE_ERROR_ERRNO_EINVAL;
        goto out;
    }
    // Copy the opt data to kernel space for processing
    ksceKernelStrncpyUserToKernel(&kopt, (uintptr_t)opt, sizeof(kopt));
    r = vfd->offset;
    switch (kopt.whence) {
    case SEEK_SET:
        r = kopt.offset;
        break;
    case SEEK_END:
        r = vfd->item->size + kopt.offset;
        break;
    case SEEK_CUR:
        r += kopt.offset;
        break;
    default:
        r = SCE_ERROR_ERRNO_EINVAL;
        perr("- sceIoLseek(0x%08X) [OVL]: invalid whence value %d\n", fd, kopt.whence);
        goto out;
    }
    if (r < 0)
        r = 0;
    else if (r > vfd->item->size)
        r = vfd->item->size;
    vfd->offset = r;
    // TODO: Check the return value of ksceIoLseek()
    if (vfd->fd > 0)
        ksceIoLseek(vfd->fd, vfd->item->offset + vfd->offset, SCE_SEEK_SET);
    printf("- sceIoLseek(0x%08X) [OVL]: 0x%llX\n", fd, r);

out:
    HOOK_EXIT(r);
}

int sceIoLseek32_Hook(SceUID fd, int offset, int whence)
{
    HOOK_INIT();

    int r = TAI_CONTINUE(int, hook_ref, fd, offset, whence);
    vfd_t* vfd = get_vfd(fd);
    if (vfd == NULL)
        goto out;
    int64_t new_offset = vfd->offset;
    switch (whence) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_END:
        new_offset = vfd->item->size + offset;
        break;
    case SEEK_CUR:
        new_offset += offset;
        break;
    default:
        r = SCE_ERROR_ERRNO_EINVAL;
        perr("- sceIoLseek32(0x%08X) [OVL]: invalid whence value %d\n", fd, whence);
        goto out;
    }
    if (new_offset < 0)
        new_offset = 0;
    else if (new_offset > vfd->item->size)
        new_offset = vfd->item->size;
    vfd->offset = new_offset;
    // TODO: Check the return value of ksceIoLseek()
    if (vfd->fd > 0)
        ksceIoLseek(vfd->fd, vfd->item->offset + vfd->offset, SCE_SEEK_SET);
    r = (int)new_offset;
    printf("- sceIoLseek32(0x%08X, 0x%08X, %d) [OVL]: 0x%08X\n", fd, offset, whence, r);

out:
    HOOK_EXIT(r);
}

// If we don't also override the ksceKernelCreateUserUid *import* from SceIofilemgr then,
// because sceIoOpen() is calling ksceIoOpen() behind the scenes and then calling
// ksceKernelCreateUserUid() on the kernel fd, we would have an issue with leaked VPFS
// fds. So we override this call.
// The other option would be to always try to open as a VPFS and only call TAI_CONTINUE
// when that fails (but then we would break chain hooking when dealing with out stuff).
// That's kind of what we do in sceIoClose() because of the taiHEN bug anyway...
// Yet another possible option, if all the user calls are translated to kernel ones
// internally, would would be not to hook the user calls at all, and only do so for the
// kernel ones, and then let ksceKernelCreateUserUid() and ksceKernelKernelUidForUserUid()
// hook translate our stuff...
SceUID ksceKernelCreateUserUid_Hook(SceUID pid, SceUID uid)
{
    HOOK_INIT();

    SceUID r = TAI_CONTINUE(SceUID, hook_ref, pid, uid);
    if ((uid >> 16) == VPFD_MAGIC)
        r = uid;
//    printf("- ksceKernelCreateUserUid(0x%08X, 0x%08X) [ORG]: 0x%08X\n", pid, uid, r);

    HOOK_EXIT(r);
}

SceUID ksceKernelKernelUidForUserUid_Hook(SceUID pid, SceUID uid)
{
    HOOK_INIT();

    SceUID r = TAI_CONTINUE(SceUID, hook_ref, pid, uid);
    if ((uid >> 16) == VPFD_MAGIC)
        r = uid;
//    printf("- ksceKernelKernelUidForUserUid(0x%08X, 0x%08X) [ORG]: 0x%08X\n", pid, uid, r);

    HOOK_EXIT(r);
}

// I don't think we need to care much about this one for now...
//int sceIoPread_Hook(SceUID uid, void *buffer, SceSize size, sceIoPreadOpt *opt)
//{
//    if (hooks[SCEIOPREAD].ref == 0)
//        return SCE_ERROR_ERRNO_EFAULT;
//    int state;
//    ENTER_SYSCALL(state);
//
//    printf("- sceIoPseek(0x%08X) [ORG]\n");
//    int r = TAI_CONTINUE(int, hooks[SCEIOPREAD].ref, uid, buffer, size, opt);
//
//out:
//    EXIT_SYSCALL(state);
//    return r;
//}

// IMPORTANT: Because we are using the __COUNTER__ gcc macro, these
// functions MUST appear in the same order as they are defined above.
// Also, the k calls should NOT be reordered or removed as we must have
// them in a known position to be able to use our _ksce...() functions.
hook_t hooks[] = {
    { ksceIoOpen_Hook, 0x75192972, -1, 0, false },
    { ksceIoClose_Hook, 0xF99DD8A3, -1, 0, false },
    { sceIoDopen_Hook, 0xE6E614B5, -1, 0, false },
    { sceIoDread_Hook, 0x8713D662, -1, 0, false },
    { sceIoDclose_Hook, 0x422A221A, -1, 0, false },
    { sceIoGetstat_Hook, 0x8E7E11F2, -1, 0, false },
    { sceIoOpen_Hook, 0xCC67B6FD, -1, 0, false },
    { sceIoRead_Hook, 0xFDB32293, -1, 0, false, },
    { sceIoLseek_Hook, 0xA604764A, -1, 0, false },
    { sceIoLseek32_Hook, 0x49252B9B, -1, 0, false },
    { ksceKernelCreateUserUid_Hook, 0xBF209859, -1, 0, true },
    { ksceKernelKernelUidForUserUid_Hook, 0x45D22597, -1, 0, true },
};

// https://docs.vitasdk.org/group__SceFcntlUser.html
// 
// Calls we still need:
// - All the kernel/driver counterparts to the above
// Calls we might still need:
// - int sceIoGetDevType(SceUID fd) [?]
// - int sceIoPread(SceUID fd, void *data, SceSize size, SceOff offset) [?]
// - int sceIoWrite(SceUID fd, const void *data, SceSize size) [Should return RO error]
// - int sceIoPwrite(SceUID fd, const void *data, SceSize size, SceOff offset) [Should return RO error]
// - int sceIoRemove(const char *file)
// - int sceIoRename(const char *oldname, const char *newname) [Should return RO error]
// - int sceIoSyncByFd(SceUID fd) [?]
// - SceUID sceIoOpenAsync(const char *file, int flags, SceMode mode)
// - int sceIoCloseAsync(SceUID fd)
// - int sceIoReadAsync(SceUID fd, void *data, SceSize size)
// - int sceIoWriteAsync(SceUID fd, const void *data, SceSize size) [Should return RO error]
// - int sceIoLseekAsync(SceUID fd, SceOff offset, int whence)
// - int sceIoLseek32Async(SceUID fd, int offset, int whence)
// - int sceIoWaitAsync(SceUID fd, SceInt64 *res) [?]
// - int sceIoWaitAsyncCB(SceUID fd, SceInt64 *res) [?]
// - int sceIoPollAsync(SceUID fd, SceInt64 *res) [?]
// - int sceIoGetAsyncStat(SceUID fd, int poll, SceInt64 *res) [?]
// - int sceIoCancel(SceUID fd)
// - int sceIoGetDevType(SceUID fd) [?]
// - int sceIoChangeAsyncPriority(SceUID fd, int pri) [?]
// - int sceIoSetAsyncCallback(SceUID fd, SceUID cb, void *argp) [?]

static void dump_hex(void *buf, size_t size)
{
#define lprintf(...) snprintf(&line[strlen(line)], sizeof(line) - strlen(line) - 1, __VA_ARGS__)
    unsigned char* buffer = (unsigned char*)buf;
    size_t i, j, k;
    char line[80] = "";

    for (i = 0; i < size; i += 16) {
        if (i != 0)
            printf("%s\n", line);
        line[0] = 0;
        lprintf("%08x  ", ((uintptr_t)buf) + i);
        for (j = 0, k = 0; k < 16; j++, k++) {
            if (i + j < size) {
                lprintf("%02x", buffer[i + j]);
            } else {
                lprintf("  ");
            }
            lprintf(" ");
        }
    }
    printf("%s\n", line);
}

// Shamelessly stolen from taiHEN
static void unrestricted_write32(void* dst, uint32_t data)
{
    ksceKernelCpuUnrestrictedMemcpy(dst, &data, sizeof(data));
    uintptr_t vma_align = (uintptr_t)dst & ~0x1F;
    size_t len = (((uintptr_t)dst + sizeof(data) + 0x1F) & ~0x1F) - vma_align;
    ksceKernelCpuDcacheWritebackInvalidateRange((void *)vma_align, len);
    ksceKernelCpuIcacheAndL2WritebackInvalidateRange((void *)vma_align, len);
}

// Module start/stop
void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize argc, const void *args)
{
    int r = -1;

    // We need a handful of mutexes to guard against concurrent calls
    log_mutex = ksceKernelCreateMutex("log_mutex", 0, 0, 0);
    vfd_mutex = ksceKernelCreateMutex("vfd_mutex", 0, 0, 0);
    vpkg_mutex = ksceKernelCreateMutex("vpkg_mutex", 0, 0, 0);

    printf("Loading VPFS kernel driver...\n");
    r = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID,
        SceSblSsMgrAESCTRDecryptForDriver_NID, (uintptr_t*)&sceSblSsMgrAESCTRDecryptForDriver);
    if (r < 0)
        perr("Could not set sceSblSsMgrAESCTRDecryptForDriver: 0x%08X\n", r);

    r = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID,
        SceSblSsMgrSHA1ForDriver_NID, (uintptr_t*)&sceSblSsMgrSHA1ForDriver);
    if (r < 0)
        perr("Could not set sceSblSsMgrSHA1ForDriver: 0x%08X\n", r);

    // Need to hook sceIoClose() manually since taiHEN can't handle it without crashing
    // See https://github.com/yifanlu/taiHEN/issues/84
    r = module_get_export_func(KERNEL_PID, "SceIofilemgr", SceIofilemgr_NID,
        SceIoClose_NID, (uintptr_t*)&sceIoClose_Addr);

    // First 4 bytes should match duplicate code from our override
    // Next 4 bytes should be a long form 'blx'
    if ((NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0] != NO_THUMB_UINT32_PTR(sceIoClose_Override)[3]) ||
        ((NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1] & 0xf800f800) != ASM_BLX_LONG_FORM)) {
        perr("Can't hook sceIoClose(): The code differs from what we can handle!\n");
        dump_hex(sceIoClose_Addr, 0x20);
        return SCE_KERNEL_START_FAILED;
    } else {
        // 0. Reconstruct the blx offset
        uintptr_t offset = (NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1] & 0x7ff) << 12;
        offset |= ((NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1] >> 16) & 0x7ff) << 1;
        offset += 4;
        // 1. set the pointers in our override sceIoClose code
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Override)[6], (uintptr_t)sceIoClose_Addr + 8);
        // blx jumps into an ARM call so make sure we clear the THUMB bit before adding the offset
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Override)[7], (uintptr_t)NO_THUMB_UINT32_PTR(sceIoClose_Addr) + offset);
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Override)[9], (uintptr_t)sceIoClose_Hook);

        // 2. Keep a backup of the bytes we are going to overwrite from the original sceIoClose()
        sceIoClose_Backup[0] = NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0];
        sceIoClose_Backup[1] = NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1];

        // 3. Replace the beginning of the original sceIoClose() to jump to our override
        // Do it in 2 steps by inserting a "return 0", so that we don't have to bother about atomicity
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0], ASM_RETURN_0);
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1], (uintptr_t)sceIoClose_Override);
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0], ASM_JUMP_TO_ADDRESS_BELOW);
    }

    // Set the other file system hooks
    for (int i = 0; i < ARRAYSIZE(hooks); i++) {
        hooks[i].id = hooks[i].import?
            taiHookFunctionImportForKernel(KERNEL_PID, &hooks[i].ref, "SceIofilemgr", TAI_ANY_LIBRARY, hooks[i].nid, hooks[i].func) :
            taiHookFunctionExportForKernel(KERNEL_PID, &hooks[i].ref, "SceIofilemgr", TAI_ANY_LIBRARY, hooks[i].nid, hooks[i].func);
    }

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    printf("Unloading VPFS kernel driver...\n");
    if (sceIoClose_Addr != NULL) {
        // Restore sceIoClose(), once again in 2 steps
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0], ASM_RETURN_0);
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[1], sceIoClose_Backup[1]);
        unrestricted_write32(&NO_THUMB_UINT32_PTR(sceIoClose_Addr)[0], sceIoClose_Backup[0]);
    }

    for (int i = ARRAYSIZE(hooks) - 1; i >= 0; i--) {
        if (hooks[i].id >= 0)
            taiHookReleaseForKernel(hooks[i].id, hooks[i].ref);
    }
    ksceKernelDeleteMutex(vpkg_mutex);
    ksceKernelDeleteMutex(vfd_mutex);
    ksceKernelDeleteMutex(log_mutex);
    return SCE_KERNEL_STOP_SUCCESS;
}
