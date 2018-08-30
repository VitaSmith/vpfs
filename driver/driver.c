/*
  VPFS - Vita PKG File System, kernel driver
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

#include "../vpfs.h"
#include "../vpfs_utils.h"
#include "driver.h"

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

#define LOG_PATH                                "ux0:data/vpfs.log"
#define ROUNDUP(n, width)                       (((n) + (width) - 1) & (~(unsigned int)((width) - 1)))
#define ONE_KB_SIZE                             1024
#define ONE_MB_SIZE                             (1024 * 1024)
#define ARRAYSIZE(A)                            (sizeof(A)/sizeof((A)[0]))
#define MAX_PATH                                122
#define MAX_FDS                                 16
#define VPFD_MAGIC                              0x5FF5

#define SCE_ERROR_ERRNO_ENOENT                  0x80010002
#define SCE_ERROR_ERRNO_EIO                     0x80010005
#define SCE_ERROR_ERRNO_ENOMEM                  0x8001000C
#define SCE_ERROR_ERRNO_EACCES                  0x8001000D
#define SCE_ERROR_ERRNO_EFAULT                  0x8001000E
#define SCE_ERROR_ERRNO_ENOTDIR                 0x80010014
#define SCE_KERNEL_ERROR_INVALID_ARGUMENT       0x80020003

#define SceSblSsMgrForDriver_NID                0x61E9428D
#define SceSblSsMgrAESCTRDecryptForDriver_NID   0x7D46768C
#define SceSblSsMgrSHA1ForDriver_NID            0xEB3AF9B5

static char vpfs_ext[] = ".vpfs";

typedef struct
{
    uint32_t unk_0;
    uint32_t unk_4;
} sceIoDopenOpt;

typedef int (sceSblSsMgrAESCTRDecryptForDriver_t)(uint8_t *src, uint8_t *dst, const uint32_t size, const uint8_t *key, const uint32_t key_size, uint8_t *iv, uint32_t mask_enable);
sceSblSsMgrAESCTRDecryptForDriver_t*            sceSblSsMgrAESCTRDecryptForDriver = NULL;
typedef int (sceSblSsMgrSHA1ForDriver_t)(const char *src, uint8_t *dst, size_t size, uint8_t *iv, uint32_t mask_enable, uint32_t command_bit);
sceSblSsMgrSHA1ForDriver_t*                     sceSblSsMgrSHA1ForDriver = NULL;

static uint8_t empty_sha1sum[20] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};

// Missing taihen exports
extern int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

// Log functions
static char log_msg[256];
static void log_print(const char* msg)
{
    SceUID fd = ksceIoOpen(LOG_PATH, SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0777);

    if (fd >= 0) {
        ksceIoWrite(fd, msg, strlen(msg));
        ksceIoClose(fd);
    }
}
#define printf(...) do { snprintf(log_msg, sizeof(log_msg), __VA_ARGS__); log_print(log_msg); } while(0)
#define perr        printf

// Kernel alloc/free functions
int kalloc(const char* path, uint32_t size, SceUID* uid, uint8_t** dest)
{
    int r;
    *uid = ksceKernelAllocMemBlock(path, SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, ROUNDUP(size, ONE_KB_SIZE), 0);
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
    uint8_t *aes_src = NULL, *aes_dst = NULL, *aes_key = NULL, *aes_iv = NULL;
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
    r = kalloc("aes_key", (kargs.key_size / 8), &aes_key_uid, &aes_key);
    if (r < 0)
        goto out;

    // Allocate iv buffer
    r = kalloc("aes_ic", 0x10, &aes_iv_uid, &aes_iv);
    if (r < 0)
        goto out;

    // Copy source to kernel
    r = ksceKernelMemcpyUserToKernel(aes_src, (uintptr_t)kargs.src, kargs.size);
    if (r < 0)
        goto out;

    // Copy key to kernel
    r = ksceKernelMemcpyUserToKernel(aes_key, (uintptr_t)kargs.key, kargs.key_size / 8);
    if (r < 0)
        goto out;

    // Copy iv to kernel
    r = ksceKernelMemcpyUserToKernel(aes_iv, (uintptr_t)kargs.iv, 0x10);
    if (r < 0)
        goto out;

    // Call function
    r = sceSblSsMgrAESCTRDecryptForDriver(aes_src, aes_dst, kargs.size, aes_key, kargs.key_size, aes_iv, kargs.mask_enable);
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

// Helper functions

typedef struct
{
    // TODO: path, uid and data should be a separate struct
    // we point to so that we can have multiple fds using the
    // same underlying vpfs. Especially important for deletion!
    char        path[MAX_PATH + sizeof(vpfs_ext)];
    SceUID      uid;
    uint8_t*    data;
    uint32_t    dir_offset;
} vfd_t;

static vfd_t    vfd[MAX_FDS] = { 0 };
static uint16_t vfd_index = 0;
static SceUID   vfd_mutex;

static uint16_t vfd_get_index(void)
{
    ksceKernelLockMutex(vfd_mutex, 1, 0);
    for (uint16_t i = 0; i < ARRAYSIZE(vfd); i++) {
        if ((vfd[i].data == NULL) && (vfd[i].uid >= 0)) {
            // Set negative uid to prevent duplicate use of this index
            // when relinquishing the mutex
            vfd[i].uid = -1;
            ksceKernelUnlockMutex(vfd_mutex, 1);
            return i;
        }
    }
    ksceKernelUnlockMutex(vfd_mutex, 1);
    return 0xFFFF;
}

static SceUID vpfs_open(const char *path)
{
    uint8_t* data;
    SceUID uid = -1, fd = -1, r = SCE_ERROR_ERRNO_ENOENT;
    SceIoStat stat;

    // First, check if the VPFS path exists and is a regular file
    if ((ksceIoGetstat(path, &stat) < 0) || (!SCE_S_ISREG(stat.st_mode)))
        return SCE_ERROR_ERRNO_ENOENT;

    // Allocate memory to cache the VPFS data
    if (kalloc(path, stat.st_size, &uid, &data) < 0)
        return SCE_ERROR_ERRNO_ENOMEM;

    fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        perr("Could not open '%s': 0x%08X\n", path, fd);
        goto out;
    }
    // Sanity check
    if (stat.st_size < sizeof(vpfs_header_t) + sizeof(vpfs_pkg_t) + sizeof(uint32_t) + sizeof(vpfs_item_t)) {
        perr("VPFS file is too small\n");
        goto out;
    }

    // TODO: Don't cache the local data after the directories, in case we have large data items
    int read = ksceIoRead(fd, data, stat.st_size);
    if (read != stat.st_size) {
        perr("Could not read VPFS data: 0x%08X\n", read);
        r = SCE_ERROR_ERRNO_EIO;
        goto out;
    }
    vpfs_header_t* header = (vpfs_header_t*)data;
    if (header->magic != VPFS_MAGIC) {
        perr("Invalid VPFS magic\n");
        r = SCE_ERROR_ERRNO_EACCES;
        goto out;
    }

    uint16_t index = vfd_get_index();
    vfd[index].uid = uid;
    vfd[index].data = data;
    strncpy(vfd[index].path, path, sizeof(vfd[index].path));
    r = (VPFD_MAGIC << 16) | index;

out:
    if (fd >= 0)
        ksceIoClose(fd);
    if ((r < 0) && (uid >= 0))
        kfree(uid);
    return r;
}

static int vpfs_close(SceUID fd)
{
    if ((fd >> 16) != VPFD_MAGIC)
        return SCE_ERROR_ERRNO_EACCES;
    uint16_t index = (uint16_t)fd;
    if (vfd[index].uid >= 0)
        kfree(vfd[index].uid);
    vfd[index].uid = 0;
    vfd[index].data = NULL;
    return 0;
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

// Hooks
#define SCEIODOPEN      0
#define SCEIODREAD      1
#define SCEIODCLOSE     2

typedef struct {
    void*           func;
    uint32_t        nid;
    SceUID          id;
    tai_hook_ref_t  ref;
} hook_t;

hook_t hooks[];

SceUID sceIoDopen_Hook(const char *dirname, sceIoDopenOpt *opt)
{
    int r;
    char path[MAX_PATH + sizeof(vpfs_ext)];
    char bck[sizeof(vpfs_ext)];
    size_t i;
    SceUID fd = SCE_ERROR_ERRNO_ENOENT;

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
        fd = TAI_CONTINUE(SceUID, hooks[SCEIODOPEN].ref, dirname, opt);
//        printf("- sceIoDopen('%s') [ORG]: 0x%08X\n", path, fd);
        return fd;
    }

    memcpy(&path[i], bck, sizeof(vpfs_ext));
    // We have an opened vfd -> process it
    uint16_t index = (uint16_t)fd;
    vpfs_item_t* item = vpfs_find_item(vfd[index].data, &path[i + 1]);
    if (item == NULL) {
        printf("- sceIoDopen('%s') [OVL]: Entry not found in .vpfs\n", &path[i + 1]);
        return SCE_ERROR_ERRNO_ENOENT;
    }

    // Check our data
    if (!(item->flags & VPFS_ITEM_TYPE_DIR)) {
        printf("- sceIoDopen('%s') [OVL]: Item found is not a directory\n", path);
        return SCE_ERROR_ERRNO_ENOTDIR;
    }
    if (item->flags & VPFS_ITEM_DELETED) {
        printf("- sceIoDopen('%s') [OVL]: Item was deleted\n", path);
        return SCE_ERROR_ERRNO_ENOENT;
    }
    if (item->pkg_index > 0) {
        printf("- sceIoDopen('%s') [OVL]: Directory offset is not in VPFS file\n", path);
        return SCE_ERROR_ERRNO_EFAULT;
    }
    vfd[index].dir_offset = (uint32_t)item->offset;
    printf("- sceIoDopen('%s') [OVL]: 0x%08X\n", path, fd);
    return fd;
}

int sceIoDread_Hook(SceUID fd, SceIoDirent *dir)
{
    if ((fd >> 16) != VPFD_MAGIC) {
        // Regular directory -> use standard call while converting any '.vpfs' file to a virtual directory
        int r = TAI_CONTINUE(int, hooks[SCEIODREAD].ref, fd, dir);
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
        return r;
    }

    // Virtual directory
    uint16_t index = (uint16_t)fd;
    const char* path = (const char*)&vfd[index].data[vfd->dir_offset];
    size_t len = strlen(path);
    if (len == 0)
        // No more content in this directory
        return 0;

    SceIoStat stat = { 0 };
    vpfs_item_t* item = vpfs_find_item(vfd->data, path);
    if (item == NULL) {
        printf("- sceIoDread('%s') [OVL]: Entry not found in .vpfs\n", path);
        return SCE_ERROR_ERRNO_ENOENT;
    }
    // TODO: Check for VPFS_ITEM_DELETED and skip deleted items
    const char* name = basename(path);
    ksceKernelMemcpyKernelToUser((uintptr_t)dir->d_name, name, strlen(name) + 1);
    if (item->flags & VPFS_ITEM_TYPE_DIR) {
        stat.st_mode = SCE_S_IFDIR | SCE_S_IRUSR | SCE_S_IROTH;
    } else {
        stat.st_mode = SCE_S_IFREG | SCE_S_IRUSR | SCE_S_IROTH;
        stat.st_size = item->size;
    }
    ksceKernelMemcpyKernelToUser((uintptr_t)dir, &stat, sizeof(stat));
    vfd[index].dir_offset += len + 1;

    //        printf("- sceIoDread(0x%08X) [OVL]: 0x%08X\n", fd, r);
    return 1;
}

int sceIoDClose_Hook(SceUID fd)
{
    int r = SCE_ERROR_ERRNO_ENOENT;
    if ((fd >> 16) != VPFD_MAGIC) {
        r = TAI_CONTINUE(int, hooks[SCEIODCLOSE].ref, fd);
//        printf("- sceIoDClose(0x%08X) [ORG]: 0x%08X\n", fd, r);
    } else {
        r = vpfs_close(fd);
        printf("- sceIoDClose(0x%08X) [OVL]: 0x%08X\n", fd, r);
    }
    return r;
}

hook_t hooks[] = {
    { sceIoDopen_Hook, 0xE6E614B5, -1, 0 },
    { sceIoDread_Hook, 0x8713D662, -1, 0 },
    { sceIoDClose_Hook, 0x422A221A, -1, 0 },
};


// Module start/stop
void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize argc, const void *args)
{
    int r = -1;
    printf("Loading VPFS kernel driver...\n");
    // TODO: re-enable this when we start exporting 
    //r = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID,
    //    SceSblSsMgrAESCTRDecryptForDriver_NID, (uintptr_t*)&sceSblSsMgrAESCTRDecryptForDriver);
    //if (r < 0)
    //    perr("Could not set sceSblSsMgrAESCTRDecryptForDriver: 0x%08X\n", r);

    r = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID,
        SceSblSsMgrSHA1ForDriver_NID, (uintptr_t*)&sceSblSsMgrSHA1ForDriver);
    if (r < 0)
        perr("Could not set sceSblSsMgrSHA1ForDriver: 0x%08X\n", r);

    // Set the file system hooks
    for (int i = 0; i < ARRAYSIZE(hooks); i++)
        hooks[i].id = taiHookFunctionExportForKernel(KERNEL_PID, &hooks[i].ref, "SceIofilemgr", TAI_ANY_LIBRARY, hooks[i].nid, hooks[i].func);

    // We need a mutex to prevent concurrency on vfd index attribution
    vfd_mutex = ksceKernelCreateMutex("VfdMutex", 0, 0, 0);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    printf("Unloading VPFS kernel driver...\n");
    for (int i = ARRAYSIZE(hooks) - 1; i >= 0; i--) {
        if (hooks[i].id >= 0)
            taiHookReleaseForKernel(hooks[i].id, hooks[i].ref);
    }
    ksceKernelDeleteMutex(vfd_mutex);
    return SCE_KERNEL_STOP_SUCCESS;
}
