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
#include "vpfs_driver.h"

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
#define MAX_PATH                                128

#define SCE_ERROR_ERRNO_ENOENT                  0x80010002
#define SCE_ERROR_ERRNO_EIO                     0x80010005
#define SCE_ERROR_ERRNO_ENOMEM                  0x8001000C
#define SCE_ERROR_ERRNO_EACCES                  0x8001000D

#define SceSblSsMgrForDriver_NID                0x61E9428D
#define SceSblSsMgrAESCTRDecryptForDriver_NID   0x7D46768C

static char vpfs_ext[] = ".vpfs";

typedef struct
{
    uint32_t unk_0;
    uint32_t unk_4;
} sceIoDopenOpt;

typedef int (sceSblSsMgrAESCTRDecryptForDriver_t)(uint8_t *src, uint8_t *dst, const uint32_t size, const uint8_t *key, const uint32_t key_size, uint8_t *iv, uint32_t mask_enable);
sceSblSsMgrAESCTRDecryptForDriver_t*            sceSblSsMgrAESCTRDecryptForDriver = NULL;

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
    uint32_t    magic;
    char        path[MAX_PATH + sizeof(vpfs_ext)];
    SceUID      uid;
    uint8_t*    data;
} vfd_t;

// TODO: allocate this
static vfd_t vfd;

SceUID vpfs_open(const char *path)
{
    SceUID fd = -1;
    vfd.uid = -1;
    SceUID r = SCE_ERROR_ERRNO_ENOENT;
    SceIoStat stat;

    // First, check if the VPFS path exists and is a regular file
    if ((ksceIoGetstat(path, &stat) < 0) || (!SCE_S_ISREG(stat.st_mode)))
        return SCE_ERROR_ERRNO_ENOENT;

    // Allocate memory to cache the VPFS data
    if (kalloc(path, stat.st_size, &vfd.uid, &vfd.data) < 0)
        return SCE_ERROR_ERRNO_ENOMEM;

    fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        perr("Could not open '%s': 0x%08X\n", path, fd);
        goto out;
    }

    int read = ksceIoRead(fd, vfd.data, stat.st_size);
    if (read != stat.st_size) {
        perr("Could not read VPFS data: 0x%08X\n", read);
        r = SCE_ERROR_ERRNO_EIO;
        goto out;
    }
    vpfs_header_t* header = (vpfs_header_t*)vfd.data;
    if (header->magic != VPFS_MAGIC) {
        perr("Invalid VPFS magic\n");
        r = SCE_ERROR_ERRNO_EACCES;
        goto out;
    }

    vfd.magic = VPFD_MAGIC;
    strncpy(vfd.path, path, sizeof(vfd.path));
    r = (SceUID)&vfd;

out:
    if (fd >= 0)
        ksceIoClose(fd);
    if ((r < 0) && (vfd.uid >= 0))
        kfree(vfd.uid);
    return r;
}

int vpfs_close(SceUID fd)
{
    vfd_t* vfd = (vfd_t*)fd;
    if (vfd->magic != VPFD_MAGIC)
        return SCE_ERROR_ERRNO_EACCES;
    if (vfd->uid >= 0)
        kfree(vfd->uid);
    return 0;
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
    if (path[len - 1] != '/') {
        path[len] = '/';
        path[len + 1] = 0;
    }
    for (i = len; i > 0; i--) {
        if (path[i] == '/') {
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
        printf("- sceIoDopen('%s') [ORG]: 0x%08X\n", path, fd);
        return fd;
    }

    // We have an opened vfd -> process it
    vfd_t* vfd = (vfd_t*)fd;
    vpfs_header_t* header = (vpfs_header_t*)vfd->data;

    // TODO: SHA-1 of remainder path
    // TODO: Lookup in short SHA-1
    // TODO: Item offset from short SHA-1

    printf("  NB pkgs = %d\n", header->nb_pkgs);
    printf("  NB items = %d\n", header->nb_items);
    //uint32_t offset = sizeof(vpfs_header_t) +
    //    header.nb_pkgs * sizeof(vpfs_pkg_t) +
    //    header.nb_items * (sizeof(uint32_t) + sizeof(vpfs_item_t));

    // TODO: Store the index of the path in our struct
    memcpy(&path[i], bck, sizeof(vpfs_ext));
    printf("  REMAINDER PATH: '%s'\n", &path[i+1]);

    printf("- sceIoDopen('%s') [OVR]: 0x%08X\n", path, fd);
    return fd;
}

int sceIoDread_Hook(SceUID fd, SceIoDirent *dir)
{
    int r = TAI_CONTINUE(int, hooks[SCEIODREAD].ref, fd, dir);
    printf("- sceIoDread(0x%08X): 0x%08X\n", fd, r);
    return r;
}

int sceIoDClose_Hook(SceUID fd)
{
    int r = SCE_ERROR_ERRNO_ENOENT;
    // We're kind of gambling that Sony's native FDs are always within memory
    // we can address, and that we can attempt to read the data they point to.
    // Then again, if this is a bad gamble, the system will definitely let us know...
    vfd_t* vfd = (vfd_t*)fd;
    printf("IN sceIoDClose...\n");
    if (vfd->magic != VPFD_MAGIC) {
        r = TAI_CONTINUE(int, hooks[SCEIODCLOSE].ref, fd);
    } else {
        r = vpfs_close(fd);
    }
    printf("- sceIoDClose(0x%08X): 0x%08X\n", fd, r);
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
    //else 
    //    printf("sceSblSsMgrAESCTRDecryptForDriver successfully set.\n");

    // Set the file system hooks
    for (int i = 0; i < ARRAYSIZE(hooks); i++)
        hooks[i].id = taiHookFunctionExportForKernel(KERNEL_PID, &hooks[i].ref, "SceIofilemgr", TAI_ANY_LIBRARY, hooks[i].nid, hooks[i].func);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    printf("Unloading VPFS kernel driver...\n");
    for (int i = ARRAYSIZE(hooks) - 1; i >= 0; i--) {
        if (hooks[i].id >= 0)
            taiHookReleaseForKernel(hooks[i].id, hooks[i].ref);
    }
    return SCE_KERNEL_STOP_SUCCESS;
}
