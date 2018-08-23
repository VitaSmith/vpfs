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

#include "vpfs_driver.h"

#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <psp2/io/dirent.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <taihen.h>

#define LOG_PATH                                "ux0:data/vpfs.log"
#define BUF_SIZE                                164640
#define ROUNDUP(n, width)                       (((n) + (width) - 1) & (~(unsigned int)((width) - 1)))
#define ONE_MB_SIZE                             (1024 * 1024)

#define SceSblSsMgrForDriver_NID                0x61E9428D
#define SceSblSsMgrAESCTRDecryptForDriver_NID   0x7D46768C

#define SceIoDopen_NID                          0xE6E614B5
#define SceIoDread_NID                          0x8713D662

typedef struct sceIoDopenOpt
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

    if (fd >= 0)
    {
        ksceIoWrite(fd, msg, strlen(msg));
        ksceIoClose(fd);
    }
}
#define printf(...) do { snprintf(log_msg, sizeof(log_msg), __VA_ARGS__); log_print(log_msg); } while(0)
#define perr        printf

// Kernel alloc/free functions
int kalloc(char* path, uint32_t size, SceUID* uid, uint8_t** dest)
{
    int r;
    *uid = ksceKernelAllocMemBlock(path, SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, ROUNDUP(size, ONE_MB_SIZE), 0);
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

// Hooks
static SceUID hooks[2];
static int nb_hooks = 0;

static tai_hook_ref_t sceIoDopen_Ref;
static tai_hook_ref_t sceIoDread_Ref;

SceUID sceIoDopen_Hook(const char *dirname, sceIoDopenOpt *opt)
{
    char path[256];
    SceUID fd = TAI_CONTINUE(SceUID, sceIoDopen_Ref, dirname, opt);
    // Copy the user pointer to kernel space for logging
    ksceKernelStrncpyUserToKernel(path, (uintptr_t)dirname, 256);
    printf("- sceIoDopen('%s'): 0x%08X\n", path, fd);
    return fd;
}

int sceIoDread_Hook(SceUID fd, SceIoDirent *dir)
{
    char path[256];
    int r = TAI_CONTINUE(int, sceIoDread_Ref, fd, dir);
    printf("- sceIoDread(0x%08X): 0x%08X\n", fd, r);
    return r;
}

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
    hooks[nb_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &sceIoDopen_Ref, "SceIofilemgr", TAI_ANY_LIBRARY, SceIoDopen_NID, sceIoDopen_Hook);
    hooks[nb_hooks++] = taiHookFunctionExportForKernel(KERNEL_PID, &sceIoDread_Ref, "SceIofilemgr", TAI_ANY_LIBRARY, SceIoDread_NID, sceIoDread_Hook);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    printf("Unloading VPFS kernel driver...\n");
    if (hooks[--nb_hooks] >= 0)
        taiHookReleaseForKernel(hooks[nb_hooks], sceIoDread_Ref);
    if (hooks[--nb_hooks] >= 0)
        taiHookReleaseForKernel(hooks[nb_hooks], sceIoDopen_Ref);
    return SCE_KERNEL_STOP_SUCCESS;
}
