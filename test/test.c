/*
 * VPFS Test - Copyright © 2018 VitaSmith
 * Based on libftpvita sample - Copyright © 2015 Sergi Granell (xerpi)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <taihen.h>

#include <psp2/ctrl.h>
#include <psp2/display.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <psp2/io/stat.h>

#include "console.h"

#define VERSION             "0.6"
#define VPFS_SKPRX          "ux0:tai/vpfs.skprx"
#define ARRAYSIZE(A)        (sizeof(A)/sizeof((A)[0]))
#define perr(...)           do { console_set_color(RED); printf(__VA_ARGS__); console_set_color(WHITE); } while(0);

SceUID module_id = -1;

char* root_list[] = {
    "sce_sys/",
    "sce_module/",
    "eboot.bin",
    "Data/",
    "Disc/",
    "sce_pfs/",
};

char* sce_sys_list[] = {
    "about/",
    "livearea/",
    "manual/",
    "trophy/",
    "param.sfo",
    "clearsign",
    "icon0.png",
    "keystone",
    "pic0.png",
    "package/",
};

char* Disc_Car_list[] = {
    "Car_01/",
    "Car_02/",
    "Car_03/",
    "Car_04/",
    "Car_05/",
    "Car_06/",
    "Car_07/",
};

static bool module_load(void)
{
    module_id = taiLoadStartKernelModule(VPFS_SKPRX, 0, NULL, 0);
    if (module_id < 0) {
        perr("Could not load kernel module: 0x%08X\n", module_id);
        return false;
    }
    return true;
}

static bool module_unload(void)
{
    if (module_id < 0)
        return false;
    int r = taiStopUnloadKernelModule(module_id, 0, NULL, 0, NULL, NULL);
    if (r < 0) {
        perr("Could not unload kernel module: 0x%08X\n", r);
        return false;
    }
    return true;
}

static SceIoStat* get_dir_entry_stat(const char* path, const char* entry)
{
    static SceIoDirent dir;
    memset(&dir, 0, sizeof(dir));
    SceUID fd = sceIoDopen(path);
    if (fd < 0)
        return NULL;
    while (sceIoDread(fd, &dir) > 0) {
        if (strcmp(dir.d_name, entry) == 0) {
            sceIoDclose(fd);
            return &dir.d_stat;
        }
    }
    sceIoDclose(fd);
    return NULL;
}

static bool compare_dir_list(char* path, char** list, size_t len)
{
    static SceIoDirent dir;
    memset(&dir, 0, sizeof(dir));
    SceUID fd = sceIoDopen(path);
    if (fd < 0)
        return NULL;
    for (int i = 0; i < len; i++) {
        if (sceIoDread(fd, &dir) <= 0) {
            sceIoDclose(fd);
            return false;
        }
        // Add an extra slash for directories
        if (SCE_S_ISDIR(dir.d_stat.st_mode)) {
            size_t len = strlen(dir.d_name);
            dir.d_name[len] = '/';
            dir.d_name[len + 1] = 0;
        }
        if (strcmp(dir.d_name, list[i]) != 0) {
            perr("Expected '%s' but got '%s'\n", list[i], dir.d_name);
            sceIoDclose(fd);
            return false;
        }
    }
    if (sceIoDread(fd, &dir) != 0) {
        perr("Extra directory element found '%s'\n", dir.d_name);
        sceIoDclose(fd);
        return false;
    }
    sceIoDclose(fd);
    return true;
}

static bool test_for_directory(char* dir, char* subdir)
{
    SceIoStat* stat = get_dir_entry_stat(dir, subdir);
    if (stat == NULL)
        return false;
    if (!SCE_S_ISDIR(stat->st_mode))
        return false;
    return true;
}

static bool test_for_file_size(char* dir, char* file, uint64_t size)
{
    SceIoStat* stat = get_dir_entry_stat(dir, file);
    if (stat == NULL) {
        perr("'%s' was not found in '%s'\n", file, dir);
        return false;
    }
    if (!SCE_S_ISREG(stat->st_mode)) {
        perr("'%s' is not a regular file\n", file);
        return false;
    }
    if (stat->st_size != size) {
        perr("Expected %lld bytes but got %lld bytes\n", size, stat->st_size);
        return false;
    }
    return true;
}

static bool test_stat(char* path, uint64_t size)
{
    SceIoStat stat = { 0 };
    int r = sceIoGetstat(path, &stat);
    if (r < 0) {
        perr("Failed to get stat for '%s': Error 0x%08X\n", path, r);
        return false;
    }
    if ((path[strlen(path) - 1] == '/') && (!SCE_S_ISDIR(stat.st_mode))) {
        perr("'%s' is not reported as a directory\n", path);
        return false;
    } else if ((path[strlen(path) - 1] != '/') && (!SCE_S_ISREG(stat.st_mode))) {
        perr("'%s' is not reported as a regular file\n", path);
        return false;
    }
    if (SCE_S_ISREG(stat.st_mode) && (stat.st_size != size)) {
        perr("Expected %lld bytes but got %lld bytes\n", size, stat.st_size);
        return false;
    }
    return true;
}

static bool test_vpfs_file(char* path)
{
    SceIoStat stat = { 0 };
    int r = sceIoGetstat(path, &stat);
    if (r < 0) {
        perr("'%s' is not present\n", path);
        return false;
    }
    // TODO: Open VPFS file and check header
    return true;
}

static bool test_open_file(char* path)
{
    SceUID fd = sceIoOpen(path, SCE_O_RDONLY, 0777);
    if (fd < 0) {
        perr("Could not open '%s': 0x%08X\n", path, fd);
        return false;
    }
    int r = sceIoClose(fd);
    if (r < 0) {
        perr("Could not close '%s': 0x%08X\n", path, r);
        return false;
    }
    return true;
}

#define DISPLAY_TEST(msg, func, ...) \
    r = func(__VA_ARGS__); \
    console_set_color(r ? GREEN : RED); printf(r ? "[PASS] " : "[FAIL] "); console_set_color(WHITE); printf("%s\n", msg)

#define DISPLAY_TEST_OR_OUT(msg, func, ...) \
    DISPLAY_TEST(msg, func, __VA_ARGS__); \
    if (!r) goto out

int main()
{
    int r = -1;
    SceCtrlData pad;

    init_video();
    console_init();

    printf("vpfs_test v" VERSION " - Vita PKG Filesystem tester\n");
    printf("Copyright (c) 2018 VitaSmith (GPLv3)\n\n");

    DISPLAY_TEST_OR_OUT("VPFS file is present", test_vpfs_file, "ux0:app/PCSE00001.vpfs");
    DISPLAY_TEST_OR_OUT("VPFS module can be loaded", module_load);
    DISPLAY_TEST("Regular directory is listed in 'ux0:app'", test_for_directory, "ux0:app", "VPFS00000");
    DISPLAY_TEST("Regular file is listed in 'ux0:app'", test_for_file_size, "ux0:app/VPFS00000/sce_sys/package", "work.bin", 512);
    DISPLAY_TEST("Virtual directory is present in 'ux0:app'", test_for_directory, "ux0:app", "PCSE00001");
    DISPLAY_TEST("Size of 'eboot.bin'", test_for_file_size, "ux0:app/PCSE00001", "eboot.bin", 1160512);
    DISPLAY_TEST("Size of 'sce_sys/param.sfo'", test_for_file_size, "ux0:app/PCSE00001/sce_sys", "param.sfo", 1988);
    DISPLAY_TEST("Size of 'sce_sys/pic0.png'", test_for_file_size, "ux0:app/PCSE00001/sce_sys", "pic0.png", 196229);
    DISPLAY_TEST("Size of 'sce_sys/package/head.bin'", test_for_file_size, "ux0:app/PCSE00001/sce_sys/package", "head.bin", 29680);
    DISPLAY_TEST("Size of 'sce_sys/package/stat.bin'", test_for_file_size, "ux0:app/PCSE00001/sce_sys/package", "stat.bin", 768);
    DISPLAY_TEST("Size of 'sce_sys/package/work.bin'", test_for_file_size, "ux0:app/PCSE00001/sce_sys/package", "work.bin", 512);
    DISPLAY_TEST("Content of 'ux0:app/PCSE00001'", compare_dir_list, "ux0:app/PCSE00001", root_list, ARRAYSIZE(root_list));
    DISPLAY_TEST("Content of 'ux0:app/PCSE00001/sce_sys'", compare_dir_list, "ux0:app/PCSE00001/sce_sys", sce_sys_list, ARRAYSIZE(sce_sys_list));
    DISPLAY_TEST("Content of 'ux0:app/PCSE00001/Disc/Car'", compare_dir_list, "ux0:app/PCSE00001/Disc/Car", Disc_Car_list, ARRAYSIZE(Disc_Car_list));
    DISPLAY_TEST("Regular directory is listed in 'ux0:app' (GetStat)", test_stat, "ux0:app/VPFS00000/", 0);
    DISPLAY_TEST("Regular file is listed in 'ux0:app' (GetStat)", test_stat, "ux0:app/VPFS00000/sce_sys/package/work.bin", 512);
    DISPLAY_TEST("Virtual directory is present in 'ux0:app' (GetStat)", test_stat, "ux0:app/PCSE00001/", 0);
    DISPLAY_TEST("Size of 'eboot.bin' (GetStat)", test_stat, "ux0:app/PCSE00001/eboot.bin", 1160512);
    DISPLAY_TEST("Open 'eboot.bin'", test_open_file, "ux0:app/PCSE00001/eboot.bin");
    DISPLAY_TEST("VPFS module can be unloaded", module_unload);

out:
    console_set_color(CYAN);
    printf("\nPress X to exit.\n");
    do {
        sceCtrlPeekBufferPositive(0, &pad, 1);
    } while (!(pad.buttons & SCE_CTRL_CROSS));
    console_exit();
    end_video();
    sceKernelExitProcess(0);
    return 0;
}
