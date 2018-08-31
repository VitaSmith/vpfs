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
#include <inttypes.h>
#include <string.h>
#include <taihen.h>

#include <psp2/ctrl.h>
#include <psp2/sqlite.h>
#include <psp2/display.h>
#include <psp2/apputil.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>

#include "console.h"

#define VERSION             "0.6"
#define DIRECTORY           "ux0:app/PCSE00001/sce_sys"
#define VPFS_SKPRX          "ux0:tai/vpfs.skprx"
#define ARRAYSIZE(A)        (sizeof(A)/sizeof((A)[0]))
#define perr(...)           do { console_set_color(RED); printf(__VA_ARGS__); console_set_color(WHITE); } while(0);

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


SceIoStat* get_dir_entry_stat(const char* path, const char* entry)
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

bool compare_dir_list(char* path, char** list, size_t len)
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

bool test_for_directory(char* dir, char* subdir)
{
    SceIoStat* stat = get_dir_entry_stat(dir, subdir);
    if (stat == NULL)
        return false;
    if (!SCE_S_ISDIR(stat->st_mode))
        return false;
    return true;
}

bool test_for_file_size(char* dir, char* file, uint64_t size)
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

#define DISPLAY_TEST(msg, func, ...) \
    r = func(__VA_ARGS__); \
    console_set_color(r ? GREEN : RED); printf(r ? "[PASS] " : "[FAIL] "); console_set_color(WHITE); printf("%s\n", msg);

int main()
{
    int r = -1;
    SceUID module_id = -1;
    SceCtrlData pad;

    init_video();
    console_init();

    printf("vpfs_test v" VERSION " - Vita PKG Filesystem tester\n");
    printf("Copyright (c) 2018 VitaSmith (GPLv3)\n\n");

    module_id = taiLoadStartKernelModule(VPFS_SKPRX, 0, NULL, 0);
    if (module_id < 0) {
        perr("Could not load kernel module: 0x%08X\n", module_id);
        goto out;
    }

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

out:
    if (module_id >= 0) {
        r = taiStopUnloadKernelModule(module_id, 0, NULL, 0, NULL, NULL);
        if (r < 0)
            perr("Could not unload kernel module: 0x%08X\n", r);
    }
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
