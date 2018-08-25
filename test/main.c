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

#define VERSION             "0.4"
#define DIRECTORY           "ux0:app/PCSE00001"
#define VPFS_SKPRX          "ux0:tai/vpfs.skprx"
#define perr(...)           do { console_set_color(RED); printf(__VA_ARGS__); console_set_color(WHITE); } while(0);

int main()
{
    int r = -1;
    SceUID module_id = -1;
    SceCtrlData pad;
    SceIoDirent dir = { 0 };
    memset(&dir, 0, sizeof(SceIoDirent));

    init_video();
    console_init();

    printf("vpfs_test v" VERSION " - Vita PKG Filesystem tester\n");
    printf("Copyright (c) 2018 VitaSmith (GPLv3)\n\n");

    module_id = taiLoadStartKernelModule(VPFS_SKPRX, 0, NULL, 0);
    if (module_id < 0) {
        perr("Could not load kernel module: 0x%08X\n", module_id);
        goto out;
    }

    SceUID fd = sceIoDopen(DIRECTORY);
    if (fd < 0) {
        perr("Could not open directory '%s': 0x%08X\n", DIRECTORY, fd);
        goto out;
    }
    while ((r = sceIoDread(fd, &dir)) > 0) {
        printf("o %s%s\n", dir.d_name, SCE_S_ISDIR(dir.d_stat.st_mode) ? "/" : "");
    }
    if (r < 0) {
        perr("Could not read directory entry: 0x%08X\n", r);
        goto out;
    }
    sceIoDclose(fd);

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
