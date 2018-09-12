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

uint8_t work_bin[] = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x55, 0x50, 0x30, 0x37, 0x30, 0x30, 0x2d, 0x50, 0x43, 0x53, 0x45, 0x30, 0x30, 0x30, 0x30, 0x31,
    0x5f, 0x30, 0x30, 0x2d, 0x52, 0x49, 0x44, 0x47, 0x45, 0x52, 0x41, 0x43, 0x45, 0x52, 0x50, 0x53,
    0x56, 0x49, 0x54, 0x41
};

uint8_t tail_bin[] = {
    0x4c, 0x08, 0x4e, 0x8d, 0xe0, 0x7b, 0xff, 0xda, 0xa1, 0x44, 0x35, 0x29, 0x9c, 0xa2, 0x54, 0xf0,
    0xed, 0x42, 0xe1, 0x17, 0x2e, 0x21, 0xe3, 0x09, 0xca, 0xff, 0x43, 0x37, 0xd9, 0xef, 0x19, 0x16,
    0x06, 0x26, 0x67, 0x34, 0x71, 0x50, 0xe4, 0x3b, 0x0d, 0x73, 0x48, 0x4f, 0xa2, 0x24, 0xd9, 0xfc,
    0xec, 0x21, 0x8e, 0x44, 0xa4, 0x50, 0x50, 0x7e, 0x88, 0xba, 0xaa, 0x4c, 0x35, 0x6c, 0x33, 0x91,
    0x82, 0x37, 0x75, 0x3b, 0x1c, 0x00, 0xcb, 0x24, 0x03, 0x37, 0xac, 0xe1, 0xd3, 0x3d, 0x55, 0xd3,
    0x44, 0x23, 0x34, 0x81, 0x95, 0xac, 0x88, 0x58, 0xa4, 0x1f, 0xeb, 0xc7, 0x92, 0xba, 0x12, 0x39,
    0xd8, 0x66, 0x70, 0x3c, 0x2a, 0xde, 0xb4, 0x65, 0xf1, 0xbe, 0x77, 0x6e, 0x5f, 0xe8, 0x21, 0xcb,
    0x2d, 0xca, 0x65, 0x41, 0x8b, 0xfe, 0x50, 0x46, 0x66, 0x88, 0xfb, 0x0e, 0x8a, 0x4a, 0x71, 0x81,
    0x39, 0x13, 0xbc, 0xbe, 0x74, 0x71, 0x0e, 0x7d, 0x59, 0x85, 0x48, 0xca, 0xe5, 0x55, 0xb0, 0xd9,
    0x8c, 0xf9, 0x25, 0x78, 0xf0, 0x77, 0x07, 0x7d, 0x5a, 0x8c, 0xc7, 0x49, 0x80, 0x64, 0x32, 0x5c,
    0x59, 0xf8, 0x3e, 0xaa, 0xcd, 0x32, 0x56, 0xec, 0xb0, 0x26, 0xec, 0xe8, 0xba, 0xfb, 0xee, 0x3a,
    0x7f, 0xc1, 0xe0, 0x19, 0x7e, 0x8a, 0xb9, 0x23, 0xa8, 0x39, 0xa2, 0x7d, 0x6f, 0x34, 0xdd, 0x50,
    0xac, 0xe2, 0x77, 0xed, 0x45, 0xd9, 0xea, 0x2a, 0x44, 0x8e, 0xdd, 0xcc, 0xf8, 0xc9, 0x38, 0x6d,
    0x14, 0x49, 0x56, 0xf6, 0x25, 0x00, 0x49, 0x45, 0xb5, 0x3c, 0xf3, 0x5d, 0x08, 0xb7, 0xf2, 0xf6,
    0xed, 0x9f, 0x9d, 0xc2, 0xcb, 0x43, 0x04, 0xc3, 0xcd, 0xdf, 0x54, 0x99, 0x41, 0x80, 0x31, 0x1d,
    0x3c, 0x26, 0x21, 0xa4, 0x0e, 0x15, 0xee, 0x46, 0x1a, 0xb8, 0x86, 0x78, 0x12, 0x48, 0x68, 0x55,
    0x54, 0xb1, 0xd0, 0x4f, 0x7b, 0xe5, 0x98, 0x67, 0xce, 0x55, 0x31, 0xce, 0x56, 0x7c, 0x90, 0xf0,
    0xb1, 0xd3, 0x02, 0x50, 0x72, 0x57, 0x2a, 0x43, 0xca, 0xc3, 0x6d, 0xd4, 0x8c, 0xc6, 0x34, 0xe1,
    0x64, 0x02, 0xca, 0xe8, 0xe9, 0x13, 0xd0, 0xa5, 0x12, 0x03, 0x5c, 0x94, 0x47, 0x77, 0x6d, 0x22,
    0x38, 0x48, 0xc1, 0xd7, 0x05, 0xae, 0xb1, 0x2d, 0x1d, 0x55, 0xf4, 0x34, 0xd9, 0xdb, 0x17, 0xd1,
    0xed, 0x42, 0xe1, 0x17, 0x2e, 0x21, 0xe3, 0x09, 0xca, 0xff, 0x43, 0x37, 0xd9, 0xef, 0x19, 0x16,
    0x06, 0x26, 0x67, 0x34, 0x71, 0x50, 0xe4, 0x3b, 0x0d, 0x73, 0x48, 0x4f, 0xa2, 0x24, 0xd9, 0xfc,
    0xec, 0x21, 0x8e, 0x44, 0xa4, 0x50, 0x50, 0x7e, 0x00, 0x85, 0xf3, 0x66, 0xba, 0xbe, 0x29, 0xcd,
    0x34, 0xfe, 0xb8, 0xe5, 0x22, 0xbe, 0x96, 0x97, 0x33, 0x29, 0xcf, 0x2e, 0xcf, 0x00, 0x66, 0x6c,
    0x64, 0xc8, 0xee, 0xbd, 0x41, 0x10, 0xc4, 0x23, 0x4e, 0xa3, 0x73, 0xd6, 0x18, 0x18, 0xf8, 0x18,
    0x2b, 0xde, 0x00, 0x03, 0x7e, 0x7f, 0x04, 0x37, 0x5f, 0x3b, 0x04, 0x23, 0x3c, 0xa1, 0x17, 0xfe,
    0xae, 0x64, 0x56, 0x48, 0xd8, 0x17, 0x62, 0x00, 0x74, 0xf6, 0xa5, 0xe7, 0x17, 0x18, 0x68, 0x6f,
    0x02, 0x61, 0x54, 0xb0, 0xcc, 0x5f, 0x24, 0x39, 0x23, 0xa9, 0x35, 0xc7, 0x6c, 0xf6, 0xda, 0x3c,
    0x34, 0x01, 0x84, 0x0b, 0x42, 0x3b, 0x80, 0x19, 0x5f, 0x8f, 0x7f, 0xba, 0xe4, 0x5c, 0xdd, 0x29,
    0xb6, 0x04, 0x5e, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t param_sfo[] = {
    0x00, 0x50, 0x53, 0x46, 0x01, 0x01, 0x00, 0x00, 0x84, 0x01, 0x00, 0x00, 0x7c, 0x02, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x04, 0x02, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x26, 0x00, 0x04, 0x02, 0x25, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x31, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x4c, 0x00, 0x00, 0x00, 0x56, 0x00, 0x04, 0x02, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x58, 0x00, 0x00, 0x00, 0x74, 0x00, 0x04, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x5c, 0x02, 0x00, 0x00, 0x8c, 0x00, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x60, 0x02, 0x00, 0x00, 0x9e, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x64, 0x02, 0x00, 0x00, 0xa5, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x98, 0x02, 0x00, 0x00, 0xaf, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0xcc, 0x02, 0x00, 0x00, 0xb9, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0xc3, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x34, 0x03, 0x00, 0x00, 0xc9, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0xb4, 0x03, 0x00, 0x00, 0xd2, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x34, 0x04, 0x00, 0x00, 0xdb, 0x00, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0xb4, 0x04, 0x00, 0x00, 0xe4, 0x00, 0x04, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x34, 0x05, 0x00, 0x00, 0xed, 0x00, 0x04, 0x02, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x40, 0x05, 0x00, 0x00, 0x41, 0x50, 0x50, 0x5f, 0x56, 0x45, 0x52, 0x00, 0x41, 0x54, 0x54, 0x52,
    0x49, 0x42, 0x55, 0x54, 0x45, 0x00, 0x41, 0x54, 0x54, 0x52, 0x49, 0x42, 0x55, 0x54, 0x45, 0x32,
    0x00, 0x43, 0x41, 0x54, 0x45, 0x47, 0x4f, 0x52, 0x59, 0x00, 0x43, 0x4f, 0x4e, 0x54, 0x45, 0x4e,
    0x54, 0x5f, 0x49, 0x44, 0x00, 0x47, 0x43, 0x5f, 0x52, 0x4f, 0x5f, 0x53, 0x49, 0x5a, 0x45, 0x00,
    0x47, 0x43, 0x5f, 0x52, 0x57, 0x5f, 0x53, 0x49, 0x5a, 0x45, 0x00, 0x50, 0x41, 0x52, 0x45, 0x4e,
    0x54, 0x41, 0x4c, 0x5f, 0x4c, 0x45, 0x56, 0x45, 0x4c, 0x00, 0x50, 0x53, 0x50, 0x32, 0x5f, 0x44,
    0x49, 0x53, 0x50, 0x5f, 0x56, 0x45, 0x52, 0x00, 0x50, 0x53, 0x50, 0x32, 0x5f, 0x53, 0x59, 0x53,
    0x54, 0x45, 0x4d, 0x5f, 0x56, 0x45, 0x52, 0x00, 0x50, 0x55, 0x42, 0x54, 0x4f, 0x4f, 0x4c, 0x49,
    0x4e, 0x46, 0x4f, 0x00, 0x52, 0x45, 0x47, 0x49, 0x4f, 0x4e, 0x5f, 0x44, 0x45, 0x4e, 0x59, 0x00,
    0x53, 0x41, 0x56, 0x45, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x4d, 0x41, 0x58, 0x5f, 0x53, 0x49, 0x5a,
    0x45, 0x00, 0x53, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x00, 0x53, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x5f,
    0x30, 0x31, 0x00, 0x53, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x5f, 0x30, 0x32, 0x00, 0x53, 0x54, 0x49,
    0x54, 0x4c, 0x45, 0x5f, 0x30, 0x33, 0x00, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x00, 0x54, 0x49, 0x54,
    0x4c, 0x45, 0x5f, 0x30, 0x31, 0x00, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x5f, 0x30, 0x32, 0x00, 0x54,
    0x49, 0x54, 0x4c, 0x45, 0x5f, 0x30, 0x33, 0x00, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x5f, 0x49, 0x44,
    0x00, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x30, 0x31, 0x2e, 0x30,
    0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x64, 0x00, 0x00,
    0x55, 0x50, 0x30, 0x37, 0x30, 0x30, 0x2d, 0x50, 0x43, 0x53, 0x45, 0x30, 0x30, 0x30, 0x30, 0x31,
    0x5f, 0x30, 0x30, 0x2d, 0x52, 0x49, 0x44, 0x47, 0x45, 0x52, 0x41, 0x43, 0x45, 0x52, 0x50, 0x53,
    0x56, 0x49, 0x54, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x30, 0x31, 0x2e, 0x30,
    0x36, 0x30, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x63, 0x5f, 0x64, 0x61, 0x74, 0x65, 0x3d, 0x32,
    0x30, 0x31, 0x32, 0x30, 0x31, 0x30, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00,
    0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41,
    0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x49, 0x44, 0x47,
    0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x52, 0x41, 0x43, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x43, 0x53, 0x45, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x30, 0x31, 0x2e, 0x30,
    0x30, 0x00, 0x00, 0x00
};

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
        lprintf("%08x  ", (unsigned int)i);
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

static bool test_open_file(char* path, SceUID* fd)
{
    *fd = sceIoOpen(path, SCE_O_RDONLY, 0777);
    if (*fd < 0) {
        perr("Could not open '%s': 0x%08X\n", path, *fd);
        return false;
    }
    return true;
}

static bool test_close_file(SceUID fd)
{
    int r = sceIoClose(fd);
    if (r < 0) {
        perr("Could not close file: 0x%08X\n", r);
        return false;
    }
    return true;
}

static bool test_xclose_file(SceUID fd, int expected)
{
    int r = sceIoClose(fd);
    if (r != expected) {
        perr("Closing of file returned 0x%08X instead of 0x%08X\n", r, expected);
        return false;
    }
    return true;
}

static bool test_zero_file(SceUID fd, int size)
{
    uint8_t* data = malloc(size);
    if (data == NULL) {
        perr("Could not open alloc data for test:\n");
        return false;
    }
    int read = sceIoRead(fd, data, size);
    if (read != size) {
        perr("Could not read data from file: 0x%08X\n", read);
        return false;
    }
    sceIoClose(fd);
    for (int i = 0; i < size; i++) {
        if (data[i] != 0) {
            perr("Data from differs at offset 0x%08X:\n", i);
            dump_hex(&data[i], 16);
            return false;
        }
    }
    return true;
}

static bool test_read_file(SceUID fd, uint8_t* expected_data, int size)
{
    uint8_t* data = malloc(size);
    if (data == NULL) {
        perr("Could not open alloc data for test:\n");
        return false;
    }
    int read = sceIoRead(fd, data, size);
    if (read != size) {
        perr("Could not read data from file: 0x%08X\n", read);
        return false;
    }
    for (int i = 0; i < size; i++) {
        if (data[i] != expected_data[i]) {
            perr("Data from file differs at offset 0x%08X:\n", i);
            dump_hex(&data[i], 16);
            dump_hex(&expected_data[i], 16);
            return false;
        }
    }
    return true;
}

static bool test_lseek_file(SceUID fd, SceOff offset, int whence, SceOff expected)
{
    SceOff r = sceIoLseek(fd, offset, whence);
    if (r != expected) {
        perr("Incorrect file position: got 0x%llX instead of 0x%%lX\n", r, expected);
        return false;
    }
    return true;
}

static bool test_lseek32_file(SceUID fd, int offset, int whence, int expected)
{
    int r = sceIoLseek32(fd, offset, whence);
    if (r != expected) {
        perr("Incorrect file position: got 0x%08X instead of 0x%08X\n", r, expected);
        return false;
    }
    return true;
}

static void wait_for_key(const char* message)
{
    SceCtrlData pad;

    console_set_color(CYAN);
    printf("\n%s\n", message);
    console_set_color(WHITE);
    do {
        sceCtrlPeekBufferPositive(0, &pad, 1);
    } while (!(pad.buttons & SCE_CTRL_CROSS));
    console_reset();
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
    const bool group[2] = { true, true };

    init_video();
    console_init();

    printf("vpfs_test v" VERSION " - Vita PKG Filesystem tester\n");
    printf("Copyright (c) 2018 VitaSmith (GPLv3)\n\n");

    DISPLAY_TEST_OR_OUT("VPFS file is present", test_vpfs_file, "ux0:app/PCSE00001.vpfs");
    DISPLAY_TEST_OR_OUT("VPFS module can be loaded", module_load);

    if (group[0]) {
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
        wait_for_key("Press X to continue...");
    }
    if (group[1]) {
        SceUID fd = -1;
        DISPLAY_TEST("Open 'eboot.bin'", test_open_file, "ux0:app/PCSE00001/eboot.bin", &fd);
        DISPLAY_TEST("Close 'eboot.bin'", test_close_file, fd);
        DISPLAY_TEST("Open 'sce_sys/package/work.bin'", test_open_file, "ux0:app/PCSE00001/sce_sys/package/work.bin", &fd);
        // Embedded unencrypted file
        DISPLAY_TEST("Read 'sce_sys/package/work.bin'", test_read_file, fd, work_bin, sizeof(work_bin));
        // Embedded zeroed file
        test_close_file(fd);
        test_open_file("ux0:app/PCSE00001/sce_sys/package/stat.bin", &fd);
        DISPLAY_TEST("Read 'sce_sys/package/stat.bin'", test_zero_file, fd, 768);
        // Calling sceIoClose() twice on the same file returns EBADFD
        DISPLAY_TEST("Double close of 'sce_sys/package/stat.bin'", test_xclose_file, fd, 0x80010051);
        // External unencrypted file
        test_open_file("ux0:app/PCSE00001/sce_sys/package/tail.bin", &fd);
        DISPLAY_TEST("Read 'sce_sys/package/tail.bin'", test_read_file, fd, tail_bin, sizeof(tail_bin));
        test_close_file(fd);
        // External encrypted file
        test_open_file("ux0:app/PCSE00001/sce_sys/param.sfo", &fd);
        DISPLAY_TEST("Read 'sce_sys/param.sfo'", test_read_file, fd, param_sfo, sizeof(param_sfo));
        const int offset_32bit = 0x8F;
        DISPLAY_TEST("Lseek32 'sce_sys/param.sfo'", test_lseek32_file, fd, -offset_32bit, SEEK_END, sizeof(param_sfo) - offset_32bit);
        // TODO: This currently fails if we have CTR rollback
        DISPLAY_TEST("Read after Lseek32", test_read_file, fd, &param_sfo[sizeof(param_sfo) - offset_32bit], offset_32bit);
        test_close_file(fd);
        const SceOff offset_64bit = 0x1CB;
        test_open_file("ux0:app/PCSE00001/sce_sys/param.sfo", &fd);
        DISPLAY_TEST("Lseek 'sce_sys/param.sfo'", test_lseek_file, fd, offset_64bit, SEEK_SET, offset_64bit);
        DISPLAY_TEST("Read after Lseek", test_read_file, fd, &param_sfo[offset_64bit], sizeof(param_sfo) - offset_64bit);
        test_close_file(fd);
    }
    DISPLAY_TEST("VPFS module can be unloaded", module_unload);

out:
    wait_for_key("Press X to exit");
    console_exit();
    end_video();
    sceKernelExitProcess(0);
    return 0;
}
