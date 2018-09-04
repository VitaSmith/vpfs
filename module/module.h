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

#pragma once

#include <stdint.h>

typedef struct {
    uint8_t *src;
    uint8_t *dst;
    uint32_t size;
    uint8_t *key;
    uint32_t key_size;
    uint8_t *iv;
    uint32_t mask_enable;
} usceSblSsMgrAESCTRDecrypt_args;

int usceSblSsMgrAESCTRDecrypt(usceSblSsMgrAESCTRDecrypt_args* args);

//---

int ksceSblSsMgrAESCTRDecrypt(uint8_t *src, uint8_t *dst, const uint32_t size, const uint8_t *key, const uint32_t key_size, uint8_t *iv, uint32_t mask_enable);
void PackageCheck(void);
