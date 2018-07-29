/*
  VPDB - Vita PKG database creator
  Copyright © 2018 VitaSmith
  Copyright © 2017-2018 Martins Mozeiko

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

#include "vpdb_utils.h"

typedef struct aes128_key {
    uint32_t PKG_ALIGN(16) key[44];
} aes128_key;

void aes128_init(aes128_key* ctx, const uint8_t* key);
void aes128_init_dec(aes128_key* ctx, const uint8_t* key);

void aes128_ecb_encrypt(const aes128_key* ctx, const uint8_t* input, uint8_t* output);
void aes128_ecb_decrypt(const aes128_key* ctx, const uint8_t* input, uint8_t* output);

void aes128_ctr_xor(const aes128_key* ctx, const uint8_t* iv, uint64_t block, uint8_t* buffer, size_t size);

void aes128_cmac(const uint8_t* key, const uint8_t* buffer, uint32_t size, uint8_t* mac);

void aes128_psp_decrypt(const aes128_key* ctx, const uint8_t* iv, uint32_t index, uint8_t* buffer, uint32_t size);
