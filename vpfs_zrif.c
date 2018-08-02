/*
  zRIF handling functions
  Copyright © 2017 - Martins Mozeiko, VitaSmith et al.

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "puff.h"

#define BASE_RIF_SIZE 512

#define ADLER32_MOD 65521

#define ZLIB_DEFLATE_METHOD 8
#define ZLIB_DICTIONARY_ID_ZRIF 0x627d1d5d

static inline uint32_t getbe32(const uint8_t* bytes)
{
    return (bytes[3]) | (bytes[2] << 8) | (bytes[1] << 16) | (bytes[0] << 24);
}

static const uint8_t zrif_dict[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 48, 48, 48, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 48,
    48, 48, 54, 48, 48, 48, 48, 55, 48, 48, 48, 48, 56, 0, 48, 48, 48, 48, 51, 48, 48, 48, 48, 52, 48, 48, 48, 48,
    53, 48, 95, 48, 48, 45, 65, 68, 68, 67, 79, 78, 84, 48, 48, 48, 48, 50, 45, 80, 67, 83, 71, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 49, 45, 80, 67, 83, 69, 48, 48, 48, 45, 80, 67, 83, 70, 48, 48, 48, 45, 80, 67, 83,
    67, 48, 48, 48, 45, 80, 67, 83, 68, 48, 48, 48, 45, 80, 67, 83, 65, 48, 48, 48, 45, 80, 67, 83, 66, 48, 48,
    48, 0, 1, 0, 1, 0, 1, 0, 2, 239, 205, 171, 137, 103, 69, 35, 1,
};

static const uint8_t b64d[] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
};

static uint32_t adler32(const uint8_t* data, size_t size)
{
    uint32_t a = 1;
    uint32_t b = 0;

    for (size_t i = 0; i < size; i++) {
        a = (a + data[i]) % ADLER32_MOD;
        b = (b + a) % ADLER32_MOD;
    }

    return (b << 16) | a;
}

static size_t base64_decode(const char* in, uint8_t* out)
{
    const uint8_t* out0 = out;
    const uint8_t* in8 = (uint8_t*)in;

    size_t len = strlen(in);
    if (in[len - 1] == '=')
        len--;
    if (in[len - 1] == '=')
        len--;

    for (size_t i = 0; i < len / 4; i++) {
        *out++ = (b64d[in8[0]] << 2) + ((b64d[in8[1]] & 0x30) >> 4);
        *out++ = (b64d[in8[1]] << 4) + (b64d[in8[2]] >> 2);
        *out++ = (b64d[in8[2]] << 6) + b64d[in8[3]];
        in8 += 4;
    }

    size_t left = len % 4;
    if (left == 2) {
        *out++ = (b64d[in8[0]] << 2) + ((b64d[in8[1]] & 0x30) >> 4);
        *out++ = (b64d[in8[1]] << 4);
    } else if (left == 3) {
        *out++ = (b64d[in8[0]] << 2) + ((b64d[in8[1]] & 0x30) >> 4);
        *out++ = (b64d[in8[1]] << 4) + (b64d[in8[2]] >> 2);
        *out++ = b64d[in8[2]] << 6;
    }

    return (size_t)(out - out0);
}

static size_t zlib_inflate(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen)
{
    if (inlen < 2 + 4)
        return 0;

    if (((in[0] << 8) + in[1]) % 31 != 0)
        return 0;

    if ((in[0] & 0xf) != ZLIB_DEFLATE_METHOD)
        return 0;

    size_t slen = inlen - 4;
    size_t dlen = outlen;
    size_t dictlen = 0;

    if (in[1] & (1 << 5)) {
        assert(outlen > sizeof(zrif_dict));
        memcpy(out, zrif_dict, sizeof(zrif_dict));
        dictlen = sizeof(zrif_dict);
        if (getbe32(in + 2) != ZLIB_DICTIONARY_ID_ZRIF)
            return 0;
        in += 6;
        slen -= 6;
    } else {
        in += 2;
        slen -= 2;
    }

    int r = puff(dictlen, out, &dlen, in, &slen);
    if (r < 0)
        return 0;
    memmove(out, out + dictlen, dlen);

    if (adler32(out, dlen) != getbe32(in + slen))
        return 0;

    return dlen;
}

size_t zrif_decode(const char* zrif, uint8_t* dst, const size_t dst_len)
{
    /* PSM RIFs are twice the base RIF size */
    uint8_t raw[2 * BASE_RIF_SIZE];
    uint8_t out[2 * BASE_RIF_SIZE + sizeof(zrif_dict)];
    size_t rif_len = 0;

    if (dst_len < 2 * BASE_RIF_SIZE)
        return 0;

    rif_len = base64_decode(zrif, raw);
    rif_len = zlib_inflate(raw, rif_len, out, sizeof(out));
    if ((rif_len != BASE_RIF_SIZE) && (rif_len != 2 * BASE_RIF_SIZE))
        return 0;

    memcpy(dst, out, rif_len);
    return rif_len;
}
