/*
  VPFS - Vita PKG File System
  Copyright © 2018 VitaSmith
  Copyright © 1998-2001 Free Software Foundation, Inc.

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

#include "vpfs_utils.h"

#undef BIG_ENDIAN_HOST

#define ROL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROR(a,b) (((a) >> (b)) | ((a) << (32-(b))))

typedef struct PKG_ALIGN(64)
{
    uint8_t  buf[64];
    uint32_t state[5];
    uint64_t bytecount;
} sha1_context;

static void sha1_init(sha1_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
}

static void sha1_transform(sha1_context *ctx, const uint8_t *data)
{
    uint32_t a, b, c, d, e, tm, x[16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

#ifdef BIG_ENDIAN_HOST
    memcpy(x, data, sizeof(x));
#else
    {
        unsigned k;
        for (k = 0; k < 16; k += 4) {
            const uint8_t *p2 = data + k * 4;
            x[k] = get32be(p2);
            x[k + 1] = get32be(p2 + 4);
            x[k + 2] = get32be(p2 + 8);
            x[k + 3] = get32be(p2 + 12);
        }
    }
#endif

#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )

#define M(i) ( tm = x[i&0x0f] ^ x[(i-14)&0x0f] ^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f], (x[i&0x0f] = ROL(tm,1)) )

#define SHA1STEP(a,b,c,d,e,f,k,m) do { e += ROL(a, 5) + f(b, c, d) + k + m; \
                                       b = ROL(b, 30); } while(0)
    SHA1STEP(a, b, c, d, e, F1, K1, x[0]);
    SHA1STEP(e, a, b, c, d, F1, K1, x[1]);
    SHA1STEP(d, e, a, b, c, F1, K1, x[2]);
    SHA1STEP(c, d, e, a, b, F1, K1, x[3]);
    SHA1STEP(b, c, d, e, a, F1, K1, x[4]);
    SHA1STEP(a, b, c, d, e, F1, K1, x[5]);
    SHA1STEP(e, a, b, c, d, F1, K1, x[6]);
    SHA1STEP(d, e, a, b, c, F1, K1, x[7]);
    SHA1STEP(c, d, e, a, b, F1, K1, x[8]);
    SHA1STEP(b, c, d, e, a, F1, K1, x[9]);
    SHA1STEP(a, b, c, d, e, F1, K1, x[10]);
    SHA1STEP(e, a, b, c, d, F1, K1, x[11]);
    SHA1STEP(d, e, a, b, c, F1, K1, x[12]);
    SHA1STEP(c, d, e, a, b, F1, K1, x[13]);
    SHA1STEP(b, c, d, e, a, F1, K1, x[14]);
    SHA1STEP(a, b, c, d, e, F1, K1, x[15]);
    SHA1STEP(e, a, b, c, d, F1, K1, M(16));
    SHA1STEP(d, e, a, b, c, F1, K1, M(17));
    SHA1STEP(c, d, e, a, b, F1, K1, M(18));
    SHA1STEP(b, c, d, e, a, F1, K1, M(19));
    SHA1STEP(a, b, c, d, e, F2, K2, M(20));
    SHA1STEP(e, a, b, c, d, F2, K2, M(21));
    SHA1STEP(d, e, a, b, c, F2, K2, M(22));
    SHA1STEP(c, d, e, a, b, F2, K2, M(23));
    SHA1STEP(b, c, d, e, a, F2, K2, M(24));
    SHA1STEP(a, b, c, d, e, F2, K2, M(25));
    SHA1STEP(e, a, b, c, d, F2, K2, M(26));
    SHA1STEP(d, e, a, b, c, F2, K2, M(27));
    SHA1STEP(c, d, e, a, b, F2, K2, M(28));
    SHA1STEP(b, c, d, e, a, F2, K2, M(29));
    SHA1STEP(a, b, c, d, e, F2, K2, M(30));
    SHA1STEP(e, a, b, c, d, F2, K2, M(31));
    SHA1STEP(d, e, a, b, c, F2, K2, M(32));
    SHA1STEP(c, d, e, a, b, F2, K2, M(33));
    SHA1STEP(b, c, d, e, a, F2, K2, M(34));
    SHA1STEP(a, b, c, d, e, F2, K2, M(35));
    SHA1STEP(e, a, b, c, d, F2, K2, M(36));
    SHA1STEP(d, e, a, b, c, F2, K2, M(37));
    SHA1STEP(c, d, e, a, b, F2, K2, M(38));
    SHA1STEP(b, c, d, e, a, F2, K2, M(39));
    SHA1STEP(a, b, c, d, e, F3, K3, M(40));
    SHA1STEP(e, a, b, c, d, F3, K3, M(41));
    SHA1STEP(d, e, a, b, c, F3, K3, M(42));
    SHA1STEP(c, d, e, a, b, F3, K3, M(43));
    SHA1STEP(b, c, d, e, a, F3, K3, M(44));
    SHA1STEP(a, b, c, d, e, F3, K3, M(45));
    SHA1STEP(e, a, b, c, d, F3, K3, M(46));
    SHA1STEP(d, e, a, b, c, F3, K3, M(47));
    SHA1STEP(c, d, e, a, b, F3, K3, M(48));
    SHA1STEP(b, c, d, e, a, F3, K3, M(49));
    SHA1STEP(a, b, c, d, e, F3, K3, M(50));
    SHA1STEP(e, a, b, c, d, F3, K3, M(51));
    SHA1STEP(d, e, a, b, c, F3, K3, M(52));
    SHA1STEP(c, d, e, a, b, F3, K3, M(53));
    SHA1STEP(b, c, d, e, a, F3, K3, M(54));
    SHA1STEP(a, b, c, d, e, F3, K3, M(55));
    SHA1STEP(e, a, b, c, d, F3, K3, M(56));
    SHA1STEP(d, e, a, b, c, F3, K3, M(57));
    SHA1STEP(c, d, e, a, b, F3, K3, M(58));
    SHA1STEP(b, c, d, e, a, F3, K3, M(59));
    SHA1STEP(a, b, c, d, e, F4, K4, M(60));
    SHA1STEP(e, a, b, c, d, F4, K4, M(61));
    SHA1STEP(d, e, a, b, c, F4, K4, M(62));
    SHA1STEP(c, d, e, a, b, F4, K4, M(63));
    SHA1STEP(b, c, d, e, a, F4, K4, M(64));
    SHA1STEP(a, b, c, d, e, F4, K4, M(65));
    SHA1STEP(e, a, b, c, d, F4, K4, M(66));
    SHA1STEP(d, e, a, b, c, F4, K4, M(67));
    SHA1STEP(c, d, e, a, b, F4, K4, M(68));
    SHA1STEP(b, c, d, e, a, F4, K4, M(69));
    SHA1STEP(a, b, c, d, e, F4, K4, M(70));
    SHA1STEP(e, a, b, c, d, F4, K4, M(71));
    SHA1STEP(d, e, a, b, c, F4, K4, M(72));
    SHA1STEP(c, d, e, a, b, F4, K4, M(73));
    SHA1STEP(b, c, d, e, a, F4, K4, M(74));
    SHA1STEP(a, b, c, d, e, F4, K4, M(75));
    SHA1STEP(e, a, b, c, d, F4, K4, M(76));
    SHA1STEP(d, e, a, b, c, F4, K4, M(77));
    SHA1STEP(c, d, e, a, b, F4, K4, M(78));
    SHA1STEP(b, c, d, e, a, F4, K4, M(79));

#undef F1
#undef F2
#undef F3
#undef F4

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_write(sha1_context *ctx, const uint8_t *buf, size_t len)
{
    size_t num = ctx->bytecount & 0x3f;

    ctx->bytecount += len;

    if (num)
    {
        uint8_t *p = ctx->buf + num;

        num = 64 - num;
        if (len < num)
        {
            memcpy(p, buf, len);
            return;
        }
        memcpy(p, buf, num);
        sha1_transform(ctx, ctx->buf);
        buf += num;
        len -= num;
    }

    while (len >= 64)
    {
        sha1_transform(ctx, buf);
        buf += 64;
        len -= 64;
    }

    memcpy(ctx->buf, buf, len);
}

static void sha1_final(sha1_context *ctx)
{
    uint64_t bitcount = ctx->bytecount << 3;
    size_t pos = ((size_t)ctx->bytecount) & 0x3F;
    uint8_t *p;

    ctx->buf[pos++] = 0x80;

    while (pos != (64 - 8))
    {
        pos &= 0x3F;
        if (pos == 0)
            sha1_transform(ctx, ctx->buf);
        ctx->buf[pos++] = 0;
    }

    ctx->buf[63] = (uint8_t)bitcount;
    ctx->buf[62] = (uint8_t)(bitcount >> 8);
    ctx->buf[61] = (uint8_t)(bitcount >> 16);
    ctx->buf[60] = (uint8_t)(bitcount >> 24);
    ctx->buf[59] = (uint8_t)(bitcount >> 32);
    ctx->buf[58] = (uint8_t)(bitcount >> 40);
    ctx->buf[57] = (uint8_t)(bitcount >> 48);
    ctx->buf[56] = (uint8_t)(bitcount >> 56);

    sha1_transform(ctx, ctx->buf);

    p = ctx->buf;
#ifdef BIG_ENDIAN_HOST
#define X(a) do { *(uint32_t*)p = ctx->state[a]; p += 4; } while(0)
#else
#define X(a) do { set32be(p, ctx->state[a]); p += 4; } while(0);
#endif
    X(0);
    X(1);
    X(2);
    X(3);
    X(4);
#undef X
}

bool sha1sum(const uint8_t* buf, const size_t len, uint8_t* sum)
{
    bool r = false;
    sha1_context ctx = { 0 };

    if (sum == NULL)
        goto out;

    sha1_init(&ctx);
    sha1_write(&ctx, buf, len);
    sha1_final(&ctx);

    memcpy(sum, ctx.buf, 20);
    r = true;

out:
    return r;
}
