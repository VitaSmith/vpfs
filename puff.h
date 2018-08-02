/*
  puff.h
  Copyright © 2002-2013 Mark Adler, all rights reserved
  version 2.3, 21 Jan 2013

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler    madler@alumni.caltech.edu
*/

/*
 * This header was modified to support custom dictionary
 * See puff.c for purpose and usage.
 */

#include <stdint.h>
#include <stdlib.h>

#ifndef NIL
#  define NIL ((unsigned char *)0)      /* for no output option */
#endif

int puff(size_t dictlen,          /* length of custom dictionary */
         uint8_t *dest,           /* pointer to destination pointer */
         size_t *destlen,         /* amount of output space */
         const uint8_t *source,   /* pointer to source data pointer */
         size_t *sourcelen);      /* amount of input available */
