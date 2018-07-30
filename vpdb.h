/*
  VPFS - Vita PKG File System
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

/*
  vpfs is a READ-ONLY file system aimed at accessing packages (mostly Sony PKGs
  but can be extended to .zip or .tar archives) as if they had been fully
  extracted/decrypted on the storage media.

  This is accomplished by overriding the sceIo#### calls to transparently
  access the package data as needed.

  Note that, because the file system is read-only, creating files or directories
  or renaming stuff will always return an error.
  It is however possible to mark an entry (dir, file) as deleted.
*/

/*
  VPFS structure:
    vpfs_header;
    vdfs_pkg[nb_pkgs];
    uint64_t sha1[nb_items][5]
    vpfs_item[nb_items];
    char dir_list[]; // concatenation of NUL terminated UTF-8 strings, grouped by directory
    uint8_t additional_local_data[] (work.bin, modded files, etc)

  pkg_table_offset = sizeof(vpfs_header);
  sha_table_offset = pkg_table_offset + nb_pkgs * sizeof(vpfs_pkg);
  item_table_offset = path_table_offset + nb_items * 40;
  item_names_offset = item_table_offset + nb_items * sizeof(vpfs_item);

  Lookups:
  - root path ("ux0:/app/TITLE_ID/") must match the vpfs path ("ux0:/app/TITLE_ID.vpfs")
    => split on slashes and see if we have a .vpfs for that. Could even have a whole
       "ux0:/app.vpfs"...
  - (short) path -> SHA-1 (short means "ux0:app/TITLE_ID/" is removed)
  - SHA-1 index = pkg_item index
  Ultimately, we'll want to sort the SHA-1 and do a *PROPER* lookup, by starting at the most
  appropriate position in our table and dichotomizing the shit out of our search. Probably also
  want to speed things up through using uint64_t for lookup (through memcmp is probably
  optimised enough). If SHA-1 not found in our tables, hand over to the original call.

  For dir entries:
  - Add trailing '/' to path if missing
  - SHA-1 of directory path -> pkg_entry (should also have type dir)
  - offset = start of directory entries in names table (concatenation of NUL terminated strings)
  - offset + size = end of directory entries in path tables
  - to find out if entry is file or dir check for terminating /

  TODO!!!: We're screwed if we try to mix real content with our content when listing dir entries...
           Or, are we? Can still try to call org call after we're done, which should list both our
           stuff and real-one. WILL NEED TO TEST THIS WITH work.bin or mod data. Or we can add
           placeholder for work.bin and fill it with data at the end of vpfs record

  TODO: Calls MUST be reentrant as we may have multiple threads accessing the same app (and
        potentially the same item!) => anything we'd like static must go into the private fd data.

  For stat:
  - All items always have the same date as the PKG
 */

// Why SHA-1 rather than MD5?
// Because there's a harwdare accelerated kernel call for it in SceSblSsMgr (sceSblSsMgrSHA1ForDriver)
// and we are going to be carrying the lookups in kernel mode

typedef struct {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    nb_pkgs;
    uint32_t    nb_items;
} vpfs_header;

// TODO: for sceIoStat, return the date of the pkg
typedef struct {
    uint32_t    type;
    uint32_t    flags;
    char        content_id[36]; // not NUL terminated!
    char        path[256];
    uint8_t     aes_key[0x10];
    uint8_t     aes_iv[0x10];
} vpfs_pkg;

typedef struct {
    uint32_t    flags;
    int32_t     pkg_index;  // < 0 if the offset is in this file, > 0  if in designated external PKG
    uint64_t    offset;     // For directories, offset is to string list in VPDB
                            // For regular files, offset is the offset in the referenced PKG
    uint64_t    size;       // For directories, this is the size of all the NUL terminated
                            // strings that are contained in the directory
                            // For regular files, this is the size of the source item in the PKG
} vpfs_item;


#define VPFS_MAGIC              0x56504653  // 'VPFS'
#define VPFS_VERSION            0x00010000  // 'v1.0'

// Flags
#define VPFS_PKG_LONG_PATHS     0x00000001

// Bits 0-2 of item describe the type of entry at offset
#define VPFS_ITEM_TYPE_BIN      0x00000000  // As is (no encryption, no compression)
#define VPFS_ITEM_TYPE_AES      0x00000001  // AES 128 CTR, such as the one from Sony PKG archives
#define VPFS_ITEM_TYPE_ZIP      0x00000002  // PKZip entry
#define VPFS_ITEM_TYPE_TAR      0x00000003  // TAR entry

#define VPFS_ITEM_TYPE_DIR      0x10000000  // Directory flag
#define VPFS_ITEM_DELETED       0x80000000  // Deleted flag
#define VPFS_ITEM_OVERRIDDEN    0x40000000  // If overriden from patch or DLC. Probably not needed.

// Internal structures for directory listing
typedef struct dir_entry {
    const char* path;
    struct dir_entry* children;
    size_t index;                 // Current array size
    size_t max;                   // Maximum array size
} dir_entry;

#define DIRENTRY_INITIAL_CHILDREN_SIZE  4
