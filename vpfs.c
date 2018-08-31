/*
  VPFS - Vita PKG File System
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

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include "vpfs_utils.h"
#include "vpfs_sys.h"
#include "vpfs_crypt.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "vpfs.h"

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#endif

// Internal structures for directory listing
typedef struct dir_entry_t {
    const char*         path;
    bool                is_dir;
    struct dir_entry_t* children;
    size_t              index;  // Current array size
    size_t              max;    // Maximum array size
} dir_entry_t;

typedef struct {
    char*               path;
    uint32_t            offset;
    uint32_t            size;
} dir_record_t;

typedef struct {
    uint32_t            nb_dirs;
    uint32_t            dir_index;
    uint32_t            buf_len;
    uint32_t            buf_offset;
    dir_record_t*       dir;
    char*               buf;
} dir_dump_t;

#define DIRENTRY_INITIAL_CHILDREN_SIZE  4
#define NUM_EXTRA_ITEMS                 5

typedef struct {
    uint32_t            index;
    vpfs_header_t       header;
    vpfs_pkg_t*         pkg;
    uint64_t*           sha;
    uint32_t*           sorted_sha;
    char**              name;
    vpfs_item_t*        item;
    dir_entry_t*        root;
    uint8_t*            data;       // buffer for extra data
    uint32_t            data_len;
    uint32_t            data_max;
} vpfs_t;

#define PKG_HEADER_SIZE         192
#define PKG_HEADER_EXT_SIZE     64

// https://wiki.henkaku.xyz/vita/Packages#AES_Keys
static const uint8_t pkg_aes_key[3][16] = {
    { 0xe3, 0x1a, 0x70, 0xc9, 0xce, 0x1d, 0xd7, 0x2b, 0xf3, 0xc0, 0x62, 0x29, 0x63, 0xf2, 0xec, 0xcb },
    { 0x42, 0x3a, 0xca, 0x3a, 0x2b, 0xd5, 0x64, 0x9f, 0x96, 0x86, 0xab, 0xad, 0x6f, 0xd8, 0x80, 0x1f },
    { 0xaf, 0x07, 0xfd, 0x59, 0x65, 0x25, 0x27, 0xba, 0xf1, 0x33, 0x89, 0x66, 0x8b, 0x17, 0xd9, 0xea }
};

// http://vitadevwiki.com/vita/System_File_Object_(SFO)_(PSF)#Internal_Structure
// https://github.com/TheOfficialFloW/VitaShell/blob/1.74/sfo.h#L29
static void parse_sfo_content(const uint8_t* sfo, uint32_t sfo_size, char* category, char* title, char* content, char* min_version, char* pkg_version)
{
    if (get32le(sfo) != 0x46535000)
    {
        sys_error("ERROR: incorrect sfo signature\n");
    }

    uint32_t keys = get32le(sfo + 8);
    uint32_t values = get32le(sfo + 12);
    uint32_t count = get32le(sfo + 16);

    int title_index = -1;
    int content_index = -1;
    int category_index = -1;
    int minver_index = -1;
    int pkgver_index = -1;
    for (uint32_t i = 0; i < count; i++)
    {
        if (i * 16 + 20 + 2 > sfo_size)
        {
            sys_error("ERROR: sfo information is too small\n");
        }

        char* key = (char*)sfo + keys + get16le(sfo + i * 16 + 20);
        if (strcmp(key, "TITLE") == 0)
        {
            if (title_index < 0)
            {
                title_index = (int)i;
            }
        }
        else if (strcmp(key, "STITLE") == 0)
        {
            title_index = (int)i;
        }
        else if (strcmp(key, "CONTENT_ID") == 0)
        {
            content_index = (int)i;
        }
        else if (strcmp(key, "CATEGORY") == 0)
        {
            category_index = (int)i;
        }
        else if (strcmp(key, "PSP2_DISP_VER") == 0)
        {
            minver_index = (int)i;
        }
        else if (strcmp(key, "APP_VER") == 0)
        {
            pkgver_index = (int)i;
        }
    }

    if (title_index < 0)
    {
        sys_error("ERROR: cannot find title from sfo file, pkg is probably corrupted\n");
    }

    char* value = (char*)sfo + values + get32le(sfo + title_index * 16 + 20 + 12);
    size_t i;
    size_t max = 255;
    for (i = 0; i<max && *value; i++, value++)
    {
        if ((*value >= 32 && *value < 127 && strchr("<>\"/\\|?*", *value) == NULL) || (uint8_t)*value >= 128)
        {
            if (*value == ':')
            {
                *title++ = ' ';
                *title++ = '-';
                max--;
            }
            else
            {
                *title++ = *value;
            }
        }
        else if (*value == 10)
        {
            *title++ = ' ';
        }
    }
    *title = 0;

    if (content_index >= 0 && content)
    {
        value = (char*)sfo + values + get32le(sfo + content_index * 16 + 20 + 12);
        while (*value)
        {
            *content++ = *value++;
        }
        *content = 0;
    }

    if (category_index >= 0)
    {
        value = (char*)sfo + values + get32le(sfo + category_index * 16 + 20 + 12);
        while (*value)
        {
            *category++ = *value++;
        }
    }
    *category = 0;

    if (minver_index >= 0 && min_version)
    {
        value = (char*)sfo + values + get32le(sfo + minver_index * 16 + 20 + 12);
        if (*value == '0')
        {
            value++;
        }
        while (*value)
        {
            *min_version++ = *value++;
        }
        if (min_version[-1] == '0')
        {
            min_version[-1] = 0;
        }
        else
        {
            *min_version = 0;
        }
    }

    if (pkgver_index >= 0 && pkg_version)
    {
        value = (char*)sfo + values + get32le(sfo + pkgver_index * 16 + 20 + 12);
        if (*value == '0')
        {
            value++;
        }
        while (*value)
        {
            *pkg_version++ = *value++;
        }
        *pkg_version = 0;
    }
}

static void parse_sfo(sys_file f, uint64_t sfo_offset, uint32_t sfo_size, char* category, char* title, char* content, char* min_version, char* pkg_version)
{
    uint8_t sfo[16 * 1024];
    if (sfo_size < 16)
    {
        sys_error("ERROR: sfo information is too small\n");
    }
    if (sfo_size > sizeof(sfo))
    {
        sys_error("ERROR: sfo information is too big, pkg file is probably corrupted\n");
    }
    sys_read(f, sfo_offset, sfo, sfo_size);

    parse_sfo_content(sfo, sfo_size, category, title, content, min_version, pkg_version);
}

typedef enum {
    PKG_TYPE_VITA_APP = 0,
    PKG_TYPE_VITA_DLC,
    PKG_TYPE_VITA_PATCH,
    PKG_TYPE_VITA_PSM,
} pkg_type;

const char* pkg_type_name[] = {
    "Vita APP",
    "Vita DLC",
    "Vita PATCH",
    "Vita PSM",
};

static bool separate_console()
{
#if defined(_WIN32) || defined(__CYGWIN__)
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
    {
        return false;
    }

    return ((!csbi.dwCursorPosition.X) && (!csbi.dwCursorPosition.Y));
#elif defined(__vita__)
    return true;
#else
    return false;
#endif
}

static dir_entry_t* direntry_create_root(void)
{
    dir_entry_t* entry = calloc(1, sizeof(dir_entry_t));

    assert(entry != NULL);

    entry->path = "";
    entry->is_dir = true;

    return entry;
}

static bool direntry_add(dir_entry_t* entry, const char* path, bool is_dir)
{
    if (entry == NULL)
    {
        return false;
    }

    if (entry->index == entry->max)
    {
        if (entry->max == 0)
        {
            entry->max = DIRENTRY_INITIAL_CHILDREN_SIZE;
            entry->children = calloc(entry->max, sizeof(dir_entry_t));
            if (entry->children == NULL)
            {
                return false;
            }
        }
        else
        {
            entry->max *= 2;
            entry->children = (dir_entry_t*)realloc(entry->children, entry->max * sizeof(dir_entry_t));
            if (entry->children == NULL)
            {
                sys_error("Could not reallocate dir_entry array for %d entries\n", entry->max);
            }
            memset(&entry->children[entry->max / 2], 0, entry->max / 2 * sizeof(dir_entry_t));
         }
    }

    entry->children[entry->index].is_dir = is_dir;
    entry->children[entry->index++].path = path;

    return true;
}

static void direntry_destroy(dir_entry_t* entry)
{
    if ((entry == NULL) && (entry->children == NULL))
    {
        return;
    }

    for (size_t i = 0; i < entry->index; i++)
    {
        direntry_destroy(&entry->children[i]);
    }

    free(entry->children);
}

static dir_entry_t* direntry_find(dir_entry_t* entry, const char* path, size_t len)
{
    for (size_t i = 0; i < entry->index; i++)
    {
        if (strncmp(entry->children[i].path, path, len) == 0)
        {
            return &entry->children[i];
        }
    }

    return NULL;
}

static void direntry_print(dir_entry_t* entry)
{
    if (entry->is_dir)
    {
        sys_printf("DIRECTORY %s\n", entry->path);
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        sys_printf("- %s\n", entry->children[i].path);
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        direntry_print(&entry->children[i]);
    }
}

static void direntry_dump_init(dir_dump_t* dump, dir_entry_t* entry)
{
    for (size_t i = 0; i < entry->index; i++)
    {
        if (entry->children[i].path[0] == 0)
            continue;
        dump->buf_len += (uint32_t)strlen(entry->children[i].path) + 1;
    }
    if (entry->is_dir)
    {
        dump->nb_dirs++;
        dump->buf_len++;    // Space for double NUL terminator
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        direntry_dump_init(dump, &entry->children[i]);
    }
}

static void direntry_dump(dir_dump_t* dump, dir_entry_t* entry)
{
    if (entry->is_dir)
    {
        dump->dir[dump->dir_index].offset = dump->buf_offset;
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        if (entry->children[i].path[0] == 0)
            continue;
        strcpy(&dump->buf[dump->buf_offset], entry->children[i].path);
        dump->buf_offset += (uint32_t)strlen(entry->children[i].path) + 1;
    }
    if (entry->is_dir)
    {
        dump->dir[dump->dir_index].path = (char*)entry->path;
        dump->buf_offset++; // Double NUL terminator
        dump->dir[dump->dir_index].size = dump->buf_offset - dump->dir[dump->dir_index].offset;
        dump->dir_index++;
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        direntry_dump(dump, &entry->children[i]);
    }
}

static bool vpfs_init(vpfs_t *vpfs, uint32_t nb_pkgs, uint32_t nb_items)
{
    memset(vpfs, 0, sizeof(vpfs_t));
    vpfs->header.magic = VPFS_MAGIC;
    vpfs->header.version = VPFS_VERSION;
    vpfs->header.nb_pkgs = nb_pkgs;
    vpfs->header.nb_items = nb_items;
    vpfs->pkg = calloc(nb_pkgs, sizeof(vpfs_pkg_t));
    assert(vpfs->pkg != NULL);
    vpfs->name = calloc(nb_items, sizeof(char*));
    assert(vpfs->name != NULL);
    vpfs->item = calloc(nb_items, sizeof(vpfs_item_t));
    assert(vpfs->item != NULL);
    vpfs->sha = calloc(nb_items, sizeof(uint64_t));
    assert(vpfs->sha != NULL);
    vpfs->root = direntry_create_root();
    assert(vpfs->root != NULL);
    return true;
}

static void vpfs_free(vpfs_t *vpfs)
{
    direntry_destroy(vpfs->root);
    for (uint32_t i = 0; i < vpfs->header.nb_items; i++)
    {
        free(vpfs->name[i]);
    }
    free(vpfs->root);
    free(vpfs->pkg);
    free(vpfs->item);
    free(vpfs->name);
    free(vpfs->sha);
    free(vpfs->sorted_sha);
    free(vpfs->data);
}

// NB: This does not check if an item with the same path already exists
static bool vpfs_add(vpfs_t* vpfs, vpfs_item_t* item, char* path)
{
    assert(path != NULL);
    assert(vpfs->index < vpfs->header.nb_items);

    dir_entry_t* entry = vpfs->root;
    for (size_t i = 0; path[i] != 0; i++)
    {
        if (path[i] == '/')
        {
            entry = direntry_find(entry, path, i);
            if (entry == NULL)
            {
                sys_error("A subfolder from '%s' is missing\n", path);
            }
        }
    }

    // If this is not the root directory, add a new entry
    if (path[0] != 0)
    {
        if (!direntry_add(entry, path, item->flags & VPFS_ITEM_TYPE_DIR))
        {
            return false;
        }
    }

    uint8_t sha[20];
    sha1sum((uint8_t*)path, strlen(path), sha);
    vpfs->sha[vpfs->index] = get32be(sha);
    vpfs->sha[vpfs->index] |= ((uint64_t)vpfs->index) << 32;
    memcpy(vpfs->item[vpfs->index].xsha, &sha[4], 16);
    vpfs->item[vpfs->index].flags = item->flags;
    vpfs->item[vpfs->index].offset = item->offset;
    vpfs->item[vpfs->index].size = item->size;
    vpfs->item[vpfs->index].pkg_index = item->pkg_index;

    vpfs->name[vpfs->index++] = path;
    return true;
}

static vpfs_item_t* vpfs_find_item(vpfs_t* vpfs, char* path)
{
    assert(path != NULL);
    uint8_t sha[20];

    sha1sum((uint8_t*)path, strlen(path), sha);
    uint32_t i, sha_head = get32be(sha);

    for (i = 0; i < vpfs->header.nb_items; i++)
    {
        if (sha_head == vpfs->sorted_sha[i])
        {
            // sha_head is not guaranteed to be unique so make sure the full SHA-1 matches
            if (memcmp(&sha[4], vpfs->item[i].xsha, 16) == 0)
            {
                break;
            }
        }
    }
    if (i >= vpfs->header.nb_items)
    {
        sys_error("Directory entry for '%s' is missing\n", path);
    }
    return &vpfs->item[i];
}

static void vpfs_set_data(vpfs_t* vpfs, void* buf, uint32_t len)
{
    uint32_t req_size = vpfs->data_len + len;
    if (req_size > vpfs->data_max)
    {
        vpfs->data_max = ((req_size + 1023) / 1024) * 1024;
        if (vpfs->data == NULL)
        {
            vpfs->data = malloc(vpfs->data_max);
            if (vpfs->data == NULL)
            {
                sys_error("Could not allocate data buffer\n");
            }
        }
        else
        {
            vpfs->data = realloc(vpfs->data, vpfs->data_max);
            if (vpfs->data == NULL)
            {
                sys_error("Could not reallocate data buffer\n");
            }
        }
    }
    memcpy(&vpfs->data[vpfs->data_len], buf, len);
    vpfs->data_len += len;
}

// https://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Quicksort#Iterative_Quicksort
// While the array is of 64-bit elements, we only sort according to the low 32-bits
#define QS_MAX 64
static void quicksort(uint64_t array[], uint32_t len)
{
    uint32_t left = 0, stack[QS_MAX], pos = 0, seed = rand();
    for (; ; )
    {
        for (; left + 1 < len; len++)
        {
            if (pos == QS_MAX)
            {
                len = stack[pos = 0];
            }
            uint32_t pivot = (uint32_t)array[left + seed % (len - left)];
            seed = seed * 69069 + 1;
            stack[pos++] = len;
            for (uint32_t right = left - 1; ; )
            {
                while ((uint32_t)array[++right] < pivot);
                while (pivot < (uint32_t)array[--len]);
                if (right >= len)
                {
                    break;
                }
                uint64_t temp = array[right];
                array[right] = array[len];
                array[len] = temp;
            }
        }
        if (pos == 0)
        {
            break;
        }
        left = len;
        len = stack[--pos];
    }
}

static const char* basename(const char* path)
{
    size_t index;

    if (path == NULL)
        return NULL;

    for (index = strlen(path) - 1; index > 0; index--)
    {
        if ((path[index] == '/') || (path[index] == '\\'))
        {
            index++;
            break;
        }
    }
    return &path[index];
}

// Note: This dirname function will keep the trailing '/' or '\'
static const char* dirname(const char* path)
{
    static char dirname[1024] = { 0 };
    size_t index;

    if (path == NULL)
        return NULL;

    for (index = strlen(path) - 1; index > 0; index--)
    {
        if ((path[index] == '/') || (path[index] == '\\'))
        {
            index++;
            break;
        }
    }
    if (index == 0)
        return NULL;
    strcpy(dirname, path);
    dirname[index] = 0;
    return dirname;
}

int main(int argc, char* argv[])
{
    bool needs_keypress = separate_console();
    sys_output_init();
    const char* pkg_arg = NULL;
    const char* zrif_arg = NULL;

    sys_printf("vpfs v0.9\n");

    for (int i = 1; i < argc; i++)
    {
        if (pkg_arg != NULL)
        {
            zrif_arg = argv[i];
            break;
        } else
        {
            pkg_arg = argv[i];
        }
    }

    if (pkg_arg == NULL)
    {
        fprintf(stderr, "ERROR: no pkg file specified\n");
        sys_error("Usage: %s file.pkg [zRIF]\n", argv[0]);
    }

    sys_printf("[*] loading %s...\n", basename(pkg_arg));

    uint32_t pkg_index = 0;
    uint64_t pkg_size;
    sys_file pkg = sys_open(pkg_arg, &pkg_size);

    uint8_t pkg_header[PKG_HEADER_SIZE + PKG_HEADER_EXT_SIZE];
    sys_read(pkg, 0, pkg_header, sizeof(pkg_header));

    if (get32be(pkg_header) != 0x7f504b47 || get32be(pkg_header + PKG_HEADER_SIZE) != 0x7f657874)
    {
        sys_error("ERROR: not a pkg file\n");
    }

    // http://www.psdevwiki.com/ps3/PKG_files
    uint64_t meta_offset = get32be(pkg_header + 8);
    uint32_t meta_count = get32be(pkg_header + 12);
    uint32_t item_count = get32be(pkg_header + 20);
    uint64_t total_size = get64be(pkg_header + 24);
    uint64_t enc_offset = get64be(pkg_header + 32);
    uint64_t enc_size = get64be(pkg_header + 40);
    const uint8_t* iv = pkg_header + 0x70;
    int key_type = pkg_header[0xe7] & 7;

    if (pkg_size < total_size)
    {
        sys_error("ERROR: pkg file is too small\n");
    }
    if (pkg_size < enc_offset + item_count * 32)
    {
        sys_error("ERROR: pkg file is too small\n");
    }

    uint32_t content_type = 0;
    uint32_t sfo_offset = 0;
    uint32_t sfo_size = 0;
    uint32_t items_offset = 0;
    uint32_t items_size = 0;

    for (uint32_t i = 0; i < meta_count; i++)
    {
        uint8_t block[16];
        sys_read(pkg, meta_offset, block, sizeof(block));

        uint32_t type = get32be(block + 0);
        uint32_t size = get32be(block + 4);

        if (type == 2)
        {
            content_type = get32be(block + 8);
        }
        else if (type == 13)
        {
            items_offset = get32be(block + 8);
            items_size = get32be(block + 12);
        }
        else if (type == 14)
        {
            sfo_offset = get32be(block + 8);
            sfo_size = get32be(block + 12);
        }

        meta_offset += 2 * sizeof(uint32_t) + size;
    }

    pkg_type type;

    // http://www.psdevwiki.com/ps3/PKG_files
    if (content_type == 0x15)
    {
        type = PKG_TYPE_VITA_APP;
    }
    else if (content_type == 0x16)
    {
        type = PKG_TYPE_VITA_DLC;
    }
    else
    {
        // Can't be bothered about PSM and PSP/PSX have their own package "virtualization"
        sys_error("ERROR: unsupported content type 0x%x", content_type);
    }

    if ((key_type < 2) || (key_type > 4))
    {
        sys_error("ERROR: unsupported key type");
    }

    aes128_key key;
    uint8_t main_key[16];
    aes128_init(&key, pkg_aes_key[key_type - 2]);
    aes128_ecb_encrypt(&key, iv, main_key);
    aes128_init(&key, main_key);

    char content[256];
    char title[256];
    char category[256];
    char min_version[256];
    char pkg_version[256];
    uint8_t rif[1024];
    uint32_t rif_size = 0;

    parse_sfo(pkg, sfo_offset, sfo_size, category, title, content, min_version, pkg_version);

    if (type == PKG_TYPE_VITA_APP && strcmp(category, "gp") == 0)
    {
        type = PKG_TYPE_VITA_PATCH;
    }

    if (type != PKG_TYPE_VITA_PATCH && zrif_arg != NULL)
    {
        rif_size = (uint32_t)zrif_decode(zrif_arg, rif, sizeof(rif));
        const char* rif_content_id = (char*)rif + (type == PKG_TYPE_VITA_PSM ? 0x50 : 0x10);
        if (strncmp(rif_content_id, content, 0x30) != 0)
        {
            sys_error("ERROR: zRIF content id '%s' doesn't match pkg '%s'\n", rif_content_id, content);
        }
    }

    sys_printf("[*] processing %s\n", pkg_type_name[type]);

    vpfs_t vpfs;
    vpfs_init(&vpfs, 1, item_count + NUM_EXTRA_ITEMS);
    vpfs.pkg[pkg_index].type = type; // Not sure if really needed
    strncpy(vpfs.pkg[pkg_index].content_id, content, sizeof(vpfs.pkg[pkg_index].content_id) - 1);
    sys_printf("[*] content_id %s\n", vpfs.pkg[pkg_index].content_id);
    snprintf(vpfs.pkg[pkg_index].path, sizeof(vpfs.pkg[pkg_index].path), "ux0:pkg/%s", basename(pkg_arg));
    memcpy(vpfs.pkg[pkg_index].aes_key, main_key, sizeof(main_key));
    memcpy(vpfs.pkg[pkg_index].aes_iv, iv, 16);

    bool sce_sys_package_created = false;

    sys_output_progress_init(pkg_size);

    char* name;
    vpfs_item_t vpfs_item = { 0 };

    // Add an entry for the root directory ("")
    vpfs_item.flags = VPFS_ITEM_TYPE_DIR;
    vpfs_item.pkg_index = -1;
    assert(vpfs_add(&vpfs, &vpfs_item, strdup("")));

    for (uint32_t item_index = 0; item_index < item_count; item_index++)
    {
        uint8_t item[32];
        uint64_t item_offset = items_offset + item_index * 32;
        sys_read(pkg, enc_offset + item_offset, item, sizeof(item));
        aes128_ctr_xor(&key, iv, item_offset / 16, item, sizeof(item));

        uint32_t name_offset = get32be(item + 0);
        uint32_t name_size = get32be(item + 4);
        uint64_t data_offset = get64be(item + 8);
        uint64_t data_size = get64be(item + 16);
        uint8_t flags = item[27];

        assert(name_offset % 16 == 0);
        assert(data_offset % 16 == 0);
        assert(pkg_size >= enc_offset + name_offset + name_size);
        assert(pkg_size >= enc_offset + data_offset + data_size);

        name = malloc(name_size + 2);
        const aes128_key* item_key = &key;
        sys_read(pkg, enc_offset + name_offset, name, name_size);
        aes128_ctr_xor(item_key, iv, name_offset / 16, (uint8_t*)name, name_size);
        name[name_size] = 0;

        if (flags == 4 || flags == 18)
        {
            // Directory
            if (strcmp(name, "sce_sys/package") == 0)
            {
                sce_sys_package_created = true;
            }

            // offset and size will be in the .vpfs -> negative index
            vpfs_item.flags = VPFS_ITEM_TYPE_DIR;
            vpfs_item.pkg_index = -1;
            assert(vpfs_add(&vpfs, &vpfs_item, name));
        }
        else
        {
            // Regular file
            if ((type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC || type == PKG_TYPE_VITA_PATCH) &&
                strcmp(name, "sce_sys/package/digs.bin") == 0)
            {
                free(name);
                name = strdup("sce_sys/package/body.bin");
                vpfs_item.flags = VPFS_ITEM_TYPE_BIN;
            }
            else
            {
                vpfs_item.flags = VPFS_ITEM_TYPE_AES;
            }

            vpfs_item.offset = data_offset;
            vpfs_item.size = data_size;
            vpfs_item.pkg_index = pkg_index;
            assert(vpfs_add(&vpfs, &vpfs_item, name));
        }
    }

    if (!sce_sys_package_created)
    {
        sys_printf("[*] creating sce_sys/package/\n");
        name = strdup("sce_sys/package");
        vpfs_item.flags = VPFS_ITEM_TYPE_DIR;
        vpfs_item.pkg_index = -1;
        assert(vpfs_add(&vpfs, &vpfs_item, name));
    }

    sys_printf("[*] adding sce_sys/package/head.bin\n");
    name = strdup("sce_sys/package/head.bin");
    vpfs_item.flags = VPFS_ITEM_TYPE_BIN;
    vpfs_item.pkg_index = pkg_index;
    vpfs_item.offset = 0;
    vpfs_item.size = enc_offset + items_size;
    assert(vpfs_add(&vpfs, &vpfs_item, name));

    sys_printf("[*] adding sce_sys/package/tail.bin\n");
    name = strdup("sce_sys/package/tail.bin");
    vpfs_item.flags = VPFS_ITEM_TYPE_BIN;
    vpfs_item.pkg_index = pkg_index;
    vpfs_item.offset = enc_offset + enc_size;
    vpfs_item.size = pkg_size - vpfs_item.offset;
    assert(vpfs_add(&vpfs, &vpfs_item, name));

    sys_printf("[*] adding sce_sys/package/stat.bin\n");
    name = strdup("sce_sys/package/stat.bin");
    uint8_t stat_bin[768] = { 0 };
    vpfs_item.flags = VPFS_ITEM_TYPE_BIN;
    vpfs_item.pkg_index = -1;   // Local item
    vpfs_item.size = sizeof(stat_bin);
    vpfs_set_data(&vpfs, stat_bin, sizeof(stat_bin));
    assert(vpfs_add(&vpfs, &vpfs_item, name));

    if ((type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC) && (zrif_arg != NULL))
    {
        sys_printf("[*] adding sce_sys/package/work.bin\n");
        name = strdup("sce_sys/package/work.bin");
        vpfs_item.flags = VPFS_ITEM_TYPE_BIN;
        vpfs_item.pkg_index = -1;   // Local item
        vpfs_item.size = rif_size;
        vpfs_set_data(&vpfs, rif, rif_size);
        assert(vpfs_add(&vpfs, &vpfs_item, name));
    }

    vpfs.header.nb_items = vpfs.index;

    // Sort items according to the first 32-bits of the SHA-1
    sys_printf("[*] sorting entries...\n");
    quicksort(vpfs.sha, vpfs.header.nb_items);
    vpfs.sorted_sha = calloc(vpfs.header.nb_items, sizeof(uint32_t));
    assert(vpfs.sorted_sha != NULL);
    vpfs_item_t *sorted_item = calloc(vpfs.header.nb_items, sizeof(vpfs_item_t));
    assert(sorted_item != NULL);
    for (uint32_t i = 0; i < vpfs.header.nb_items; i++)
    {
        vpfs.sorted_sha[i] = (uint32_t)vpfs.sha[i];
        memcpy(&sorted_item[i], &vpfs.item[vpfs.sha[i] >> 32], sizeof(vpfs_item_t));
    }
    free(vpfs.item);
    vpfs.item = sorted_item;

    // Create the directory listings
    sys_printf("[*] adding local data...\n");
    dir_dump_t dir_dump = { 0 };
    direntry_dump_init(&dir_dump, vpfs.root);
    dir_dump.dir = calloc(dir_dump.nb_dirs, sizeof(dir_record_t));
    assert(dir_dump.dir != NULL);
    dir_dump.buf = calloc(dir_dump.buf_len, 1);
    assert(dir_dump.buf != NULL);
    direntry_dump(&dir_dump, vpfs.root);

    uint32_t local_data_offset = sizeof(vpfs_header_t) + sizeof(vpfs_pkg_t) * vpfs.header.nb_pkgs +
        (sizeof(uint32_t) + sizeof(vpfs_item_t)) * vpfs.header.nb_items;
    for (uint32_t i = 0; i < dir_dump.nb_dirs; i++)
    {
        vpfs_item_t* item = vpfs_find_item(&vpfs, (i == 0) ? "" : dir_dump.dir[i].path);
        assert(item->flags & VPFS_ITEM_TYPE_DIR);
        item->offset = local_data_offset + dir_dump.dir[i].offset;
        item->size = dir_dump.dir[i].size;
    }

    // Set the offset of stat.bin and optionally work.bin, also in local_data
    vpfs_item_t* item = vpfs_find_item(&vpfs, "sce_sys/package/stat.bin");
    assert(item != NULL);
    item->offset = local_data_offset + dir_dump.buf_len;
    if ((type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC) && (zrif_arg != NULL))
    {
        item = vpfs_find_item(&vpfs, "sce_sys/package/work.bin");
        assert(item != NULL);
        item->offset = local_data_offset + dir_dump.buf_len + sizeof(stat_bin);
    }

    char path[1024] = "", *dir = (char*)dirname(pkg_arg);

    if (dir != NULL)
    {
        strcpy(path, dir);
    }

    size_t len = strlen(path);
    strncpy(&path[len], &vpfs.pkg[pkg_index].content_id[7], 9);
    path[len + 9] = 0;
    strncat(path, ".vpfs", sizeof(path) - 1);
    sys_printf("[*] creating %s...\n", path);
    sys_file fd = sys_create(path);
    uint64_t offset = 0;
    sys_write(fd, 0, &vpfs.header, sizeof(vpfs_header_t));
    offset += sizeof(vpfs_header_t);
    sys_write(fd, offset, vpfs.pkg, sizeof(vpfs_pkg_t) * vpfs.header.nb_pkgs);
    offset += sizeof(vpfs_pkg_t) * vpfs.header.nb_pkgs;
    sys_write(fd, offset, vpfs.sorted_sha, sizeof(uint32_t) * vpfs.header.nb_items);
    offset += sizeof(uint32_t) * vpfs.header.nb_items;
    sys_write(fd, offset, vpfs.item, sizeof(vpfs_item_t) * vpfs.header.nb_items);
    offset += sizeof(vpfs_item_t) * vpfs.header.nb_items;
    sys_write(fd, offset, dir_dump.buf, dir_dump.buf_len);
    offset += dir_dump.buf_len;
    sys_write(fd, offset, vpfs.data, vpfs.data_len);
    sys_close(fd);

    free(dir_dump.dir);
    free(dir_dump.buf);
    vpfs_free(&vpfs);

    sys_printf("[*] done!\n");

#ifdef _CRTDBG_MAP_ALLOC
    _CrtDumpMemoryLeaks();
#endif

    if (needs_keypress)
    {
        sys_printf("\nPress any key to exit...\n");
        fflush(stdout);
        getchar();
    }
    sys_output_done();

    return 0;
}
