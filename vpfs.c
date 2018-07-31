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

static dir_entry* direntry_create(const char* path)
{
    dir_entry* entry = calloc(1, sizeof(dir_entry));

    assert(entry != NULL);

    entry->path = path;

    return entry;
}

static bool direntry_add(dir_entry* entry, const char* path)
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
            entry->children = calloc(entry->max, sizeof(dir_entry));
            if (entry->children == NULL)
            {
                return false;
            }
        }
        else
        {
            entry->max *= 2;
            entry->children = (dir_entry*)realloc(entry->children, entry->max * sizeof(dir_entry));
            if (entry->children == NULL)
            {
                sys_error("Could not reallocate dir_entry array for %d entries\n", entry->max);
            }
            memset(&entry->children[entry->max / 2], 0, entry->max / 2 * sizeof(dir_entry));
         }
    }

    entry->children[entry->index++].path = path;

    return true;
}

static void direntry_destroy(dir_entry* entry)
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

static dir_entry* find_item(dir_entry* entry, const char* path, size_t len)
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

// NB: This does not check if an item with the same path already exists
static bool add_item(dir_entry* entry, const char* path)
{
    assert(path != NULL);

    for (size_t i = 0; path[i] != 0; i++)
    {
        if ((path[i] == '/') && (path[i+1] != 0))
        {
            entry = find_item(entry, path, i);
            // If this assert is false, it means we've seen a child before the parent
            assert(entry != NULL);
        }
    }

    return direntry_add(entry, path);
}

void display_fs(dir_entry* entry)
{
    if (entry->path[strlen(entry->path) - 1] == '/')
    {
        sys_printf("DIRECTORY %s\n", entry->path);
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        sys_printf("- %s\n", entry->children[i].path);
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        display_fs(&entry->children[i]);
    }
}

bool vpfs_init(vpfs_t *vpfs, uint32_t nb_pkgs, uint32_t nb_items)
{
    memset(vpfs, 0, sizeof(vpfs_t));
    vpfs->header.magic = VPFS_MAGIC;
    vpfs->header.version = VPFS_VERSION;
    vpfs->header.nb_pkgs = nb_pkgs;
    vpfs->pkg = calloc(nb_pkgs, sizeof(vpfs_pkg));
    assert(vpfs->pkg != NULL);
    vpfs->name = calloc(nb_items, sizeof(char*));
    assert(vpfs->name != NULL);
    vpfs->item = calloc(nb_items, sizeof(vpfs_item));
    assert(vpfs->item != NULL);
    vpfs->sha = calloc(nb_items, sizeof(uint64_t));
    assert(vpfs->sha != NULL);
    vpfs->root = direntry_create("[ROOT]");
    assert(vpfs->root != NULL);
    return true;
}

void vpfs_free(vpfs_t *vpfs)
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
}

int main(int argc, char* argv[])
{
    bool needs_keypress = separate_console();
    sys_output_init();
    const char* pkg_arg = NULL;

    sys_printf("vpfs v0.6\n");

    if (argc != 2)
    {
        fprintf(stderr, "ERROR: no pkg file specified\n");
        sys_error("Usage: %s file.pkg\n", argv[0]);
    }
    pkg_arg = argv[1];
    size_t base_name;
    for (base_name = strlen(pkg_arg) - 1; base_name > 0; base_name--)
    {
        if ((pkg_arg[base_name] == '/') || (pkg_arg[base_name] == '\\'))
        {
            base_name++;
            break;
        }
    }

    sys_printf("[*] loading %s...\n", &pkg_arg[base_name]);

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

    parse_sfo(pkg, sfo_offset, sfo_size, category, title, content, min_version, pkg_version);

    if (type == PKG_TYPE_VITA_APP && strcmp(category, "gp") == 0)
    {
        type = PKG_TYPE_VITA_PATCH;
    }

    sys_printf("[*] processing %s\n", pkg_type_name[type]);

    vpfs_t vpfs;
    vpfs_init(&vpfs, 1, item_count + NUM_EXTRA_ITEMS);
    vpfs.pkg[pkg_index].type = type; // Not sure if really needed
    strncpy(vpfs.pkg[pkg_index].content_id, content, sizeof(vpfs.pkg[pkg_index].content_id) - 1);
    sys_printf("[*] content_id %s\n", vpfs.pkg[pkg_index].content_id);
    snprintf(vpfs.pkg[pkg_index].path, sizeof(vpfs.pkg[pkg_index].path), "ux0:pkg/%s", pkg_arg);
    memcpy(vpfs.pkg[pkg_index].aes_key, main_key, sizeof(main_key));
    memcpy(vpfs.pkg[pkg_index].aes_iv, iv, 16);

    bool sce_sys_package_created = false;

    sys_output_progress_init(pkg_size);

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

        vpfs.name[item_index] = malloc(name_size + 2);
        const aes128_key* item_key = &key;
        sys_read(pkg, enc_offset + name_offset, vpfs.name[item_index], name_size);
        aes128_ctr_xor(item_key, iv, name_offset / 16, (uint8_t*)vpfs.name[item_index], name_size);
        vpfs.name[item_index][name_size] = 0;

        if (flags == 4 || flags == 18)
        {
            // Directory
            if (vpfs.name[item_index][name_size - 1] != '/')
            {
                vpfs.name[item_index][name_size++] = '/';
                vpfs.name[item_index][name_size] = 0;
            }

            if (strcmp("sce_sys/package/", vpfs.name[item_index]) == 0)
            {
                sce_sys_package_created = true;
            }

            assert(add_item(vpfs.root, vpfs.name[item_index]));

            // offset and size will be in the .vpfs > negative index
            vpfs.item[item_index].flags = VPFS_ITEM_TYPE_DIR;
            vpfs.item[item_index].pkg_index = -1;
        }
        else
        {
            // Regular file
            if ((type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC || type == PKG_TYPE_VITA_PATCH) &&
                strcmp("sce_sys/package/digs.bin", vpfs.name[item_index]) == 0)
            {
                vpfs.name[item_index] = _strdup("sce_sys/package/body.bin");
                vpfs.item[item_index].flags = VPFS_ITEM_TYPE_BIN;
            }
            else
            {
                vpfs.item[item_index].flags = VPFS_ITEM_TYPE_AES;
            }

            assert(add_item(vpfs.root, vpfs.name[item_index]));

            vpfs.item[item_index].offset = data_offset;
            vpfs.item[item_index].size = data_size;
            vpfs.item[item_index].pkg_index = pkg_index;
        }

//        sys_printf("[%u/%u] %s\n", vfs_index + 1, item_count, vfs_name[vfs_index]);

        vpfs.item[item_index].pkg_index = pkg_index;
        vpfs.item[item_index].offset = data_offset;
        vpfs.item[item_index].size = data_size;
    }

    if (!sce_sys_package_created)
    {
        sys_printf("[*] creating sce_sys/package/\n");
        vpfs.name[item_count] = strdup("sce_sys/package/");
        assert(add_item(vpfs.root, vpfs.name[item_count]));
        vpfs.item[item_count].flags = VPFS_ITEM_TYPE_DIR;
        vpfs.item[item_count].pkg_index = -1;
        item_count++;
    }

    sys_printf("[*] adding sce_sys/package/head.bin\n");
    vpfs.name[item_count] = strdup("sce_sys/package/head.bin");
    assert(add_item(vpfs.root, vpfs.name[item_count]));
    vpfs.item[item_count].flags = VPFS_ITEM_TYPE_BIN;
    vpfs.item[item_count].pkg_index = pkg_index;
    vpfs.item[item_count].offset = 0;
    vpfs.item[item_count].size = enc_offset + items_size;
    item_count++;

    sys_printf("[*] adding sce_sys/package/tail.bin\n");
    vpfs.name[item_count] = strdup("sce_sys/package/tail.bin");
    assert(add_item(vpfs.root, vpfs.name[item_count]));
    vpfs.item[item_count].flags = VPFS_ITEM_TYPE_BIN;
    vpfs.item[item_count].pkg_index = pkg_index;
    vpfs.item[item_count].offset = enc_offset + enc_size;
    vpfs.item[item_count].size = pkg_size - vpfs.item[item_count].offset;
    item_count++;

    sys_printf("[*] adding sce_sys/package/stat.bin\n");
    vpfs.name[item_count] = strdup("sce_sys/package/stat.bin");
    assert(add_item(vpfs.root, vpfs.name[item_count]));
    vpfs.item[item_count].flags = VPFS_ITEM_TYPE_BIN;
    vpfs.item[item_count].pkg_index = pkg_index;
    // TODO: Once .vpkg creation is set add 768 zeroed bytes and point sce_sys/package/stat.bin to it
    vpfs.item[item_count].offset = ~0;
    vpfs.item[item_count].size = 768;
    item_count++;

//        uint8_t stat[768] = { 0 };
//        out_begin_file(path, 0);
//        out_write(stat, sizeof(stat));
//        out_end_file();

    vpfs.header.nb_items = item_count;

    if (type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_PATCH)
    {
        sys_printf("[*] minimum fw version required: %s\n", min_version);
    }

    sys_printf("DIRECTORY LIST:\n");
    display_fs(vpfs.root);
    vpfs_free(&vpfs);

    sys_printf("[*] done!\n");
    sys_output_done();

#ifdef _CRTDBG_MAP_ALLOC
    _CrtDumpMemoryLeaks();
#endif

    if (needs_keypress) {
        printf("\nPress any key to exit...\n");
        fflush(stdout);
        getchar();
    }

    return 0;
}
