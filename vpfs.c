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

#include "vpfs_aes.h"
#include "vpfs_utils.h"
#include "vpfs_sys.h"

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
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
#define MAX_FILENAME            1024

// https://wiki.henkaku.xyz/vita/Packages#AES_Keys
static const uint8_t pkg_vita_2[] = { 0xe3, 0x1a, 0x70, 0xc9, 0xce, 0x1d, 0xd7, 0x2b, 0xf3, 0xc0, 0x62, 0x29, 0x63, 0xf2, 0xec, 0xcb };
static const uint8_t pkg_vita_3[] = { 0x42, 0x3a, 0xca, 0x3a, 0x2b, 0xd5, 0x64, 0x9f, 0x96, 0x86, 0xab, 0xad, 0x6f, 0xd8, 0x80, 0x1f };
static const uint8_t pkg_vita_4[] = { 0xaf, 0x07, 0xfd, 0x59, 0x65, 0x25, 0x27, 0xba, 0xf1, 0x33, 0x89, 0x66, 0x8b, 0x17, 0xd9, 0xea };

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
    PKG_TYPE_VITA_APP,
    PKG_TYPE_VITA_DLC,
    PKG_TYPE_VITA_PATCH,
    PKG_TYPE_VITA_PSM,
} pkg_type;

static bool separate_console()
{
#if defined(_WIN32) || defined(__CYGWIN__)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
        return 0;
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
    if (entry == NULL)
        return NULL;
    entry->path = path;
    return entry;
}

static bool direntry_add(dir_entry* entry, const char* path)
{
    if (entry == NULL)
        return false;
    if (entry->index == entry->max)
    {
        if (entry->max == 0)
        {
            entry->max = DIRENTRY_INITIAL_CHILDREN_SIZE;
            entry->children = calloc(entry->max, sizeof(dir_entry));
            if (entry->children == NULL)
                return false;
        }
        else
        {
            entry->max *= 2;
            dir_entry* old_table = entry->children;
            entry->children = (dir_entry*)realloc(entry->children, entry->max * sizeof(dir_entry));
            memset(&entry->children[entry->max / 2], 0, entry->max / 2 * sizeof(dir_entry));
            if (entry->children == NULL)
            {
                free(old_table);
                entry->index = 0;
                entry->max = 0;
                sys_output("Could not reallocate dir_entry array\n");
                return false;
            }
        }
    }
    entry->children[entry->index++].path = path;
    return true;
}

static void direntry_destroy(dir_entry* entry)
{
    if ((entry == NULL) && (entry->children == NULL))
        return;
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
            return &entry->children[i];
    }
    return NULL;
}

// NB: This does not check if an item with the same path already exists
static bool add_item(dir_entry* entry, const char* path)
{
    // Locate each directory along our path
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
        sys_output("DIRECTORY %s\n", entry->path);
    for (size_t i = 0; i < entry->index; i++)
    {
        sys_output("- %s\n", entry->children[i].path);
    }
    for (size_t i = 0; i < entry->index; i++)
    {
        display_fs(&entry->children[i]);
    }
}

void test_add_item(void)
{
    dir_entry *root = direntry_create("[ROOT]");
    assert(root != NULL);

    assert(add_item(root, "first_level_dir1") == true);
    assert(add_item(root, "first_level_dir1/second_level_file1.bin") == true);
    assert(add_item(root, "first_level_dir1/second_level_dir1") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir2") == false);
    assert(add_item(root, "first_level_dir2") == true);
    assert(add_item(root, "first_level_file1.bin") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3/third_level_file1.bin") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3/third_level_file2.bin") == true);
    assert(add_item(root, "first_level_dir1/second_level_file2.bin") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3/third_level_file3.bin") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3/third_level_file4.bin") == true);
    assert(add_item(root, "first_level_dir2/second_level_dir3/third_level_file5.bin") == true);
    sys_output("[*] test_add_item okay..\n");

    display_fs(root);

    direntry_destroy(root);
    free(root);
}

int main(int argc, char* argv[])
{
    bool needs_keypress = separate_console();
    sys_output_init();
    const char* pkg_arg = NULL;

    sys_output("vpdb v0.5\n");

//    test_add_item();

    if (argc != 2)
    {
        fprintf(stderr, "ERROR: no pkg file specified\n");
        sys_error("Usage: %s file.pkg\n", argv[0]);
    }
    pkg_arg = argv[1];
    sys_output("[*] loading...\n");

    uint64_t pkg_size;
    sys_file pkg = sys_open(pkg_arg, &pkg_size);

    uint8_t pkg_header[PKG_HEADER_SIZE + PKG_HEADER_EXT_SIZE];
    sys_read(pkg, 0, pkg_header, sizeof(pkg_header));

    if (get32be(pkg_header) != 0x7f504b47 || get32be(pkg_header + PKG_HEADER_SIZE) != 0x7F657874)
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

//    vpfs_header vfs_header = { VPFS_MAGIC, VPFS_VERSION, 0, 0 };
    vpfs_pkg vfs_pkg = { 0 };
    char** vfs_name = calloc(item_count, sizeof(char*));
    vpfs_item* vfs_item = calloc(item_count, sizeof(vpfs_item));
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
        // Can't be bothered about PSM/PSP/PSX
        sys_error("ERROR: unsupported content type 0x%x", content_type);
    }

    uint8_t main_key[16];
    if (key_type == 1)
    {
        sys_error("ERROR: unsupported PS3 key type");
    }
    else if (key_type == 2)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_2);
        aes128_ecb_encrypt(&key, iv, main_key);
    }
    else if (key_type == 3)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_3);
        aes128_ecb_encrypt(&key, iv, main_key);
    }
    else if (key_type == 4)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_4);
        aes128_ecb_encrypt(&key, iv, main_key);
    }

    aes128_key key;
    aes128_init(&key, main_key);

    char content[256];
    char title[256];
    char category[256];
    char min_version[256];
    char pkg_version[256];
    const char* id = content + 7;
    const char* id2 = id + 13;

    // Vita APP, DLC or PATCH
    parse_sfo(pkg, sfo_offset, sfo_size, category, title, content, min_version, pkg_version);

    if (type == PKG_TYPE_VITA_APP && strcmp(category, "gp") == 0)
    {
        type = PKG_TYPE_VITA_PATCH;
    }

    char root[1024];
    if (type == PKG_TYPE_VITA_DLC)
    {
//        snprintf(root, sizeof(root), "%s [%.9s] [%s] [DLC-%s]%s", title, id, get_region(id), id2, ext);
        sys_output("[*] unpacking Vita DLC\n");
    }
    else if (type == PKG_TYPE_VITA_PATCH)
    {
//        snprintf(root, sizeof(root), "%s [%.9s] [%s] [PATCH] [v%s]%s", title, id, get_region(id), pkg_version, ext);
        sys_output("[*] unpacking Vita PATCH\n");
    }
    else if (type == PKG_TYPE_VITA_APP)
    {
//        snprintf(root, sizeof(root), "%s [%.9s] [%s]%s", title, id, get_region(id), ext);
        sys_output("[*] unpacking Vita APP\n");
    }
    else
    {
        assert(0);
        sys_error("ERROR: unsupported type\n");
    }

//    sys_output("[*] creating '%s' archive\n", root);
    vfs_pkg.type = type; // Not sure if really needed
    // TODO: copy content_id?
    snprintf(vfs_pkg.path, sizeof(vfs_pkg.path), "ux0:pkg/%s", pkg_arg);
    memcpy(vfs_pkg.aes_key, main_key, sizeof(main_key));
    memcpy(vfs_pkg.aes_iv, iv, 16);

//     out_begin(root, zipped);
    root[0] = 0;

    if (type == PKG_TYPE_VITA_DLC)
    {
        sys_vstrncat(root, sizeof(root), "addcont");
//        out_add_folder(root);

        sys_vstrncat(root, sizeof(root), "/%.9s", id);
//        out_add_folder(root);

        sys_vstrncat(root, sizeof(root), "/%s", id2);
//        out_add_folder(root);
    }
    else if (type == PKG_TYPE_VITA_PATCH)
    {
        sys_vstrncat(root, sizeof(root), "patch");
//        out_add_folder(root);

        sys_vstrncat(root, sizeof(root), "/%.9s", id);
//        out_add_folder(root);
    }
    else if (type == PKG_TYPE_VITA_APP)
    {
        sys_vstrncat(root, sizeof(root), "app");
//        out_add_folder(root);

        sys_vstrncat(root, sizeof(root), "/%.9s", id);
//        out_add_folder(root);
    }
    else
    {
        assert(0);
        sys_error("ERROR: unsupported type\n");
    }

    char path[1024];

    int sce_sys_package_created = 0;

    sys_output_progress_init(pkg_size);

    dir_entry *vfs_root = direntry_create("[ROOT]");
    uint32_t vfs_index = 0;
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

        if (pkg_size < enc_offset + name_offset + name_size ||
            pkg_size < enc_offset + data_offset + data_size)
        {
            sys_error("ERROR: pkg file is too short, possibly corrupted\n");
        }

        vfs_name[vfs_index] = malloc(name_size + 2);
        const aes128_key* item_key = &key;
        sys_read(pkg, enc_offset + name_offset, vfs_name[vfs_index], name_size);
        aes128_ctr_xor(item_key, iv, name_offset / 16, (uint8_t*)vfs_name[vfs_index], name_size);
        vfs_name[vfs_index][name_size] = 0;

        if (flags == 4 || flags == 18)
        {
            // Directory
            if (vfs_name[vfs_index][name_size - 1] != '/')
            {
                vfs_name[vfs_index][name_size++] = '/';
                vfs_name[vfs_index][name_size] = 0;
            }
            assert(add_item(vfs_root, vfs_name[vfs_index]));
        }
        else
        {
            if ((type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC || type == PKG_TYPE_VITA_PATCH) && strcmp("sce_sys/package/digs.bin", vfs_name[vfs_index]) == 0)
            {
                vfs_name[vfs_index] = _strdup("sce_sys/package/body.bin");
                vfs_item[vfs_index].flags = VPFS_ITEM_TYPE_BIN;
            }
            else
            {
                vfs_item[vfs_index].flags = VPFS_ITEM_TYPE_AES;
            }
            assert(add_item(vfs_root, vfs_name[vfs_index]));
        }

//        sys_output("[%u/%u] %s\n", vfs_index + 1, item_count, vfs_name[vfs_index]);

        vfs_item[vfs_index].pkg_index = 0;
        vfs_item[vfs_index].offset = data_offset;
        vfs_item[vfs_index].size = data_size;
        vfs_index++;
    }
//    vfs_header.nb_pkgs = 1;
//    vfs_header.nb_items = vfs_index;

    sys_output("[*] unpacking completed\n");

    if (type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_DLC || type == PKG_TYPE_VITA_PATCH)
    {
        // TODO: Add these paths/dirs to our items, with type VPFS_ITEM_TYPE_BIN

        if (!sce_sys_package_created)
        {
            sys_output("[*] creating sce_sys/package\n");
            snprintf(path, sizeof(path), "%s/sce_sys/package/", root);
//            out_add_folder(path);
        }

        sys_output("[*] creating sce_sys/package/head.bin\n");
        snprintf(path, sizeof(path), "%s/sce_sys/package/head.bin", root);

//        out_begin_file(path, 0);
        uint64_t head_size = enc_offset + items_size;
        uint64_t head_offset = 0;
        while (head_size != 0)
        {
            uint8_t PKG_ALIGN(16) buffer[1 << 16];
            uint32_t size = (uint32_t)min64(head_size, sizeof(buffer));
            sys_read(pkg, head_offset, buffer, size);
//            out_write(buffer, size);
            head_size -= size;
            head_offset += size;
        }
//        out_end_file();

        sys_output("[*] creating sce_sys/package/tail.bin\n");
        snprintf(path, sizeof(path), "%s/sce_sys/package/tail.bin", root);

//        out_begin_file(path, 0);
        uint64_t tail_offset = enc_offset + enc_size;
        while (tail_offset != pkg_size)
        {
            uint8_t PKG_ALIGN(16) buffer[1 << 16];
            uint32_t size = (uint32_t)min64(pkg_size - tail_offset, sizeof(buffer));
            sys_read(pkg, tail_offset, buffer, size);
//            out_write(buffer, size);
            tail_offset += size;
        }
//        out_end_file();

        sys_output("[*] creating sce_sys/package/stat.bin\n");
        snprintf(path, sizeof(path), "%s/sce_sys/package/stat.bin", root);

//        uint8_t stat[768] = { 0 };
//        out_begin_file(path, 0);
//        out_write(stat, sizeof(stat));
//        out_end_file();
    }

//    out_end();

    if (type == PKG_TYPE_VITA_APP || type == PKG_TYPE_VITA_PATCH)
    {
        sys_output("[*] minimum fw version required: %s\n", min_version);
    }

    sys_output("[DIRECTORY LISTING]\n");
    display_fs(vfs_root);
    direntry_destroy(vfs_root);
    free(vfs_root);
    free(vfs_item);

    for (uint32_t i = 0; i < item_count; i++)
    {
        free(vfs_name[i]);
    }
    free(vfs_name);

    sys_output("[*] done!\n");
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
