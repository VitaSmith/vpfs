# pkg2zip

[![Travis CI Build Status][img_travis]][travis] [![AppVeyor Build Status][img_appveyor]][appveyor] [![Downloads][img_downloads]][downloads] [![Release][img_latest]][latest] [![License][img_license]][license]

Utility that decrypts PlayStation Vita pkg file and creates zip package. Supports also PSX pkg files for use with [Adrenaline](https://github.com/TheOfficialFloW/Adrenaline).

Optionally saves [NoNpDrm](https://github.com/TheOfficialFloW/NoNpDrm) license into work.bin file. You must provide license key.

# Requirements

* [Henkaku](https://henkaku.xyz/) / [Enso](https://enso.henkaku.xyz/)
* [NoNpDrm](https://github.com/TheOfficialFloW/NoNpDrm)
* to use DLC pkg files, [VitaShell](https://github.com/TheOfficialFloW/VitaShell) **v1.76** or newer required
* [Adrenaline](https://github.com/TheOfficialFloW/Adrenaline) for PSX titles

# Features

* **portable**, written in cross-platform C code, runs on Windows, GNU/Linux, macOS (system dependent functionality is isolated in sys.c file).
* **small**, has no external library dependencies and uses very minimal dynamic memory allocations.
* **fast**, uses AESNI hardware accelerated AES decryption if supported by CPU (requires [AESNI](https://en.wikipedia.org/wiki/AES_instruction_set) and [SSSE3](https://en.wikipedia.org/wiki/SSSE3) instructions).
* **simple**, creates zip package with same folder structure that Vita expects (just drag & drop all file from zip archive to ux0:). Zip file is created directly from pkg without any intermediate temporary files.
* **DLC** and **PATCH** pkg unpacking.
* **PSX** pkg unpacking.

Limitations:

* currently no PSM, PSP or PSP Mini pkg files are supported.

# Usage

If you have zRIF fake license, then execute:

    pkg2zip package.pkg zRIF_STRING

This will create `title [id] [region].zip` file. Title, ID and region is automatically detected from pkg file. It will include work.bin file.

If you don't have zRIF fake license, but just want to unpack files, then omit last argument:

    pkg2zip package.pkg

Resulting zip file will not include work.bin. This is useful for patch pkg files.

PSX pkg files do not require zRIF argument. It will be ignored.

# Generating zRIF string

If you have working main.bin file you can create zRIF string with `rif2zrif.py` python script:

    $ python rif2zrif.py path/to/main.bin

It will print zRIF string to stdout.

To generate main.bin from zRIF string use `zrif2rif.py` script:

    $ python zrif2rif.py zRIF work.bin

Last argument is optional, it specifies where to save file and defaults to work.bin name.

# Download

Get latest Windows binaries [here](https://github.com/mmozeiko/pkg2zip/releases).

ArchLinux users can build binary with [pkg2zip](https://aur.archlinux.org/packages/pkg2zip/) package in AUR repository. For example, with pacaur:

    $ pacaur -S pkg2zip

# Building

Execute `make` if you are on GNU/Linux or macOS.

On Windows you can build either with MinGW (get [MinGW-w64](http://www.msys2.org/)) or [Visual Studio 2017 Community Edition](https://www.visualstudio.com/vs/community/).
* for MinGW make sure you have make installed, and then execute `mingw32-make`
* for Visual Studio run `build.cmd`

# Alternatives

* https://github.com/RikuKH3/unpkg_vita
* https://github.com/St4rk/PkgDecrypt
* https://github.com/weaknespase/PkgDecrypt

# License

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

[travis]: https://travis-ci.org/mmozeiko/pkg2zip/
[appveyor]: https://ci.appveyor.com/project/mmozeiko/pkg2zip/
[downloads]: https://github.com/mmozeiko/pkg2zip/releases
[latest]: https://github.com/mmozeiko/pkg2zip/releases/latest
[license]: https://github.com/mmozeiko/pkg2zip/blob/master/LICENSE
[img_travis]: https://api.travis-ci.org/mmozeiko/pkg2zip.svg?branch=master
[img_appveyor]: https://ci.appveyor.com/api/projects/status/xmkl6509ahlp9b7k/branch/master?svg=true
[img_downloads]: https://img.shields.io/github/downloads/mmozeiko/pkg2zip/total.svg?maxAge=3600
[img_latest]: https://img.shields.io/github/release/mmozeiko/pkg2zip.svg?maxAge=3600
[img_license]: https://img.shields.io/github/license/mmozeiko/pkg2zip.svg?maxAge=2592000
