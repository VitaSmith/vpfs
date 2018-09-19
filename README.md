# VPFS

![VPFS Screenshot](https://raw.githubusercontent.com/VitaSmith/vpfs/master/pics/vpfs_screenshot.jpg)

VPFS (Vita PKG File System) is a virtual file system for the Sony PlayStation Vita that allows access to
PKG archives (such as the kind you get from PSN) without having to go through a costly decryption and
installation process.

In other words, VPFS is designed to grant PS Vita users complete access to PKG files as if they had been
installed on one's system.

This is achieved by:
- First, creating a small `.vpfs` content database for each archive
- Second, running a kernel module that consumes the `.vpfs` data and, along with the original `.pkg` file
  can reconstruct the virtual data, such as file listing, decrypted data and so on, and present it as
  local file system content

## License

[GNU General Public License (GPL) version 3](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Status

__Pre ALPHA__

You can browse and read data from VitaShell, but you cannot use it to promote or run apps because there are
__unknown__ file system calls used by ScePfsMgr, which must be overridden for `sce_pfs/files.db` access...

## Compilation and testing

1. Download the Ridge Racer game installer pkg from [here](http://zeus.dl.playstation.net/cdn/UP0700/PCSE00001_00/IRPERCkHKvxNuhhuMvATYhUJimapzQvevrRLryolHuueAPfxDZnnOzWcNtjIvICnauoHCkVmffZQDjIYeOgcDWzKjNveGcxtClJLm.pkg) (777 MB).
2. Rename the file to `UP0700-PCSE00001_00-RIDGERACERPSVITA.pkg`.
3. Compile the `vpfs` __PC__ application from the root directory.
4. On PC, run the command `vpfs UP0700-PCSE00001_00-RIDGERACERPSVITA.pkg` to create the `PCSE00001.vpfs` file.
   You can also add the zRIF if you want a `work.bin` to be embedded in the `.vpfs`.
5. Copy `UP0700-PCSE00001_00-RIDGERACERPSVITA.pkg` to `ux0:pkg/` (you may need to create this directory) and `PCSE00001.vpfs` to `ux0:app/`.
6. Compile the module application in `module/` (`vpfs.skprx`) and copy it to `ux0:tai/`.
7. Compile the test application in `test/` (`vpfs_test.vpk`) and install it on your Vita.
8. Run the test application which will load the kernel module, run a series of tests, and then unload the kernel module.

Alternatively, you can choose to close the application when it asks you to press `X` to continue with the
tests to keep the kernel module loaded. Then you can try to open VitaShell, which should let you navigate
to `ux0:app/PCSE00001/` and let your browse the content of the PKG, even as it has not been installed.

## TODO

- Complete the overrides (async calls and so on).
- Validate that VPFS content can be promoted if `work.bin` is present.
- Validate that a promoted application can run as a VPFS.
- File/directory deletion.
- Create an SceShell module/plugin/app that detects `.pkg` and creates the relevant `.vpfs`.
- Double buffering for read + AES-CTR decription and other optimisation.
- Support other types of archives besides `.pkg` (e.g. `.zip`).

## Credits

- mmozeiko for [pkg2zip](https://github.com/mmozeiko/pkg2zip) on which the `vpfs` PC application is based.
- yifanlu for taiHEN.
- TheFlow, CelesteBlue and dots-tb for their awesome work on varions applications that have been
  invaluable for the creation of the kernel plugin.
- Everyone who contributed to the Vita SDK.
