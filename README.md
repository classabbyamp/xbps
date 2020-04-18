[![Packaging status](https://repology.org/badge/vertical-allrepos/xbps.svg)](https://repology.org/project/xbps/versions)

[![Build Status](https://travis-ci.org/void-linux/xbps.svg?branch=master)](https://travis-ci.org/void-linux/xbps)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/void-linux/xbps.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/void-linux/xbps/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/void-linux/xbps.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/void-linux/xbps/context:cpp)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/20884/badge.svg)](https://scan.coverity.com/projects/void-linux-xbps)

## XBPS

The X Binary Package System (in short XBPS) is a binary package system
**designed and implemented from scratch**. Its goal is to be fast, easy to use,
bug-free, featureful and portable as much as possible.

The XBPS code is totally **compatible with POSIX/SUSv2/C99 standards**, and
released with a **Simplified BSD license (2 clause)**. There is a well
documented API provided by the XBPS Library that is the basis for its frontends
to handle binary packages and repositories. Some highlights:

 * Supports **multiple local/remote repositories** (HTTP/HTTPS/FTP).
 * **RSA signed remote repositories** (NEW in 0.27).
 * Supports **multiple compression formats** for repositories:
   gzip (zlib), bzip2, lz4, xz, [zstd](https://github.com/facebook/zstd) (default).
 * Supports **multiple compression formats** for package archives:
   gzip (zlib), bzip2, lz4, xz, [zstd](https://github.com/facebook/zstd) (default).
 * **SHA256 hashes** for package metadata, files and binary packages.
 * Supports **package states** (ala dpkg) to mitigate broken package
   installs/updates.
 * Ability to **resume** partial package install/updates.
 * Ability to **unpack only files that have been modified** in package updates.
 * Ability to use **virtual packages**.
 * Ability to **ignore completely** any number of packages in dependency resolution.
 * Ability to **check for incompatible shared libraries in reverse
   dependencies**.
 * Ability to **update reverse dependencies** of any number of packages or **globally**
   in a single transaction.
 * Ability to **replace packages**.
 * Ability to **put packages on hold** (to never update them. NEW in 0.16).
 * Ability to **preserve/update configuration files**.
 * Ability to **force reinstallation** of any installed package.
 * Ability to **downgrade any** installed package.
 * Ability to **execute pre/post install/remove/update scriptlets**.
 * Ability to **check package integrity**: missing files, hashes, missing or
   unresolved (reverse)dependencies, dangling or modified symlinks, etc.

XBPS contains an almost complete test suite, currently with ~200 test cases,
and its number is growing daily! If you find any issue and you can reproduce it,
we will fix it and a new test case will be created. No more regressions!

XBPS is brought to you by:

- [Juan Romero Pardines (main author)](https://github.com/xtraeme)
- [Enno Boland](https://github.com/Gottox)
- [Duncan Overbruck](https://github.com/duncaen)

and many other contributors in the free community that have helped improving it.
See the `AUTHORS` file for a complete list of contributors.

Thanks to all who have contributed.

### Build requirements

To build this you'll need:

  - A C99 compiler (clang, gcc, pcc, tcc)
  - A POSIX compatible shell
  - [GNU make](https://www.gnu.org/software/make/)
  - [pkgconf](http://pkgconf.org/)
  - [zlib](https://www.zlib.net)
  - [openssl](https://www.openssl.org) or [libressl](https://www.libressl.org/)
  - [libarchive >= 3.3.3](https://www.libarchive.org) with lz4 and zstd support.

and optionally:

  - [graphviz](https://www.graphviz.org) and [doxygen](https://www.doxygen.org)
    (--enable-api-docs) to build API documentation.
  - [atf >= 0.15](https://github.com/jmmv/kyua) (--enable-tests) to build the
    Kyua test suite.

### Building and testing for dummies

```
$ git clone https://github.com/void-linux/xbps
$ cd xbps
$ ./configure --enable-rpath --prefix=/usr --sysconfdir=/etc
$ make -j$(nproc)
$ make DESTDIR=~/xbps-git install clean
$ export PATH=~/xbps-git/usr/bin:$PATH
$ xbps-query -V
...
```

Thanks to `--enable-rpath` you can install it anywhere and it will still use
the libxbps shared library at `$ORIGIN/../lib`, that means that if xbps
is installed to `$HOME/xbps-git/usr`, the executables will use
`$HOME/xbps-git/usr/lib` to locate `libxbps`.

Happy testing!

### Tests

To run the test suite make sure *kyua* is installed and run the following:

```
$ ./configure --enable-tests
$ make
$ make check
```

### Build instructions

Standard configure script (not generated by GNU autoconf).

```
$ ./configure --prefix=/blah
$ make -jX
$ make install
```

By default PREFIX is set `/usr/local` and may be changed by setting `--prefix`
in the `configure` script. The `DESTDIR` variable is also supported at the
install stage.

There are some more options that can be tweaked, see them with
`./configure --help`.

Good luck!

### Binaries

Binaries for Linux compiled statically with the musl C library are available:

* [aarch64](https://a-hel-fi.m.voidlinux.org/static/xbps-static-latest.aarch64-musl.tar.xz)
* [armv6hf](https://a-hel-fi.m.voidlinux.org/static/xbps-static-latest.armv6l-musl.tar.xz)
* [i686](https://a-hel-fi.m.voidlinux.org/static/xbps-static-latest.i686-musl.tar.xz)
* [x86\_64](https://a-hel-fi.m.voidlinux.org/static/xbps-static-latest.x86_64-musl.tar.xz)
* [mips32](https://a-hel-fi.m.voidlinux.org/static/xbps-static-latest.mips-musl.tar.xz)

These builds are available on all official void mirrors, along with their
*sha256* [checksums](https://a-hel-fi.m.voidlinux.org/static/sha256sums.txt).

### Usage instructions

The xbps package includes the following utilities (among others, not a complete list):

 * `xbps-create (1)`      - XBPS utility to create binary packages
 * `xbps-dgraph (1)`      - XBPS utility to generate dot(1) graphs
 * `xbps-install (1)`     - XBPS utility to install and update packages
 * `xbps-pkgdb (1)`       - XBPS utility to report and fix issues in pkgdb
 * `xbps-query (1)`       - XBPS utility to query for package and repository information
 * `xbps-reconfigure (1)` - XBPS utility to configure installed packages
 * `xbps-remove (1)`      - XBPS utility to remove packages
 * `xbps-rindex (1)`      - XBPS utility to handle local binary package repositories

In the following sections there will be a brief description of how these utilities currently work.

### Package expressions

In the following examples there will be commands accepting an argument such as `<package expression>`. A package expression is a form to match a pattern; currently XBPS >= 0.19 supports 3 ways to specify them:

 * by specifying a package name, i.e `foo`.
 * by specifying the exact package name and version, i.e `foo-1.0_1`.
 * by specifying a package name and version separated by any of the following version comparators:
      * `<` less than
      * `>` greater than
      * `<=` less or equal than
      * `>=` greater or equal than

    Such example would be `foo>=2.0` or `blah-foo<=1.0`.

### Repositories

Repositories can be declared in a configuration file of the `configuration` or `system configuration` directories:

 * `<sysconfdir>/xbps.d` - The configuration directory (set to `/etc/xbps.d`)
 * `<sharedir>/xbps.d` - The system directory (set to `/usr/share/xbps.d`)

A configuration file bearing the same filename in `/etc/xbps.d` overrides the one from `<sharedir>/xbps.d`.
By default the `XBPS` package provides only the main Void repository in the `/usr/share/xbps.d/00-repository-main.conf` file.

Additional repositories can be added by installing any of the following XBPS packages or creating new configuration files manually:

```
$ xbps-query -Rs void-repo
[*] void-repo-debug-3_1            Void Linux drop-in file for the debug repository
[*] void-repo-multilib-3_1         Void Linux drop-in file for the multilib repository
[*] void-repo-multilib-nonfree-3_1 Void Linux drop-in file for the multilib/nonfree repository
[*] void-repo-nonfree-3_1          Void Linux drop-in file for the nonfree repository
$
```

> Repositories specified in the `configuration` directory are added to the head of the list, while repositories specified via `system configuration` directories are appended to the existing list.

> If no repositories are found it's possible to declare them manually via the command line option `--repository`, currently accepted in `xbps-install(1)` and `xbps-query(1)`.

### xbps-query - querying packages and repositories

> xbps-query(1) will try to match `<package expression>` in local packages. This behaviour
can be changed by enabling the `-R` or `--repository` option to force repository mode.

To query the list of installed packages:

    $ xbps-query -l

To query the list of working repositories:

    $ xbps-query -L

To query the list of installed packages that were installed manually (not as dependencies):

    $ xbps-query -m

To query the list of packages on hold (won't be upgraded automatically):

    $ xbps-query -H

To query the list of installed package orphans (packages that were installed as dependencies but there is not any package currently that requires it):

    $ xbps-query -O

To query a package and show its meta information:

    $ xbps-query <package expression>

> Additionally the `-p or --property` option can be used to only show a specific key of a package:

    $ xbps-query --property=pkgver xbps
    xbps-0.19_1
    $

> Multiple properties can be specified by delimiting them with commas, i.e `-p key,key2`.

To query a package and show its file list:

    $ xbps-query -f <package expression>

To query a package and show required run-time dependencies:

    $ xbps-query -x <package expression>

To query a package and show required reverse run-time dependencies:

    $ xbps-query -X <package expression>

To query for packages matching a file with specified pattern(s) (ownedby mode):

    $ xbps-query -o <pattern>

> Where `<pattern>` is a shell wildcard pattern as explained in fnmatch(3); e.g `"*.png"`.

> Multiple `<patterns>` can be specified as arguments.

To query for packages matching pkgname/version/description with specified pattern(s) (search mode):

    $ xbps-query -s <pattern>

> The same rules explained above in the `ownedby` mode shall be applied.

### xbps-install - installing and updating packages

To synchronize remote repository index files:

    $ xbps-install -S

> The `-S, --sync` option can be combined while installing or updating packages, i.e `xbps-install -Su`.

To install a package:

    $ xbps-install <package expression>

To install multiple packages at once:

    $ xbps-install <package expression> <package expressions>

To update a single package:

    $ xbps-install -u <package expression>

To update all packages (also known as dist-upgrade in Debian/Ubuntu):

    $ xbps-install -u

> The `-n, --dry-run` option can be used to print what packages will be updated and/or installed and doesn't need permissions in the target rootdir, which can be useful to list updates.

### xbps-remove - removing packages

To remove a package:

    $ xbps-remove <package name>

To recursively remove unneeded dependencies that were installed by the target package:

    $ xbps-remove -R <package name>

To remove package orphans:

    $ xbps-remove -o

To clean the cache directory and remove outdated packages and/or packages with wrong hash:

    $ xbps-remove -O

> To remove package orphans and clean the cache repository both options can be combined, i.e `xbps-remove -Oo`.

### xbps-reconfigure - configure (or force configuration of) a package

The `xbps-reconfigure(1)` utility may be used to configure packages that were not previously
(perhaps due to a power outage, process killed, etc) or simply to force package
reconfiguration. By default and unless the `-f, --force` option is set, only packages that
were not configured will be processed.

Its usage is simple, specify a package name or `a, --all` for all packages:

    $ xbps-reconfigure [-f] <package name> | -a

### xbps-pkgdb - checking for errors in packages and pkgdb

The `xbps-pkgdb(1)` utility may be used to check for errors in packages and in the package database.
It is also used to update the *package database* format (if there have been changes). It works exactly the
same way as `xbps-reconfigure(1)` and expects a package name or -a, --all for all packages.

    $ xbps-pkgdb <package name> | -a

To put a package on hold mode (won't be upgraded in dist-upgrade mode):

    $ xbps-pkgdb -m hold <package name>

To remove a package from hold mode:

    $ xbps-pkgdb -m unhold <package name>

To put a package in automatic mode (as it were installed as a dependency):

    $ xbps-pkgdb -m auto <package name>

To put a package in manual mode (won't be detected as orphan):

    $ xbps-pkgdb -m manual <package name>

To update the pkgdb format to the latest one:

    $ xbps-pkgdb -u

> NOTE: updating the pkgdb format does not happen too frequently, therefore it's only necessary in rare circumstances.

### xbps-rindex - Create, update and administer local repositories

This command only has 3 operation modes:

 * Add [-a, --all]: adds the specified packages into the specified repository and removes previous entry if found:

        $ xbps-rindex -a /path/to/repository/*.xbps

> The `-f, --force` option can be used to forcefully register a package into the repository index, even if the same version is already registered.

 * Clean [-c, --clean]: cleans the index of the specified repository by removing outdated or invalid entries (nonexistent packages, unmatched hashes, etc):

        $ xbps-rindex -c /path/to/repository

 * Remove-obsoletes [-r, --remove-obsoletes]: removes obsolete packages in repository (outdated, broken and unmatched hashes):

        $ xbps-rindex -r /path/to/repository

### Examples

Upgrade all packages in the system, without asking for an answer:

    # xbps-install -Syu

Clean the cache directory and remove package orphans:

    # xbps-remove -Oo

Show information of a package available in repositories:

    $ xbps-query -R xbps

Show filelist of a package available in repositories:

    $ xbps-query -Rf xbps

Find the packages that own the file `/bin/ls` in repositories:

    $ xbps-query -Ro /bin/ls

Make a package keepable (won't be detected as orphan):

    # xbps-pkgdb -m manual xbps

Search for packages in repositories matching the `xbps` pattern in its `pkgver` and `short_desc` objects:

    $ xbps-query -Rs xbps

Remove a package and all unnecessary dependencies that were installed:

    # xbps-remove -R xbmc

Appending repositories via command line:

    $ xbps-query --repository=<url> ...
    # xbps-install --repository=<url> ...

Switch an installed package to on *hold* mode (won't be updated via `xbps-install -u`):

    # xbps-pkgdb -m hold <pkgname>

Switch an installed package to the *unhold* mode (will be updated if there are updates):

    # xbps-pkgdb -m unhold <pkgname>

Check for errors on installed packages and in pkgdb:

    # xbps-pkgdb -a

Listing all files not managed by xbps:

```sh
#!/bin/sh

tmp=$(mktemp -dt xbps-disownedXXXXXX)
pkg=$tmp/pkg
fs=$tmp/fs

trap "rm -rf $tmp" EXIT

xbps-query -o \* | cut -d ' ' -f2 | sort > $pkg
find /boot /etc /opt /usr /var -xdev -type f -print | sort > $fs

comm -23 $fs $pkg
```
