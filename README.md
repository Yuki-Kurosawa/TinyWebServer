Yuki — Tiny Web Server 🚀
=========================

[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](/LICENSE)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](/CODE_OF_CONDUCT.md)

yuki is a light-weight and easy extendable web server.

yuki is free and open source software, distributed under the terms of [MIT license](/LICENSE)

---

## Table of Contents
- [Yuki — Tiny Web Server 🚀](#yuki--tiny-web-server-)
  - [Table of Contents](#table-of-contents)
- [How it works](#how-it-works)
  - [Modules](#modules)
  - [Configurations](#configurations)
  - [Runtime](#runtime)
- [Downloading and installing](#downloading-and-installing)
  - [Stable and Mainline binaries](#stable-and-mainline-binaries)
  - [Linux binary installation process](#linux-binary-installation-process)
    - [Upgrades](#upgrades)
- [Building from source](#building-from-source)
  - [Installing dependencies](#installing-dependencies)
    - [Installing compiler and make utility](#installing-compiler-and-make-utility)
    - [Installing dependency libraries](#installing-dependency-libraries)
  - [Cloning the yuki GitHub repository](#cloning-the-yuki-github-repository)
  - [Development build](#development-build)
  - [Configuring the build](#configuring-the-build)
  - [Compiling](#compiling)
  - [Location of binary and installation](#location-of-binary-and-installation)
  - [Running and testing the installed binary](#running-and-testing-the-installed-binary)

# How it works
yuki is installed software with binary packages available for Linux distributions. If you want to use latest version with latest patches/features/fixes, just build yuki from source.

Supported Systems:
| OS | Minimum Version |
|----|----|
| Debian | 13.x  |
| Ubuntu | 24.04 |
| Other | latest |

## Modules
yuki is comprised of individual modules, each extending core functionality by providing additional, configurable features.

yuki modules can be built and distributed as static modules. Static modules are defined at build-time, compiled, and distributed in the resulting binaries.

built-in modules:
| Name | Usage | Notes |
|----|----|----|
| mod_ssl | HTTPS communications | can't removable, always enabled |
| mod_pcre2 | Regex matches | can't removable, always enabled |
| mod_magic | MIME detections | can't removable, always enabled |

> [!TIP]
> You can issue the following command to see which static modules your yuki binaries were built with:
```bash
yuki -v
```

## Configurations
yuki is highly flexible and configurable. Provisioning the software is achieved via text-based config file(s) accepting parameters called "[Directives](#)".

> [!NOTE]
> The set of directives available to your distribution of yuki is dependent on which [modules](#modules) have been made available to it.

## Runtime
Rather than running in tons of processes, yuki is architected to scale beyond Operating System process limitations by operating as a collection of threads. They include:
- A "master" thread that maintains worker threads, as well as, reads and evaluates configuration files.
- One or more "worker" threads that process data (eg. HTTP requests).

# Downloading and installing
Follow these steps to download and install precompiled yuki binaries. You may also choose to [build yuki locally from source code](#building-from-source).

## Stable and Mainline binaries
yuki binaries are built and distributed in two versions: stable and mainline. Stable binaries are built from stable branches and only contain critical fixes backported from the mainline version. Mainline binaries are built from the [master branch](https://github.com/Yuki-Kurosawa/TinyWebServer/tree/master) and contain the latest features and bugfixes. You'll need to decide which is appropriate for your purposes.

## Linux binary installation process
The yuki binary installation process takes advantage of package managers native to specific Linux distributions. 

Debian: [You can track releases here](https://qa.debian.org/developer.php?login=yuki@ksyuki.com)

### Upgrades
Future upgrades to the latest version can be managed using the same package manager without the need to manually download and verify binaries.

# Building from source
The following steps can be used to build yuki from source code available in this repository.

## Installing dependencies
Most Linux distributions will require several dependencies to be installed in order to build yuki. The following instructions are specific to the `apt` package manager, widely available on most Ubuntu/Debian distributions and their derivatives.

> [!TIP]
> It is always a good idea to update your package repository lists prior to installing new packages.
> ```bash
> sudo apt update
> ```

### Installing compiler and make utility
Use the following command to install the GNU C compiler and Make utility.

```bash
sudo apt install gcc make
```

### Installing dependency libraries

```bash
sudo apt install pkgconf libssl-dev libpcre2-dev libmagic-dev 
```

## Cloning the yuki GitHub repository
Using your preferred method, clone the yuki repository into your development directory. See [Cloning a GitHub Repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) for additional help.

```bash
git clone https://github.com/Yuki-Kurosawa/TinyWebServer.git
```

## Development build
build yuki with following command:
```bash
./build.sh
sudo ./yuki
```

test with curl from a new terminal session:
```bash
curl localhost
```

## Configuring the build
Prior to building yuki, you must run the `configure` script with appropriate flags. This will generate a Makefile in your yuki source root directory that can then be used to compile yuki.

From the yuki source code repository's root directory:

```bash
./configure --prefix=/usr
```

## Compiling
The `configure` script will generate a `Makefile` in the yuki source root directory upon successful execution. To compile yuki into a binary, issue the following command from that same directory:

```bash
make
```

## Location of binary and installation
After successful compilation, a binary will be generated at `<YUKI_SRC_ROOT_DIR>/yuki`. To install this binary, issue the following command from the source root directory:

```bash
sudo make install
sudo ./debian/postinst configure
```

> [!IMPORTANT]
> The binary will be installed into the `/usr/bin/yuki` directory.

## Running and testing the installed binary
To run the installed binary, issue the following command:

```bash
sudo systemctl daemon-reload
sudo systemctl start yuki-web
```

You may test yuki operation using `curl`.

```bash
curl localhost
```

The output of which should contains:

```html
It Works!
```

