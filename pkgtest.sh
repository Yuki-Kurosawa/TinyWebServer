# Copyright (c) 2025 Yuki Kurosawa
# SPDX-License-Identifier: MIT
#!/bin/bash

./cleanenv.sh
dpkg-buildpackage -sa --force-sign
lintian
sudo dpkg -i ../*.deb
yuki --version
sudo yuki
sudo apt purge -y yuki