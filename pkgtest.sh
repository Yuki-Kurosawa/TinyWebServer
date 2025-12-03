# Copyright (c) 2025 Yuki Kurosawa
# SPDX-License-Identifier: MIT
#!/bin/bash

./cleanenv.sh
dpkg-buildpackage -sa --force-sign
lintian --fail-on error --allow-root --display-info --pedantic
sudo dpkg -i ../*.deb
yuki --version
sudo systemctl start yuki-web.service
sudo systemctl status yuki-web.service
curl http://localhost/ --verbose
sudo systemctl stop yuki-web.service
sudo apt purge -y yuki