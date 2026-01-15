#! /bin/bash
make distclean
rm -rvf debian/yuki/* *~ autom4te.cache/ *.1 .pc .deps .libs debian/patches
git archive -o ../yuki_1.0.1.orig.tar.gz HEAD
