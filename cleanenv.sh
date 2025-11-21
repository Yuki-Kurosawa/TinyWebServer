#! /bin/bash
make distclean
rm -rvf debian/yuki/* *~ autom4te.cache/ *.1
git archive -o ../yuki_1.0.0.orig.tar.gz HEAD