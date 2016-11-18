#!/bin/sh
#
# Bootstrap autotools environment
libtoolize --automake
aclocal
automake -ac
autoconf
echo 'Ready to rock!'
