#!/bin/bash

# sources from https://github.com/harbour/core

DIR1="include/harbour/"
DIR2="include/wine/"
DIR3="include/git/compat/"

mkdir -p $DIR1
cd $DIR1

wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbvmpub.h
wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbdefs.h
wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbver.h
wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbsetup.h
wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbsetup.ch
wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbtrace.h

wget -N https://raw.githubusercontent.com/harbour/core/master/include/hbpcode.h
wget -N https://raw.githubusercontent.com/harbour/core/master/src/compiler/hbpcode.c

awk '
    /const HB_BYTE hb_comp_pcode_len/{ FOUND=1};
    { if (FOUND) { print $0}}
    /^\/\*|^\s\*/ { print $0 }
    /};/ {exit}
' hbpcode.c > hbpcode_awked.h


# sources from https://github.com/wine-mirror/wine

cd ../../
mkdir -p $DIR2
cd $DIR2

wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/winnt.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/basetsd.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/guiddef.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/excpt.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/windef.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/pshpack4.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/poppack.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/winnt.rh
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/pshpack2.h
wget -N https://raw.githubusercontent.com/wine-mirror/wine/master/include/pshpack8.h

#sources from https://github.com/git/git

cd ../../
mkdir -p $DIR3
cd $DIR3

wget -N https://raw.githubusercontent.com/git/git/master/compat/memmem.c 

awk ' /git-compat-util.h/{
			    print "#include <string.h>";
			    next;
			}
	{print $0}
	' memmem.c > memmem_awked.c

cd ../

wget -N https://raw.githubusercontent.com/git/git/master/COPYING
wget -N https://raw.githubusercontent.com/git/git/master/LGPL-2.1

cd ../