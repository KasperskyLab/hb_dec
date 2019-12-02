# Simple Harbour decompiler: hb_dec

## Descrption
Simple Harbour decompiler `hb_dec` finds, loads and prints the humanized version of Harbour opcodes from compiled Harbour script.
Helped us with reverse engeneering compiled Harbour scripts.

Not all opcodes are implemented (60 of 180 but it covered our needs).

Was tested on harbour binaries compiled by Borland C compiler and MINGW.

## 3rdparty libs

I took some files from https://github.com/harbour/core to know harbour specific structures, constants...
Same for parsing PE's https://github.com/wine-mirror/wine.
Also i used memmem.c from https://github.com/git/git for windows compatibility.

## Build instructions

Use cmake to build: `mkdir build; cd build; cmake ..; make`

Worked fine on Linux, but code is also Windows friendly (checked with i686-w64-mingw32-c++ (GCC) 7.3-win32 20180312)

## Additional information

* https://harbour.github.io/
* https://github.com/harbour/core
* https://github.com/harbour/core/blob/master/doc/pcode.txt
* https://sourceforge.net/p/hmgs-minigui/svncode/334/tree/trunk/MiniGUI/SAMPLES/Advanced/Decompiler/

