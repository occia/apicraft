#!/bin/bash

set -e
set -x

# rtf
clang++ -g -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Foundation -framework CoreFoundation -framework CoreText -Wno-deprecated-declarations -Wno-c++11-extensions

export DYLD_INSERT_LIBRARIES=./libhook.dylib

qlmanage -p ../../samples/sample.rtf 
#./TextEdit.app/Contents/MacOS/TextEdit
#./Notes.app/Contents/MacOS/Notes
#/Users/kvmmac/Downloads/0xlib_harness/CoreTextRTF/CoreTextRTF.app/Contents/MacOS/CoreTextRTF

unset DYLD_INSERT_LIBRARIES
