#!/bin/bash

set -e
set -x

# cgpdf
clang++ -g -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework CoreGraphics -framework CoreFoundation -framework Foundation -Wno-deprecated-declarations -Wno-c++11-extensions

export DYLD_INSERT_LIBRARIES=./libhook.dylib

qlmanage -p ../../samples/sample.pdf 
#/System/Applications/Preview.app/Contents/MacOS/Preview
#/System/Applications/Mail.app/Contents/MacOS/Mail 
#./TextEdit.app/Contents/MacOS/TextEdit
#./Notes.app/Contents/MacOS/Notes

unset DYLD_INSERT_LIBRARIES
