#!/bin/bash

set -e
set -x

clang++ -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Foundation -framework CoreGraphics -framework CoreText -framework AppKit -framework AudioToolBox -Wno-deprecated-declarations -Wno-c++11-extensions

export DYLD_INSERT_LIBRARIES=./libhook.dylib


qlmanage -p ../../samples/not_kitty.jpg
#/System/Applications/Preview.app/Contents/MacOS/Preview
#/System/Applications/Messages.app/Contents/MacOS/Messages
#/Applications/Safari.app/Contents/MacOS/Safari 
#/System/Applications/Mail.app/Contents/MacOS/Mail 
#/System/Applications/TextEdit.app/Contents/MacOS/TextEdit
#/System/Applications/Notes.app/Contents/MacOS/Notes
#./Photos.app/Contents/MacOS/Photos

unset DYLD_INSERT_LIBRARIES
