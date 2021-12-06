#!/bin/bash

set -e
set -x

clang++ -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Foundation -framework CoreGraphics -framework CoreText -framework AppKit -framework AudioToolBox -Wno-deprecated-declarations -Wno-c++11-extensions

export DYLD_INSERT_LIBRARIES=./libhook.dylib

#
# font
# trace directly
#

qlmanage -p ../../samples/OpenSans-Regular.otf
#"/System/Applications/Font Book.app/Contents/MacOS/Font Book"
#/System/Applications/Messages.app/Contents/MacOS/Messages
#/System/Applications/Mail.app/Contents/MacOS/Mail 
#/System/Applications/TextEdit.app/Contents/MacOS/TextEdit
#/System/Applications/Notes.app/Contents/MacOS/Notes
#/Applications/Safari.app/Contents/MacOS/Safari 
#/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal

unset DYLD_INSERT_LIBRARIES
