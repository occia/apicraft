#!/bin/bash

set -e
set -x

# compile
clang++ -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Foundation -framework CoreGraphics -framework CoreText -framework AppKit -framework AudioToolBox -Wno-deprecated-declarations


export DYLD_INSERT_LIBRARIES=./libhook.dylib

# run
/System/Applications/Preview.app/Contents/MacOS/Preview

unset DYLD_INSERT_LIBRARIES
