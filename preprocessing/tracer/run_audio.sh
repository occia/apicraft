#!/bin/bash

set -e
set -x

# audio
clang++ -g -dynamiclib -o libhook.dylib libhook.mm jsoncpp.mm -x objective-c -target x86_64-apple-macos10.15 -isysroot /Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework AudioToolbox -framework CoreFoundation -Wno-deprecated-declarations -Wno-c++11-extensions

export DYLD_INSERT_LIBRARIES=./libhook.dylib

afclip ../../samples/sample_audio.mp3
#/System/Applications/Messages.app/Contents/MacOS/Messages
#"/System/Applications/QuickTime Player.app/Contents/MacOS/QuickTime Player"
#/System/Applications/Notes.app/Contents/MacOS/Notes
#/System/Applications/VoiceMemos.app/Contents/MacOS/VoiceMemos

unset DYLD_INSERT_LIBRARIES
