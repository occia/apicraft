# font
python merge_json.py ../workdir/ida_cov_font.json 10.15.7_19H15_libFontParser.dylib.json 10.15.7_19H15_libFontRegistry.dylib.json 10.15.7_19H15_CoreText.json 10.15.7_19H15_CoreGraphics.json 10.15.7_19H15_CoreFoundation.json

# image
python merge_json.py ../workdir/ida_cov_img.json 10.15.7_19H15_CoreGraphics.json 10.15.7_19H15_ImageIO.json 10.15.7_19H15_vImage.json 10.15.7_19H15_CoreFoundation.json 10.15.7_19H15_CoreDisplay.json 10.15.7_19H15_AppleJPEG.json 10.15.7_19H15_libGIF.dylib.json 10.15.7_19H15_libJP2.dylib.json 10.15.7_19H15_libJPEG.dylib.json 10.15.7_19H15_libPng.dylib.json 10.15.7_19H15_libTIFF.dylib.json 10.15.7_19H15_libRadiance.dylib.json 10.15.7_19H15_CoreImage.json 

# audio
python merge_json.py ../workdir/ida_cov_audio.json 10.15.7_19H15_CoreFoundation.json 10.15.7_19H15_libvDSP.dylib.json 10.15.7_19H15_AudioCodecs.json 10.15.7_19H15_libAudioToolboxUtility.dylib.json 10.15.7_19H15_AudioToolboxCore.json

# rtf
python merge_json.py ../workdir/ida_cov_rtf.json 10.15.7_19H15_CoreText.json 10.15.7_19H15_CoreFoundation.json

# cgpdf
python merge_json.py ../workdir/ida_cov_cgpdf.json 10.15.7_19H15_CoreGraphics.json 10.15.7_19H15_CoreFoundation.json

