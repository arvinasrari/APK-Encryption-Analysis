# encryption-search

This script automates the process of analyzing APK files to identify encryption usage and analyze native libraries. It follows these steps:

Download the APK or clone the Git repository.
Decompile the APK.
Search for encryption keywords in decompiled Java files.
Search for encryption terms in the decompiled native libraries files (.so).
Install the APK on a connected mobile device.
Analyze functions based on search keys using radare2.
Find NDK functions using readelf.
Uninstall the APK from the device.
Prerequisites
adb: Install with apt install adb.
apktool: Install with apt install apktool.
radare2: Install with apt install radare2.
