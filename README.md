# APK Analysis Script

This script automates the process of analyzing APK files to identify encryption usage and analyze native libraries. It follows these steps:

1. Download the APK or clone the git repository.
2. Decompile the APK.
3. Search for encryption keywords in decompiled Java files.
4. Search for encryption terms in the decompiled native libraries files (.so).
5. Install the APK on a connected mobile device.
6. Analyze functions based on search keys using radare2.
7. Find NDK functions using readelf.
8. Uninstall the APK from the device.

## Prerequisites

- **adb**: Install with `apt install adb`.
- **apktool**: Install with `apt install apktool`.
- **radare2**: Install with `apt install radare2`.

## Usage

```bash
./analyze.sh <apk_file>
