# Quick Start Guide - Building the Wireless Driver DLL

## Prerequisites
- Windows 7 or later
- Visual Studio 2019+ OR MinGW-w64
- Windows SDK
- CMake 3.10+ (optional)

## Quick Build - Visual Studio

```batch
# Navigate to the template directory
cd contrib\wireless_driver_template

# Build with Visual Studio (x64 Release)
msbuild wireless_driver.vcxproj /p:Configuration=Release /p:Platform=x64 /m

# Output: build\Release\x64\wireless_driver.dll
```

## Quick Build - CMake

```bash
cd contrib/wireless_driver_template
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
# Output: build/bin/wireless_driver.dll
```

## Quick Build - MinGW

```bash
cd contrib/wireless_driver_template
gcc -shared -fPIC -o wireless_driver.dll wireless_driver.c ^
    -lkernel32 -luser32 -lsetupapi -liphlpapi -lws2_32 -ladvapi32 ^
    -Wall -Wextra -O2
```

## Next Steps

1. **Customize for your hardware:**
   - Modify `wireless_driver_init()` to open your specific device
   - Implement device IOCTLs in stub functions
   - Test each function individually

2. **Test the DLL:**
   - Create a test program that loads the DLL
   - Verify each exported function works
   - Check frame capture functionality

3. **Integrate with Aircrack-ng:**
   - Copy DLL to aircrack-ng binary directory
   - Run aircrack-ng tools with your adapter

4. **Refer to README.md for:**
   - Detailed implementation guide
   - API reference
   - Common patterns
   - Troubleshooting

## File Structure

```
contrib/wireless_driver_template/
├── README.md                    # Full documentation
├── QUICK_START.md              # This file
├── wireless_driver.h           # Header with API definitions
├── wireless_driver.c           # Implementation template
├── CMakeLists.txt             # CMake build configuration
├── wireless_driver.vcxproj    # Visual Studio project
└── Makefile.win               # GNU Make for Windows
```

## Common Issues

| Issue | Solution |
|-------|----------|
| "Cannot open device" | Check device GUID in wireless_driver_init() |
| "Access denied" | Run as Administrator |
| "DLL not found" | Copy to aircrack-ng binary directory |
| "Missing dependencies" | Install Windows SDK |

For more help, see README.md
