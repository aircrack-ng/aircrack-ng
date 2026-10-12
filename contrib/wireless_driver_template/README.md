# Wireless Card Driver DLL Template for Aircrack-ng on Windows

This is a **template and example implementation** for developing a Windows wireless card driver DLL that integrates with aircrack-ng. It provides a framework for communicating with wireless adapters on Windows systems.

## Overview

Aircrack-ng on Windows requires custom DLL drivers to interface with wireless cards because Windows doesn't provide direct access to raw 802.11 frames like Linux does. This template provides:

- **Header file** (`wireless_driver.h`) defining the DLL interface
- **Implementation template** (`wireless_driver.c`) with function stubs
- **Build files** for both CMake and Visual Studio

## Features

The template DLL implements the following functions:

### Core Operations
- `wireless_driver_init()` - Initialize and open the wireless device
- `wireless_driver_close()` - Close the device and release resources
- `wireless_driver_reset()` - Reset the adapter to default state

### Monitor Mode
- `wireless_driver_set_monitor_mode()` - Enable/disable raw frame capture
- `wireless_driver_get_channel()` - Get current channel
- `wireless_driver_set_channel()` - Switch to a specific channel

### Frame Operations
- `wireless_driver_capture_frame()` - Read raw 802.11 frames
- `wireless_driver_send_frame()` - Inject raw 802.11 frames

### Adapter Management
- `wireless_driver_get_mac_address()` - Read MAC address
- `wireless_driver_set_mac_address()` - Spoof MAC address
- `wireless_driver_get_version()` - Get driver version
- `wireless_driver_get_capabilities()` - Query supported features

## Building the DLL

### Requirements

- **Windows Vista or later** (for WinPcap/Npcap compatibility)
- **Visual Studio 2019+** or **MinGW-w64**
- **CMake 3.10+** (optional, for CMake builds)
- **Windows SDK** with device driver headers

### Option 1: Visual Studio Build

1. Open `wireless_driver.vcxproj` in Visual Studio
2. Select your configuration (Debug/Release) and platform (Win32/x64)
3. Build the project
4. Output DLL will be in `build\<Configuration>\<Platform>\wireless_driver.dll`

```batch
# Command-line build
msbuild wireless_driver.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Option 2: CMake Build

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Option 3: MinGW-w64 Build

```bash
gcc -shared -fPIC wireless_driver.c -o wireless_driver.dll \
    -lkernel32 -luser32 -lsetupapi -liphlpapi -lws2_32 -ladvapi32 \
    -Wall -Wextra -O2
```

## Development Guide

### 1. Understanding the Template

The template provides stub implementations for all required functions. Each function includes:
- Parameter validation
- Error handling
- Comments explaining what needs to be implemented
- Example IOCTL patterns

### 2. Implementing for Your Hardware

To adapt this template for your specific wireless card:

#### Step 1: Identify Your Device
```c
// Example for Intel WiFi 6 adapter
// You need to find the correct device GUID
HKEY hKey;
RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
    L"SYSTEM\\CurrentControlSet\\Services\\Ndisuio\\Parameters\\Export",
    0, KEY_READ, &hKey);
// Enumerate adapters to find your device
```

#### Step 2: Open Device Handle
```c
// Replace with your actual device path
HANDLE hDevice = CreateFileW(
    L"\\\\.\\{YOUR-DEVICE-GUID}",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
```

#### Step 3: Implement IOCTLs
```c
// Define custom IOCTLs for your driver
#define IOCTL_WIRELESS_SET_CHANNEL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Use DeviceIoControl to communicate
DeviceIoControl(hDevice, IOCTL_WIRELESS_SET_CHANNEL, 
    &channel, sizeof(channel), NULL, 0, &bytes_returned, NULL);
```

### 3. Common Implementation Patterns

#### Pattern 1: Setting Monitor Mode
```c
int wireless_driver_set_monitor_mode(BOOL enable)
{
    // 1. Check driver initialized
    // 2. Send IOCTL to driver with enable flag
    // 3. Disable association/authentication
    // 4. Set frame filtering to capture all frames
    // 5. Return 0 on success
}
```

#### Pattern 2: Capturing Frames
```c
int wireless_driver_capture_frame(unsigned char *buffer, int size, int timeout)
{
    // 1. Create overlapped event for async I/O
    // 2. Call ReadFile with the device handle
    // 3. Wait for completion with timeout
    // 4. Return number of bytes read
    // 5. Close event handle
}
```

#### Pattern 3: Channel Hopping
```c
int wireless_driver_set_channel(int channel)
{
    // 1. Validate channel (1-13 for 2.4GHz, 36+ for 5GHz)
    // 2. Send channel change IOCTL
    // 3. Wait for operation to complete
    // 4. Verify channel was set
    // 5. Update internal state
}
```

### 4. Linking with Aircrack-ng

Once your DLL is built, place it in the directory where aircrack-ng binaries are located:
```
C:\Program Files\aircrack-ng\
└── wireless_driver.dll
```

Aircrack-ng will dynamically load your DLL using the loader system in:
`lib/libac/support/crypto_engine_loader.c`

### 5. Testing Your Implementation

Create a simple test program:
```c
#include "wireless_driver.h"
#include <stdio.h>

int main()
{
    // Test initialization
    if (wireless_driver_init(L"\\\\.\\YourDeviceGUID") != 0)
        return -1;
    
    // Test monitor mode
    wireless_driver_set_monitor_mode(TRUE);
    
    // Test channel setting
    wireless_driver_set_channel(6);
    
    // Test frame capture
    unsigned char buffer[4096];
    int bytes = wireless_driver_capture_frame(buffer, sizeof(buffer), 1000);
    printf("Captured %d bytes\n", bytes);
    
    // Cleanup
    wireless_driver_close();
    return 0;
}
```

## Important Notes

### Security Considerations
- **Administrator privileges** are required to access raw wireless frames on Windows
- **Signature verification** may be required depending on Windows version
- **Kernel mode drivers** may need to be installed for full functionality

### Windows Versions
- **Windows 10/11**: Use modern NDIS 6.x APIs
- **Windows Vista/7/8**: May require compatibility adjustments
- **Windows Server**: May have additional restrictions

### API References

- [Windows Device I/O Control (IOCTL)](https://docs.microsoft.com/en-us/windows/win32/fileio/device-input-and-output-control-ioctl-)
- [NDIS Drivers](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-drivers)
- [Device Driver Interface (DDI)](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-driver-kit)
- [WinPcap/Npcap API](https://www.tcpdump.org/papers/sniffing-faq.html)

## Export Functions

The DLL exports the following functions that can be loaded dynamically:

```c
// All functions use __declspec(dllexport) and are decorated with WIRELESS_DRIVER_API
int wireless_driver_init(const wchar_t *device_name);
int wireless_driver_close(void);
int wireless_driver_set_monitor_mode(BOOL enable);
int wireless_driver_set_channel(int channel);
int wireless_driver_get_channel(void);
int wireless_driver_capture_frame(unsigned char *buffer, int buffer_size, int timeout_ms);
int wireless_driver_send_frame(const unsigned char *frame, int frame_size);
int wireless_driver_get_mac_address(unsigned char *mac_address);
int wireless_driver_set_mac_address(const unsigned char *mac_address);
int wireless_driver_get_version(char *version_buffer, int buffer_size);
int wireless_driver_get_capabilities(void);
int wireless_driver_reset(void);
```

## Troubleshooting

### "Cannot load DLL"
- Check DLL is in the correct directory
- Verify dependencies (setupapi.dll, iphlpapi.dll, etc.) are available
- Use Dependency Walker to check missing dependencies

### "No such device"
- Verify your device path/GUID
- Check device is installed and enabled
- Use Device Manager to find correct device GUID

### "Access Denied"
- Run with administrator privileges
- Check driver permissions
- May need kernel mode driver for full access

### "No frames captured"
- Verify monitor mode is enabled
- Check correct channel is set
- Verify adapter supports frame injection
- Check for packet filtering rules

## Example Implementations

For reference implementations, check:
- `lib/osdep/cygwin.c` - Cygwin Windows implementation
- `contrib/commview/commview.c` - ComView capture card driver
- `contrib/airpcap/airpcap.c` - AirPcap adapter driver

## License

This template is provided under the GNU General Public License v2.0 or later, same as aircrack-ng.

See LICENSE for details.

## Support

- **For aircrack-ng**: https://github.com/aircrack-ng/aircrack-ng
- **Windows Driver Development**: https://docs.microsoft.com/en-us/windows-hardware/drivers/
- **Community Support**: aircrack-ng forums and GitHub issues

## Contributing

If you develop a working driver for a specific wireless card, consider contributing it back to the aircrack-ng project:

1. Fork the repository
2. Add your driver DLL to `contrib/`
3. Create comprehensive documentation
4. Submit a pull request
5. Include test results and supported hardware

## Disclaimer

This is a **template only**. You are responsible for:
- Understanding your specific wireless card's driver interface
- Implementing device-specific functionality
- Testing on your hardware
- Compliance with local wireless laws and regulations
- Proper licensing of any code you use

The aircrack-ng project provides no warranty for custom drivers developed from this template.
