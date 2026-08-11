# Wireless Driver DLL - Developer Implementation Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Device Discovery](#device-discovery)
3. [IOCTL Implementation](#ioctl-implementation)
4. [Frame Operations](#frame-operations)
5. [Testing Strategy](#testing-strategy)
6. [Debugging](#debugging)

## Getting Started

This guide walks you through implementing a working wireless driver DLL for your specific hardware.

### Step 1: Identify Your Hardware

First, determine what wireless adapter(s) you want to support:

```c
// Use Device Manager to find your adapter's device GUID
// Or enumerate adapters programmatically:

#include <setupapi.h>
#include <devguid.h>

HDEVINFO hDevInfo = SetupDiGetClassDevs(
    &GUID_DEVCLASS_NET,
    NULL, NULL,
    DIGCF_PRESENT);

SP_DEVINFO_DATA devInfoData;
devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++)
{
    WCHAR friendlyName[256];
    DWORD dataSize = sizeof(friendlyName);
    
    SetupDiGetDeviceRegistryProperty(
        hDevInfo,
        &devInfoData,
        SPDRP_FRIENDLYNAME,
        NULL,
        (PBYTE)friendlyName,
        dataSize,
        &dataSize);
    
    wprintf(L"Found: %ls\n", friendlyName);
}
```

### Step 2: Create Device Handle

Once you've identified your device:

```c
// Method 1: Using device GUID from Device Manager
// Example: {12345678-1234-1234-1234-123456789012}
const wchar_t *device_path = L"\\\\.\\{YOUR-GUID-HERE}";

HANDLE hDevice = CreateFileW(
    device_path,
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
    NULL);

if (hDevice == INVALID_HANDLE_VALUE)
{
    DWORD error = GetLastError();
    wprintf(L"Failed to open device: %ld\n", error);
    return -1;
}
```

### Step 3: Define IOCTLs

Create custom IOCTLs for your device driver:

```c
#include <winioctl.h>

// IOCTL format: CTL_CODE(DeviceType, Function, TransferMethod, RequiredAccess)
#define FILE_DEVICE_WIRELESS_ADAPTER 0x8001

#define IOCTL_WIRELESS_ENABLE_MONITOR \
    CTL_CODE(FILE_DEVICE_WIRELESS_ADAPTER, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WIRELESS_SET_CHANNEL \
    CTL_CODE(FILE_DEVICE_WIRELESS_ADAPTER, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WIRELESS_GET_CHANNEL \
    CTL_CODE(FILE_DEVICE_WIRELESS_ADAPTER, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WIRELESS_CAPTURE_FRAME \
    CTL_CODE(FILE_DEVICE_WIRELESS_ADAPTER, 0x804, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_WIRELESS_SEND_FRAME \
    CTL_CODE(FILE_DEVICE_WIRELESS_ADAPTER, 0x805, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
```

## Device Discovery

### Enumerating Wireless Adapters

```c
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int enumerate_wireless_adapters(void)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    DWORD ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
    {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return -1;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return -1;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
    {
        pAdapter = pAdapterInfo;
        int index = 0;
        while (pAdapter)
        {
            printf("Adapter %d:\n", index);
            printf("  Name: %s\n", pAdapter->AdapterName);
            printf("  Description: %s\n", pAdapter->Description);
            printf("  MAC Address: ");
            for (int i = 0; i < pAdapter->AddressLength; i++)
            {
                if (i > 0) printf("-");
                printf("%02x", pAdapter->Address[i]);
            }
            printf("\n");
            pAdapter = pAdapter->Next;
            index++;
        }
    }
    else
    {
        printf("GetAdaptersInfo failed: %ld\n", dwRetVal);
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}
```

## IOCTL Implementation

### Pattern 1: Simple Control Command

```c
int wireless_driver_set_monitor_mode(BOOL enable)
{
    if (!g_driver_state.initialized)
    {
        fprintf(stderr, "Driver not initialized\n");
        return -1;
    }

    DWORD bytes_returned;
    BOOL result = DeviceIoControl(
        g_driver_state.device_handle,
        IOCTL_WIRELESS_ENABLE_MONITOR,
        &enable,                          // Input buffer
        sizeof(enable),                   // Input buffer size
        NULL,                             // Output buffer
        0,                                // Output buffer size
        &bytes_returned,                  // Bytes returned
        NULL);                            // Synchronous

    if (!result)
    {
        fprintf(stderr, "IOCTL failed: %ld\n", GetLastError());
        return -1;
    }

    g_driver_state.monitor_mode = enable;
    return 0;
}
```

### Pattern 2: Command with Output

```c
int wireless_driver_get_channel(void)
{
    if (!g_driver_state.initialized)
    {
        return -1;
    }

    DWORD bytes_returned;
    int channel = 0;
    
    BOOL result = DeviceIoControl(
        g_driver_state.device_handle,
        IOCTL_WIRELESS_GET_CHANNEL,
        NULL,                             // No input
        0,
        &channel,                         // Output buffer
        sizeof(channel),                  // Output size
        &bytes_returned,                  // Bytes returned
        NULL);                            // Synchronous

    if (!result)
    {
        fprintf(stderr, "IOCTL failed: %ld\n", GetLastError());
        return -1;
    }

    return channel;
}
```

### Pattern 3: Asynchronous I/O for Frame Capture

```c
int wireless_driver_capture_frame(unsigned char *buffer, int buffer_size, int timeout_ms)
{
    if (!g_driver_state.initialized || !buffer || buffer_size <= 0)
    {
        return -1;
    }

    // Create event for async I/O
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        fprintf(stderr, "Failed to create event: %ld\n", GetLastError());
        return -1;
    }

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = hEvent;

    DWORD bytes_read = 0;
    BOOL result = DeviceIoControl(
        g_driver_state.device_handle,
        IOCTL_WIRELESS_CAPTURE_FRAME,
        NULL,                             // No input
        0,
        buffer,                           // Output buffer for frame
        buffer_size,
        &bytes_read,
        &overlapped);                     // Async I/O

    if (!result)
    {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING)
        {
            // Wait for operation to complete
            DWORD wait_result = WaitForSingleObject(hEvent, timeout_ms);
            
            if (wait_result == WAIT_TIMEOUT)
            {
                CancelIo(g_driver_state.device_handle);
                CloseHandle(hEvent);
                return 0;  // No data available
            }
            
            if (wait_result != WAIT_OBJECT_0)
            {
                fprintf(stderr, "Wait failed: %ld\n", GetLastError());
                CloseHandle(hEvent);
                return -1;
            }

            // Get actual bytes transferred
            if (!GetOverlappedResult(g_driver_state.device_handle, 
                                     &overlapped, &bytes_read, FALSE))
            {
                fprintf(stderr, "GetOverlappedResult failed: %ld\n", GetLastError());
                CloseHandle(hEvent);
                return -1;
            }
        }
        else
        {
            fprintf(stderr, "IOCTL failed: %ld\n", error);
            CloseHandle(hEvent);
            return -1;
        }
    }

    CloseHandle(hEvent);
    return (int)bytes_read;
}
```

## Frame Operations

### Frame Structure (802.11)

```c
// Basic 802.11 frame header
typedef struct {
    // Frame control (2 bytes)
    unsigned char protocol_version:2;
    unsigned char type:2;
    unsigned char subtype:4;
    unsigned char to_ds:1;
    unsigned char from_ds:1;
    unsigned char more_frag:1;
    unsigned char retry:1;
    unsigned char power_mgmt:1;
    unsigned char more_data:1;
    unsigned char protected_frame:1;
    unsigned char order:1;
    
    unsigned char duration[2];           // Duration/ID (2 bytes)
    unsigned char address1[6];           // Receiver address
    unsigned char address2[6];           // Transmitter address
    unsigned char address3[6];           // BSSID or destination
    
    unsigned char sequence_control[2];   // Sequence/Fragment
    // Optional: address4[6] if to_ds and from_ds both set
    // Optional: QoS control (2 bytes) if QoS frame
    // Optional: HT control (4 bytes) if Order bit set
} wireless_frame_header_t;
```

### Parsing Captured Frames

```c
void parse_frame_header(const unsigned char *frame, int length)
{
    if (length < 24)  // Minimum frame size
    {
        printf("Frame too small: %d bytes\n", length);
        return;
    }

    const wireless_frame_header_t *hdr = (wireless_frame_header_t *)frame;
    
    printf("Frame Info:\n");
    printf("  Type: %d, Subtype: %d\n", hdr->type, hdr->subtype);
    printf("  To DS: %d, From DS: %d\n", hdr->to_ds, hdr->from_ds);
    printf("  Duration: %d\n", hdr->duration[0] | (hdr->duration[1] << 8));
    printf("  Dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->address1[0], hdr->address1[1], hdr->address1[2],
           hdr->address1[3], hdr->address1[4], hdr->address1[5]);
    printf("  Source: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->address2[0], hdr->address2[1], hdr->address2[2],
           hdr->address2[3], hdr->address2[4], hdr->address2[5]);
    printf("  BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->address3[0], hdr->address3[1], hdr->address3[2],
           hdr->address3[3], hdr->address3[4], hdr->address3[5]);
}
```

### Injecting Custom Frames

```c
// Example: Create a beacon frame
int send_beacon_frame(const unsigned char *bssid, const char *ssid)
{
    unsigned char frame[256];
    unsigned char *ptr = frame;

    // Frame control: Management frame, subtype 8 (Beacon)
    *ptr++ = 0x80;  // Protocol version 0, Type 0 (Mgmt), Subtype 8
    *ptr++ = 0x00;

    // Duration
    *ptr++ = 0x00;
    *ptr++ = 0x00;

    // Destination (broadcast)
    memset(ptr, 0xff, 6);
    ptr += 6;

    // Source (our MAC)
    unsigned char our_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    memcpy(ptr, our_mac, 6);
    ptr += 6;

    // BSSID
    memcpy(ptr, bssid, 6);
    ptr += 6;

    // Sequence control
    *ptr++ = 0x00;
    *ptr++ = 0x00;

    // Calculate frame length
    int frame_length = (int)(ptr - frame);

    // Send the frame
    return wireless_driver_send_frame(frame, frame_length);
}
```

## Testing Strategy

### Unit Testing Pattern

```c
typedef struct {
    const char *name;
    int (*test_func)(void);
} test_case_t;

test_case_t test_cases[] = {
    {"Monitor Mode", test_monitor_mode},
    {"Channel Setting", test_channel_setting},
    {"Frame Capture", test_frame_capture},
    {"Frame Injection", test_frame_injection},
    {NULL, NULL}
};

int run_all_tests(void)
{
    int passed = 0, failed = 0;
    
    for (int i = 0; test_cases[i].name != NULL; i++)
    {
        printf("Running: %s... ", test_cases[i].name);
        int result = test_cases[i].test_func();
        if (result == 0)
        {
            printf("PASSED\n");
            passed++;
        }
        else
        {
            printf("FAILED\n");
            failed++;
        }
    }
    
    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed;
}
```

## Debugging

### Enable Debug Output

```c
// Add to wireless_driver.c
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) \
    do { \
        fprintf(stderr, "[WIRELESS] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while(0)
#else
#define DEBUG_PRINT(fmt, ...) do { } while(0)
#endif
```

### Windows Debugger Integration

```c
// Use DebugBreak for breakpoints in debugger
if (error_condition)
{
    DEBUG_PRINT("Error condition detected");
    #ifdef DEBUG
    DebugBreak();
    #endif
}
```

### Common Errors

| Error Code | Meaning | Solution |
|-----------|---------|----------|
| ERROR_FILE_NOT_FOUND (2) | Device not found | Check device GUID |
| ERROR_ACCESS_DENIED (5) | Insufficient privileges | Run as Administrator |
| ERROR_NOT_ENOUGH_MEMORY (8) | Out of memory | Reduce buffer sizes |
| ERROR_INVALID_HANDLE (6) | Invalid device handle | Check handle is open |
| ERROR_IO_PENDING (997) | Async I/O in progress | Wait for completion |

### Performance Considerations

- Use overlapped I/O for frame capture
- Pre-allocate buffers to avoid allocation in hot paths
- Use channel hopping in separate thread
- Batch frame transmission when possible

---

For more information, refer to:
- [Windows Device I/O Control](https://docs.microsoft.com/en-us/windows/win32/fileio/device-input-and-output-control-ioctl-)
- [NDIS Drivers](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/)
- [802.11 Frame Format](https://en.wikipedia.org/wiki/IEEE_802.11#Frame_format)
