/*
 * Sample test program for Wireless Driver DLL
 * 
 * This program demonstrates how to use the wireless_driver DLL functions.
 * Compile with: gcc test_driver.c -o test_driver.exe -L. -lwireless_driver
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "wireless_driver.h"

/* Helper function to print hex data */
void print_hex(const unsigned char *data, int length)
{
    for (int i = 0; i < length && i < 16; i++)
    {
        printf("%02x ", data[i]);
    }
    if (length > 16)
        printf("... (%d bytes total)", length);
    printf("\n");
}

/* Test 1: Basic initialization */
int test_init_close(void)
{
    printf("\n--- Test 1: Initialization and Cleanup ---\n");
    
    // Note: Replace with your actual device GUID or name
    const wchar_t *device = L"\\\\.\\{YOUR-DEVICE-GUID}";
    
    printf("Initializing with device: ");
    wprintf(L"%ls\n", device);
    
    int result = wireless_driver_init(device);
    if (result != 0)
    {
        printf("FAILED: Could not initialize driver\n");
        printf("Note: Update the device GUID in the source code\n");
        return -1;
    }
    
    printf("SUCCESS: Driver initialized\n");
    
    // Close the driver
    result = wireless_driver_close();
    if (result != 0)
    {
        printf("FAILED: Could not close driver\n");
        return -1;
    }
    
    printf("SUCCESS: Driver closed\n");
    return 0;
}

/* Test 2: Get driver version */
int test_get_version(void)
{
    printf("\n--- Test 2: Get Driver Version ---\n");
    
    char version[256];
    int result = wireless_driver_get_version(version, sizeof(version));
    
    if (result != 0)
    {
        printf("FAILED: Could not get version\n");
        return -1;
    }
    
    printf("SUCCESS: Driver version: %s\n", version);
    return 0;
}

/* Test 3: Get capabilities */
int test_get_capabilities(void)
{
    printf("\n--- Test 3: Get Driver Capabilities ---\n");
    
    int caps = wireless_driver_get_capabilities();
    printf("Capabilities bitmask: 0x%08x\n", caps);
    
    if (caps & WIRELESS_CAP_MONITOR_MODE)
        printf("  [x] Monitor Mode\n");
    if (caps & WIRELESS_CAP_FRAME_INJECTION)
        printf("  [x] Frame Injection\n");
    if (caps & WIRELESS_CAP_CHANNEL_HOPPING)
        printf("  [x] Channel Hopping\n");
    if (caps & WIRELESS_CAP_MAC_SPOOFING)
        printf("  [x] MAC Address Spoofing\n");
    if (caps & WIRELESS_CAP_FCS_STRIP)
        printf("  [x] FCS Stripping\n");
    
    return 0;
}

/* Test 4: Monitor mode */
int test_monitor_mode(void)
{
    printf("\n--- Test 4: Monitor Mode ---\n");
    
    printf("Enabling monitor mode...\n");
    int result = wireless_driver_set_monitor_mode(TRUE);
    if (result != 0)
    {
        printf("FAILED: Could not enable monitor mode\n");
        return -1;
    }
    printf("SUCCESS: Monitor mode enabled\n");
    
    printf("Disabling monitor mode...\n");
    result = wireless_driver_set_monitor_mode(FALSE);
    if (result != 0)
    {
        printf("FAILED: Could not disable monitor mode\n");
        return -1;
    }
    printf("SUCCESS: Monitor mode disabled\n");
    
    return 0;
}

/* Test 5: Channel setting */
int test_channel_setting(void)
{
    printf("\n--- Test 5: Channel Setting ---\n");
    
    int channels[] = {1, 6, 11, 36, 40, 44, 48};
    int num_channels = sizeof(channels) / sizeof(channels[0]);
    
    for (int i = 0; i < num_channels; i++)
    {
        printf("Setting channel to %d...\n", channels[i]);
        int result = wireless_driver_set_channel(channels[i]);
        if (result != 0)
        {
            printf("  FAILED\n");
            continue;
        }
        
        int current = wireless_driver_get_channel();
        printf("  SUCCESS: Current channel is %d\n", current);
    }
    
    return 0;
}

/* Test 6: MAC address operations */
int test_mac_address(void)
{
    printf("\n--- Test 6: MAC Address Operations ---\n");
    
    unsigned char mac_original[6];
    unsigned char mac_spoofed[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    printf("Getting original MAC address...\n");
    int result = wireless_driver_get_mac_address(mac_original);
    if (result != 0)
    {
        printf("FAILED: Could not get MAC address\n");
        return -1;
    }
    printf("SUCCESS: MAC address is: ");
    print_hex(mac_original, 6);
    
    printf("Setting spoofed MAC address...\n");
    result = wireless_driver_set_mac_address(mac_spoofed);
    if (result != 0)
    {
        printf("FAILED: Could not set MAC address\n");
        return -1;
    }
    printf("SUCCESS: MAC address spoofed to: ");
    print_hex(mac_spoofed, 6);
    
    printf("Restoring original MAC address...\n");
    result = wireless_driver_set_mac_address(mac_original);
    if (result != 0)
    {
        printf("FAILED: Could not restore MAC address\n");
        return -1;
    }
    printf("SUCCESS: MAC address restored\n");
    
    return 0;
}

/* Test 7: Frame capture */
int test_frame_capture(void)
{
    printf("\n--- Test 7: Frame Capture ---\n");
    
    unsigned char buffer[4096];
    printf("Attempting to capture frame (timeout=1000ms)...\n");
    
    int bytes = wireless_driver_capture_frame(buffer, sizeof(buffer), 1000);
    
    if (bytes < 0)
    {
        printf("FAILED: Error capturing frame\n");
        return -1;
    }
    
    if (bytes == 0)
    {
        printf("No frame captured within timeout period\n");
        return 0;
    }
    
    printf("SUCCESS: Captured %d bytes\n", bytes);
    printf("Frame header (first 16 bytes): ");
    print_hex(buffer, bytes);
    
    return 0;
}

/* Test 8: Frame injection */
int test_frame_injection(void)
{
    printf("\n--- Test 8: Frame Injection ---\n");
    
    // Create a simple test frame (not a valid 802.11 frame, just for testing)
    unsigned char test_frame[] = {0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    printf("Attempting to send test frame...\n");
    int result = wireless_driver_send_frame(test_frame, sizeof(test_frame));
    
    if (result != 0)
    {
        printf("FAILED: Could not send frame\n");
        return -1;
    }
    
    printf("SUCCESS: Frame sent\n");
    return 0;
}

/* Test 9: Reset */
int test_reset(void)
{
    printf("\n--- Test 9: Driver Reset ---\n");
    
    printf("Resetting driver...\n");
    int result = wireless_driver_reset();
    
    if (result != 0)
    {
        printf("FAILED: Could not reset driver\n");
        return -1;
    }
    
    printf("SUCCESS: Driver reset\n");
    return 0;
}

/* Main function */
int main(int argc, char *argv[])
{
    printf("====================================\n");
    printf("Wireless Driver DLL Test Program\n");
    printf("====================================\n");
    
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;
    
    // Note: Most tests require actual hardware to work properly
    // This sample demonstrates the API usage
    
    // Test version and capabilities (don't require device)
    if (test_get_version() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_get_capabilities() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    // The following tests require an initialized device
    // Uncomment only if you have the correct device GUID set
    
    /*
    if (test_init_close() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_monitor_mode() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_channel_setting() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_mac_address() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_frame_capture() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_frame_injection() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    
    if (test_reset() == 0) passed_tests++; else failed_tests++;
    total_tests++;
    */
    
    printf("\n====================================\n");
    printf("Test Results\n");
    printf("====================================\n");
    printf("Total: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);
    
    if (failed_tests > 0)
    {
        printf("\nNote: Some tests failed. This is expected if:\n");
        printf("  - The device GUID is not configured correctly\n");
        printf("  - No wireless adapter is present\n");
        printf("  - The driver DLL is not fully implemented\n");
        printf("\nUpdate the device GUID in wireless_driver.c and rebuild.\n");
    }
    
    return failed_tests > 0 ? 1 : 0;
}
