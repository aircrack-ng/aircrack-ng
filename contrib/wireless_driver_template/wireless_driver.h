/*
 * Wireless Card Driver DLL Header
 * 
 * This header defines the interface for the wireless card driver DLL.
 * It provides function declarations and constants for communicating with
 * a Windows wireless adapter.
 *
 * Copyright (C) 2024 Aircrack-ng Contributors
 */

#ifndef WIRELESS_DRIVER_H
#define WIRELESS_DRIVER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DLL export macro */
#ifdef WIRELESS_DRIVER_EXPORTS
#define WIRELESS_DRIVER_API __declspec(dllexport)
#else
#define WIRELESS_DRIVER_API __declspec(dllimport)
#endif

/* Driver capabilities bitmask */
typedef enum {
    WIRELESS_CAP_NONE = 0x00,
    WIRELESS_CAP_MONITOR_MODE = 0x01,
    WIRELESS_CAP_FRAME_INJECTION = 0x02,
    WIRELESS_CAP_CHANNEL_HOPPING = 0x04,
    WIRELESS_CAP_MAC_SPOOFING = 0x08,
    WIRELESS_CAP_FCS_STRIP = 0x10,
    WIRELESS_CAP_RTS_CTS = 0x20,
    WIRELESS_CAP_SHORT_PREAMBLE = 0x40,
} wireless_capabilities_t;

/* Frame information structure */
typedef struct {
    unsigned int timestamp;
    unsigned char signal_strength;
    unsigned char noise_level;
    unsigned char rate;
    unsigned short flags;
    unsigned short channel;
} wireless_frame_info_t;

/*
 * Initialize wireless driver
 * 
 * Parameters:
 *   device_name - Wide character string containing the device path or name
 *                (e.g., "\\\\.\\{GUID}" for a specific adapter)
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_init(const wchar_t *device_name);

/*
 * Close wireless driver and release resources
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_close(void);

/*
 * Enable or disable monitor mode
 * 
 * In monitor mode, the adapter receives all 802.11 frames
 * on the current channel without association.
 * 
 * Parameters:
 *   enable - TRUE to enable monitor mode, FALSE to disable
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_set_monitor_mode(BOOL enable);

/*
 * Set the wireless channel to monitor
 * 
 * Parameters:
 *   channel - Channel number (1-13 for 2.4 GHz, 36+ for 5 GHz)
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_set_channel(int channel);

/*
 * Get the current channel
 * 
 * Returns:
 *   Current channel number
 */
WIRELESS_DRIVER_API int wireless_driver_get_channel(void);

/*
 * Capture a raw wireless frame
 * 
 * Parameters:
 *   buffer - Pointer to buffer to receive frame data
 *   buffer_size - Size of the buffer in bytes
 *   timeout_ms - Timeout in milliseconds (0 = non-blocking)
 * 
 * Returns:
 *   Number of bytes read (0 if no data available)
 *   -1 on error
 */
WIRELESS_DRIVER_API int wireless_driver_capture_frame(unsigned char *buffer, int buffer_size, int timeout_ms);

/*
 * Send a raw wireless frame
 * 
 * Parameters:
 *   frame - Pointer to frame data to send
 *   frame_size - Size of the frame in bytes
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_send_frame(const unsigned char *frame, int frame_size);

/*
 * Get the wireless adapter MAC address
 * 
 * Parameters:
 *   mac_address - Pointer to 6-byte buffer to receive MAC address
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_get_mac_address(unsigned char *mac_address);

/*
 * Set the wireless adapter MAC address (spoofing)
 * 
 * Parameters:
 *   mac_address - Pointer to 6-byte MAC address
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_set_mac_address(const unsigned char *mac_address);

/*
 * Get driver version information
 * 
 * Parameters:
 *   version_buffer - Pointer to buffer for version string
 *   buffer_size - Size of the buffer
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_get_version(char *version_buffer, int buffer_size);

/*
 * Get driver capabilities
 * 
 * Returns:
 *   Bitmask of supported capabilities (wireless_capabilities_t)
 */
WIRELESS_DRIVER_API int wireless_driver_get_capabilities(void);

/*
 * Reset the wireless adapter to default state
 * 
 * Returns:
 *   0 on success
 *   -1 on failure
 */
WIRELESS_DRIVER_API int wireless_driver_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* WIRELESS_DRIVER_H */
