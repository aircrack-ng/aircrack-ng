/*
 * Copyright (c) 2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "nexmon.h"

static char * get_text_file_content(const char * filename);
static int exec_get_output(char ** output, char * const cmd_args[]);

int get_nexutil_mon_value(const char * iface)
{
    char * str = NULL;
    char * cmd_args[5] = { "nexutil", "-m", "-I", (char*)iface, NULL };
    int ret = exec_get_output(&str, cmd_args);
    // Should return something like: "monitor: 2"
    if (str == NULL) {
        return -1;
    }
    size_t len = strlen(str);
    if (len == 11 && str[10] == '\n') {
        str[10] = 0;
        --len;
    }
    if (ret || len != 10 || strncmp(str, "monitor: ", 9)) {
        free(str);
        return -1;
    }

    // Return the value
    ret = (str[9] - '0');
    free(str);
    if (ret < NEXUTIL_MIN_RET_VALUE || ret > NEXUTIL_MAX_RET_VALUE) {
        return -1;
    }
    
    return ret;
}

int is_nexmon(const char * iface)
{
    /*
     * First we need to check for nexutil presence.
     * Looking at the BUS the device is on (SDIO), finding the
     * vendor Broadcom (0x02d0) and then checking device ID
     * and comparing to the available device list that can do
     * monitor mode: https://github.com/seemoo-lab/nexmon/
     * (Supported devices) and matching with Linux-wireless:
     * https://wireless.wiki.kernel.org/en/users/Drivers/brcm80211
     * (SDIO).
     * And finally, we can check if nexutil is present
     * 
     * Relying on nexutil only is not a good idea because it can
     * set the monitor flags on other interfaces and then the interface
     * has to be unplugged or changed back to managed mode with iw
     * tools
     */

    const char * sys_base_format = "/sys/class/net/%s/device/%s";
    char * sys, *tmp;
    // Interface name starts with wlan
    if (iface == NULL || strlen(iface) >= IFNAMSIZ || strncmp(iface, "wlan", 4)) {
        return 0;
    }
    
    sys = (char *)calloc(1, PATH_MAX);
    if (sys == NULL) {
        return -1;
    }
    
    // Check if it's on SDIO
    sprintf(sys, sys_base_format, iface, "modalias");
    tmp = get_text_file_content(sys);
    if (tmp == NULL || strncmp(tmp, "sdio", 4)) {
        if (tmp) {
            free(tmp);
        }
        free(sys);
        return -1;
    }
    free(tmp);
    memset(sys, 0, PATH_MAX);

    // Check if it's Broadcom
    sprintf(sys, sys_base_format, iface, "vendor");
    tmp = get_text_file_content(sys);
    if (tmp == NULL || strncmp(tmp, "0x02d0", 6)) {
        if (tmp) {
            free(tmp);
        }
        free(sys);
        return -1;
    }
    free(tmp);
    memset(sys, 0, PATH_MAX);

    // Check if it's one of the devices supported
    sprintf(sys, sys_base_format, iface, "device");
    tmp = get_text_file_content(sys);
    free(sys);
    if (tmp == NULL || ! (strncmp(tmp, "0x4330", 6) == 0 || strncmp(tmp, "0x4335", 6) == 0 
        || strncmp(tmp, "0xa9a6", 6) == 0 || strncmp(tmp, "0x4345", 6) == 0)) {
        if (tmp) {
            free(tmp);
        }
        return -1;
    }
    free(tmp);

    /*
    // Check if nexutil is installed
    char * cmd_args[3] = { "which", "nexutil", NULL };
    if (exec_get_output(NULL, cmd_args) != 0) {
        // if return is not 0, then there won't be any output
        return 0;
    }
    */

    // Get current monitor mode value from nexutil
    return get_nexutil_mon_value(iface);
}

static char * get_text_file_content(const char * filename)
{
    if (filename == NULL || strlen(filename) == 0) {
        return NULL;
    }

    FILE * f = fopen(filename, "r");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    if (length < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    char * buffer = (char *)calloc(1, length + 1);
    if (buffer == NULL || length == 0) {
        fclose(f);
        return buffer;
    }

    // There isn't much we can do if it fails or reads part of it
    if (fread(buffer, 1, length, f) <= 0) {
        free(buffer);
        buffer = NULL;
    }
    fclose(f);
    return buffer;
}

static int exec_get_output(char ** output, char * const cmd_args[])
{
    int link[2];
    pid_t pid;
    char buffer[256];
    char * rea = NULL; // For reallocation
    char * tmp = NULL; // temporary buffer for the whole output

    if (cmd_args == NULL || cmd_args[0] == NULL || pipe(link) == -1 || (pid = fork()) == -1) {
        return -1;
    }

    if (pid == 0) {
        dup2 (link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        execvp(cmd_args[0], cmd_args);
        exit(1);
    }

    close(link[1]);
    if (output) {
        ssize_t count = 0;
        size_t total = 0;
        memset(buffer, 0, sizeof(buffer));

        // Get output and append to buffer
        while ( (count = read(link[0], buffer, sizeof(buffer))) > 0 ) {
            rea = (char *)realloc(tmp, total + count + 1);
            if (rea) {
                tmp = rea;
                memcpy(tmp + total, buffer, count);
                total += count;
                tmp[total] = 0;
            } else {
                break;
            }
            memset(buffer, 0, sizeof(buffer));
        }

        // Give it back to output
        *output = tmp;
    } else {
        close(2);
    }

    // Get return value
    int waitstatus;
    wait(&waitstatus);
    return WEXITSTATUS(waitstatus);
}
