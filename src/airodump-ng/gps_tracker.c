#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gps_tracker.h"
#include "aircrack-ng/support/common.h"
#include "battery.h"

#define _GNU_SOURCE
#define _WITH_DPRINTF
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <unistd.h>
#include <sys/time.h>
#include <wait.h>

/* Read at least one full line from the network.
 *
 * Returns the amount of data in the buffer on success, 0 on connection
 * closed, or a negative value on error.
 *
 * If the return value is >0, the buffer contains at least one newline
 * character.  If the return value is <= 0, the contents of the buffer
 * are undefined.
 */
static inline ssize_t
read_line(int sock, char * buffer, size_t pos, size_t size)
{
    ssize_t status = 1;
    if (size < 1 || pos >= size || buffer == NULL || sock < 0)
    {
        return (-1);
    }

    while (strchr_n(buffer, 0x0A, pos) == NULL && status > 0 && pos < size)
    {
        status = recv(sock, buffer + pos, size - pos, 0);
        if (status > 0)
        {
            pos += status;
        }
    }

    if (status <= 0)
    {
        return (status);
    }
    else if (pos == size && strchr_n(buffer, 0x0A, pos) == NULL)
    {
        return (-1);
    }

    return (pos);
}

/* Extract a name:value pair from a null-terminated line of JSON.
 *
 * Returns 1 if the name was found, or 0 otherwise.
 *
 * The string in "value" is null-terminated if the name was found.  If
 * the name was not found, the contents of "value" are undefined.
 */
static int
json_get_value_for_name(const char * buffer, const char * name, char * value)
{
    char * to_find;
    char * cursor;
    size_t to_find_len;
    char * vcursor = value;
    int ret = 0;

    if (buffer == NULL || strlen(buffer) == 0 || name == NULL
        || strlen(name) == 0
        || value == NULL)
    {
        return (0);
    }

    to_find_len = strlen(name) + 3;
    to_find = (char *)malloc(to_find_len);
    ALLEGE(to_find != NULL);
    snprintf(to_find, to_find_len, "\"%s\"", name);
    cursor = strstr(buffer, to_find);
    free(to_find);
    if (cursor != NULL)
    {
        cursor += to_find_len - 1;
        while (*cursor != ':' && *cursor != '\0')
        {
            cursor++;
        }
        if (*cursor != '\0')
        {
            cursor++;
            while (isspace((int)(*cursor)) && *cursor != '\0')
            {
                cursor++;
            }
        }
        if ('\0' == *cursor)
        {
            return (0);
        }

        if ('"' == *cursor)
        {
            /* Quoted string */
            cursor++;
            while (*cursor != '"' && *cursor != '\0')
            {
                if ('\\' == *cursor && '"' == *(cursor + 1))
                {
                    /* Escaped quote */
                    *vcursor = '"';
                    cursor++;
                }
                else
                {
                    *vcursor = *cursor;
                }
                vcursor++;
                cursor++;
            }
            *vcursor = '\0';
            ret = 1;
        }
        else if (strncmp(cursor, "true", 4) == 0)
        {
            /* Boolean */
            strcpy(value, "true");
            ret = 1;
        }
        else if (strncmp(cursor, "false", 5) == 0)
        {
            /* Boolean */
            strcpy(value, "false");
            ret = 1;
        }
        else if ('{' == *cursor || '[' == *cursor)
        {
            /* Object or array.  Too hard to handle and not needed for
             * getting coords from GPSD, so pretend we didn't see anything.
             */
            ret = 0;
        }
        else
        {
            /* Number, supposedly.  Copy as-is. */
            while (*cursor != ',' && *cursor != '}'
                   && !isspace((int)(*cursor)))
            {
                *vcursor = *cursor;
                cursor++;
                vcursor++;
            }
            *vcursor = '\0';
            ret = 1;
        }
    }

    return (ret);
}

static void * gps_tracker_thread(void * arg)
{
    ALLEGE(arg != NULL);

    gps_tracker_context_st * const gps_context = arg;
    /* Pass in as the thread arg? 
     * The 'result' doesn't appear to be used. 
     */
    int gpsd_sock;
    char line[1537]; 
    char buffer[1537]; 
    char data[1537];
    char * temp;
    struct sockaddr_in gpsd_addr;
    int is_json;
    ssize_t pos;
    int gpsd_tried_connection = 0;
    fd_set read_fd;
    struct timeval timeout;

    // In case we GPSd goes down or we lose connection or a fix, we keep trying to connect inside the while loop
    while (*gps_context->do_exit == 0)
    {
        // If our socket connection to GPSD has been attempted and failed wait before trying again - used to prevent locking the CPU on socket retries
        if (gpsd_tried_connection)
        {
            sleep(2);
        }
        gpsd_tried_connection = 1;

        time_t updateTime = time(NULL);

        /* FIXME - Are these memsets necessary? */
        memset(line, 0, sizeof line);
        memset(buffer, 0, sizeof buffer);
        memset(data, 0, sizeof data);

        /* attempt to connect to localhost, port 2947 */
        pos = 0;
        gpsd_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (gpsd_sock < 0)
            continue;

        memset(&gpsd_addr, 0, sizeof gpsd_addr);
        gpsd_addr.sin_family = AF_INET;
        gpsd_addr.sin_port = htons(2947);
        gpsd_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(
                gpsd_sock, (struct sockaddr *)&gpsd_addr, sizeof(gpsd_addr))
            < 0)
            continue;

        // Check if it's GPSd < 2.92 or the new one
        // 2.92+ immediately sends version information
        // < 2.92 requires to send PVTAD command
        FD_ZERO(&read_fd);
        FD_SET(gpsd_sock, &read_fd); // NOLINT(hicpp-signed-bitwise)
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        is_json = select(gpsd_sock + 1, &read_fd, NULL, NULL, &timeout);

        if (is_json > 0)
        {
            /* Probably JSON.  Read the first line and verify it's a version of the
            * protocol we speak. */
            pos = read_line(gpsd_sock, buffer, 0, sizeof(buffer));
            if (pos <= 0)
            {
                continue;
            }

            pos = get_line_from_buffer(buffer, (size_t)pos, line);
            is_json =
                json_get_value_for_name(line, "class", data)
                && strncmp(data, "VERSION", 7) == 0;

            if (is_json)
            {
                /* Verify it's a version of the protocol we speak */
                if (json_get_value_for_name(line, "proto_major", data)
                    && data[0] != '3')
                {
                    /* It's an unknown version of the protocol.  Bail out. */
                    continue;
                }

                // Send ?WATCH={"json":true};
                strcpy(line, "?WATCH={\"json\":true};\n");

                if (send(gpsd_sock, line, strlen(line), 0) != (ssize_t)strlen(line))
                {
                    continue;
                }
            }
        }
        else if (is_json < 0)
        {
            /* An error occurred while we were waiting for data */
            continue;
        }
        /* Else select() returned zero (timeout expired) and we assume we're
        * connected to an old-style gpsd. */

        // Initialisation of all GPS data to 0
        memset(gps_context->gps_loc, 0, sizeof(gps_context->gps_loc));

        /* Inside loop for reading the GPS coordinates/data */
        while (*gps_context->do_exit == 0)
        {
            gpsd_tried_connection = 0; // reset socket connection test

            usleep(500000);

            // Reset all GPS data before each read so that if we lose GPS signal
            // or drop to a 2D fix, the loss of data is accurately reflected
            // gps_loc data structure:
            // 0 = lat, 1 = lon, 2 = speed, 3 = heading, 4 = alt, 5 = lat error, 6 = lon error, 7 = vertical error

            // Check if we need to reset/invalidate our GPS data if the data has become 'stale' based on a timeout/interval
            time_t const seconds_since_last_update = time(NULL) - updateTime;

            if (seconds_since_last_update > gps_context->gps_valid_interval_seconds)
            {
                memset(gps_context->gps_loc, 0, sizeof(gps_context->gps_loc));
            }

            // Record ALL GPS data from GPSD
            if (gps_context->fp != NULL)
            {
                fputs(line, gps_context->fp);
            }

            /* read position, speed, heading, altitude */
            if (is_json)
            {
                // Format definition: http://catb.org/gpsd/gpsd_json.html
                pos =
                    read_line(gpsd_sock, buffer, (size_t)pos, sizeof(buffer));
                if (pos <= 0)
                {
                    break;
                }
                pos = get_line_from_buffer(buffer, (size_t)pos, line);

                // See if we got a TPV report - aka actual GPS data if not send default 0 values
                if (!json_get_value_for_name(line, "class", data)
                    || strncmp(data, "TPV", 3) != 0)
                {
                    /* Not a TPV report.  Get another line. */

                    continue;
                }

                /* See what sort of GPS fix we got.  Possibilities are:
                * 0: No data
                * 1: No fix
                * 2: Lat/Lon, but no alt
                * 3: Lat/Lon/Alt
                * Either 2 or 3 may also have speed and heading data.
                */
                if (!json_get_value_for_name(line, "mode", data)
                    || (strtol(data, NULL, 10)) < 2)
                {
                    /* No GPS fix, so there are no coordinates to extract. */
                    continue;
                }

                /* Extract the available data from the TPV report.  If we're
                * in mode 2, latitude and longitude are mandatory, altitude
                * is set to 0, and speed and heading are optional.
                * In mode 3, latitude, longitude, and altitude are mandatory,
                * while speed and heading are optional.
                * If we can't get a mandatory value, the line is discarded
                * as fragmentary or malformed.  If we can't get an optional
                * value, we default it to 0.
                */

                // GPS Time
                if (json_get_value_for_name(line, "time", data))
                {
                    if (!(strptime(data, "%Y-%m-%dT%H:%M:%S", &gps_context->gps_time)
                          == NULL))
                    {
                        updateTime = time(NULL);
                    }
                }

                // Latitude
                if (json_get_value_for_name(line, "lat", data))
                {
                    gps_context->gps_loc[0] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[0] = 0.0f;
                    }
                }

                // Longitude
                if (json_get_value_for_name(line, "lon", data))
                {
                    gps_context->gps_loc[1] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[1] = 0.0f;
                    }
                }

                // Longitude Error
                if (json_get_value_for_name(line, "epx", data))
                {
                    gps_context->gps_loc[6] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[6] = 0.0f;
                    }
                }

                // Latitude Error
                if (json_get_value_for_name(line, "epy", data))
                {
                    gps_context->gps_loc[5] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[5] = 00.f;
                    }
                }

                // Vertical Error
                if (json_get_value_for_name(line, "epv", data))
                {
                    gps_context->gps_loc[7] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[7] = 0.0f;
                    }
                }

                // Altitude
                if (json_get_value_for_name(line, "alt", data))
                {
                    gps_context->gps_loc[4] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[4] = 0.0f;
                    }
                }

                // Speed
                if (json_get_value_for_name(line, "speed", data))
                {
                    gps_context->gps_loc[2] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[2] = 0.0f;
                    }
                }

                // Heading
                if (json_get_value_for_name(line, "track", data))
                {
                    gps_context->gps_loc[3] = strtof(data, NULL);
                    if (errno == EINVAL || errno == ERANGE)
                    {
                        gps_context->gps_loc[3] = 0.0f;
                    }
                }
            }
            else
            {
                // Else read a NON JSON format
                snprintf(line, sizeof(line) - 1, "PVTAD\r\n");
                if (send(gpsd_sock, line, 7, 0) != 7)
                {
                    goto done;
                }

                memset(line, 0, sizeof(line));
                if (recv(gpsd_sock, line, sizeof(line) - 1, 0) <= 0)
                {
                    goto done;
                }

                if (memcmp(line, "GPSD,P=", 7) != 0)
                    continue;

                /* make sure the coordinates are present */

                if (line[7] == '?')
                    continue;

                int ret;
                updateTime = time(NULL);
                ret = sscanf(line + 7,
                             "%f %f",
                             &gps_context->gps_loc[0],
                             &gps_context->gps_loc[1]); /* lat lon */
                if (ret == EOF)
                    fprintf(stderr, "Failed to parse lat lon.\n");

                if ((temp = strstr(line, "V=")) == NULL)
                    continue;
                ret = sscanf(temp + 2, "%f", &gps_context->gps_loc[2]); /* speed */
                if (ret == EOF)
                    fprintf(stderr, "Failed to parse speed.\n");

                if ((temp = strstr(line, "T=")) == NULL)
                    continue;
                ret = sscanf(temp + 2, "%f", &gps_context->gps_loc[3]); /* heading */
                if (ret == EOF)
                    fprintf(stderr, "Failed to parse heading.\n");

                if ((temp = strstr(line, "A=")) == NULL)
                    continue;
                ret = sscanf(temp + 2, "%f", &gps_context->gps_loc[4]); /* altitude */
                if (ret == EOF)
                    fprintf(stderr, "Failed to parse altitude.\n");
            }

            gps_context->save_gps = 1;
        }

        // If we are still wanting to read GPS but encountered an error - reset data and try again
        if (*gps_context->do_exit == 0)
        {
            memset(gps_context->gps_loc, 0, sizeof(gps_context->gps_loc));
            sleep(1);
        }
    }

done:
    return NULL;
}

static void gps_tracker_cleanup(gps_tracker_context_st * const gps_context)
{
    free(gps_context->batt);
}

void gps_tracker_initialise(
    gps_tracker_context_st * const gps_context,
    char const * const dump_prefix,
    int const f_index,
    FILE * const fp,
    volatile int * do_exit)
{
    static const unsigned int default_gps_valid_interval_seconds = 5;

    memset(gps_context, 0, sizeof *gps_context);

    gps_context->gps_valid_interval_seconds = default_gps_valid_interval_seconds;
    gps_context->dump_prefix = dump_prefix;
    gps_context->f_index = f_index;
    gps_context->fp = fp;
    gps_context->do_exit = do_exit;
}

void gps_tracker_update(gps_tracker_context_st * const gps_context)
{
    update_battery_string(&gps_context->batt);
}

bool gps_tracker_start(gps_tracker_context_st * const gps_context)
{
    bool success;

    gps_tracker_update(gps_context);

    if (pthread_create(&gps_context->gps_tid,
                       NULL,
                       &gps_tracker_thread,
                       gps_context) != 0)
    {
        perror("Could not create GPS thread");
        success = false;
        goto done;
    }

    usleep(50000);
    waitpid(-1, NULL, WNOHANG);

    success =  true;

done:
    return success;
}

void gps_tracker_stop(gps_tracker_context_st * const gps_context)
{
    pthread_join(gps_context->gps_tid, NULL);

    gps_tracker_cleanup(gps_context);

    if (!gps_context->save_gps)
    {
        char buffer[PATH_MAX];

        snprintf(buffer,
                 sizeof buffer,
                 "%s-%02d.gps",
                 gps_context->dump_prefix,
                 gps_context->f_index);

        unlink(buffer);
    }
}

