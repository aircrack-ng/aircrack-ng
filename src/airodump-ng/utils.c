#include "utils.h"
#include "aircrack-ng/defs.h"

#include <string.h>
#include <sys/wait.h>

char * time_as_string(time_t const time)
{
    char * const string = strdup(ctime(&time));

    ALLEGE(string != NULL);

    /* Remove the new line that is included by ctime(). 
     * Cripes why wouldn't it just provide the time, and not assume 
     * that it goes at the end of a line? 
     */
    if (strlen(string) > 0)
    {
        string[strlen(string) - 1] = '\0';
    }

    return string;
}

char const * create_output_filename(
    char * const buffer,
    size_t const buffer_size,
    char const * const prefix,
    int const index,
    char const * const suffix)
{
    if (index < 0)
    {
        snprintf(buffer,
                 buffer_size,
                 "%s.%s",
                 prefix,
                 suffix);
    }
    else
    {
        snprintf(buffer,
                 buffer_size,
                 "%s-%02d.%s",
                 prefix,
                 index,
                 suffix);
    }

    return buffer;
}

int wait_proc(pid_t in, pid_t * out)
{
    int stat = 0;
    pid_t pid;

    do
    {
        pid = waitpid(in, &stat, WNOHANG);
    }
    while (pid < 0 && errno == EINTR);

    if (out != NULL)
    {
        *out = pid;
    }

    int status = -1;
    if (WIFEXITED(stat))
    {
        status = WEXITSTATUS(stat);
    }
    else if (WIFSIGNALED(stat))
    {
        status = WTERMSIG(stat);
    }

    return status;
}

void make_printable(uint8_t * const buf, size_t const buf_size)
{
    for (size_t i = 0; i < buf_size; i++)
    {
        if (buf[i] < (uint8_t)' ')
        {
            buf[i] = '.';
        }
    }
}

static int is_filtered_netmask(
    mac_address const * const bssid,
    mac_address const * const f_bssid,
    mac_address const * const f_netmask)
{
    REQUIRE(bssid != NULL);

    mac_address mac1;
    mac_address mac2;

    for (size_t i = 0; i < sizeof mac1; i++)
    {
        /* FIXME - Do (a ^ b) & mask? */
        mac1.addr[i] = bssid->addr[i] & f_netmask->addr[i];
        mac2.addr[i] = f_bssid->addr[i] & f_netmask->addr[i];
    }

    bool const is_filtered = !MAC_ADDRESS_EQUAL(&mac1, &mac2);

    return is_filtered;
}

bool bssid_is_filtered(
    mac_address const * const bssid,
    mac_address const * const f_bssid,
    mac_address const * const f_netmask)
{
    bool is_filtered;

    if (MAC_ADDRESS_IS_EMPTY(f_bssid))
    {
        is_filtered = false;
        goto done;
    }

    if (!MAC_ADDRESS_IS_EMPTY(f_netmask))
    {
        if (is_filtered_netmask(bssid, f_bssid, f_netmask))
        {
            is_filtered = true;
            goto done;
        }
    }
    else if (!MAC_ADDRESS_EQUAL(f_bssid, bssid))
    {
        is_filtered = true;
        goto done;
    }

    is_filtered = false;

done:
    return is_filtered;
}

