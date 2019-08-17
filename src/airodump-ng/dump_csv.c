#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h> // ftruncate
#include <sys/types.h> // ftruncate
#include <sys/time.h>
#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "aircrack-ng/defs.h"
#include "airodump-ng.h"
#include "aircrack-ng/support/communications.h"
#include "dump_csv.h"
#include "dump_write.h"
#include "dump_write_private.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/utf8/verifyssid.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

static char * format_text_for_csv(const unsigned char * input, size_t len)
{
    // Unix style encoding
    char * ret;
    size_t pos;
    int contains_space_end;
    static char const hex_table[] = "0123456789ABCDEF";

    if (len == 0 || input == NULL)
    {
        ret = strdup("");
        ALLEGE(ret != NULL);

        goto done;
    }

    pos = 0;
    contains_space_end = input[0] == ' ' || input[len - 1] == ' ';

    // Make sure to have enough memory for all that stuff
    ret = malloc((len * 4) + 1 + 2);
    ALLEGE(ret != NULL);

    if (contains_space_end)
    {
        ret[pos++] = '"';
    }

    for (size_t i = 0; i < len; i++)
    {
        if (!isprint(input[i]) || input[i] == ',' || input[i] == '\\'
            || input[i] == '"')
        {
            ret[pos++] = '\\';
        }

        if (isprint(input[i]))
        {
            ret[pos++] = input[i];
        }
        else if (input[i] == '\n')
        {
            ret[pos++] = 'n';
        }
        else if (input[i] == '\r')
        {
            ret[pos++] = 'r';
        }
        else if (input[i] == '\t')
        {
            ret[pos++] = 't';
        }
        else
        {
            uint8_t const val = input[i];

            ret[pos++] = 'x';
            ret[pos++] = hex_table[(val >> 4) & 0x0f];
            ret[pos++] = hex_table[val & 0x0f];
        }
    }

    if (contains_space_end)
    {
        ret[pos++] = '"';
    }

    ret[pos++] = '\0';

    char * const rret = realloc(ret, pos);

    if (rret != NULL)
    {
        ret = rret;
    }

done:
    return ret;
}

static void dump_write_csv(
    FILE * const fp,
    struct ap_list_head * ap_list,
    struct sta_list_head * const sta_list,
    unsigned int f_encrypt)
{
    int i, probes_written;
    struct tm * ltime;
    struct AP_info * ap_cur;
    char * temp;

    if (fp == NULL)
    {
        goto done;
    }

    fseek(fp, 0, SEEK_SET);

    fprintf(fp,
            "\r\nBSSID, First time seen, Last time seen, channel, Speed, "
            "Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, "
            "ID-length, ESSID, Key\r\n");

    TAILQ_FOREACH(ap_cur, ap_list, entry)
    {
        if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
        {
            continue;
        }

        if (ap_cur->security != 0 && f_encrypt != 0
            && ((ap_cur->security & f_encrypt) == 0))
        {
            continue;
        }

        if (is_filtered_essid(ap_cur->essid))
        {
            continue;
        }

        fprintf(fp,
                "%02X:%02X:%02X:%02X:%02X:%02X, ",
                ap_cur->bssid.addr[0],
                ap_cur->bssid.addr[1],
                ap_cur->bssid.addr[2],
                ap_cur->bssid.addr[3],
                ap_cur->bssid.addr[4],
                ap_cur->bssid.addr[5]);

        ltime = localtime(&ap_cur->tinit);

        fprintf(fp,
                "%04d-%02d-%02d %02d:%02d:%02d, ",
                1900 + ltime->tm_year,
                1 + ltime->tm_mon,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec);

        ltime = localtime(&ap_cur->tlast);

        fprintf(fp,
                "%04d-%02d-%02d %02d:%02d:%02d, ",
                1900 + ltime->tm_year,
                1 + ltime->tm_mon,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec);

        fprintf(fp, "%2d, %3d,", ap_cur->channel, ap_cur->max_speed);

        if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) == 0)
        {
            fprintf(fp, " ");
        }
        else
        {
            if (ap_cur->security & STD_WPA2)
            {
                if (ap_cur->security & AUTH_SAE || ap_cur->security & AUTH_OWE)
                {
                    fprintf(fp, " WPA3");
                }
                fprintf(fp, " WPA2");
            }
            if (ap_cur->security & STD_WPA)
                fprintf(fp, " WPA");
            if (ap_cur->security & STD_WEP)
                fprintf(fp, " WEP");
            if (ap_cur->security & STD_OPN)
                fprintf(fp, " OPN");
        }

        fprintf(fp, ",");

        if ((ap_cur->security & ENC_FIELD) == 0)
            fprintf(fp, " ");
        else
        {
            if (ap_cur->security & ENC_CCMP)
                fprintf(fp, " CCMP");
            if (ap_cur->security & ENC_WRAP)
                fprintf(fp, " WRAP");
            if (ap_cur->security & ENC_TKIP)
                fprintf(fp, " TKIP");
            if (ap_cur->security & ENC_WEP104)
                fprintf(fp, " WEP104");
            if (ap_cur->security & ENC_WEP40)
                fprintf(fp, " WEP40");
            if (ap_cur->security & ENC_WEP)
                fprintf(fp, " WEP");
            if (ap_cur->security & ENC_GCMP)
                fprintf(fp, " GCMP");
            if (ap_cur->security & ENC_GMAC)
                fprintf(fp, " GMAC");
        }

        fprintf(fp, ",");

        if ((ap_cur->security & AUTH_FIELD) == 0)
        {
            fprintf(fp, "   ");
        }
        else
        {
            if (ap_cur->security & AUTH_SAE)
                fprintf(fp, " SAE");
            if (ap_cur->security & AUTH_MGT)
                fprintf(fp, " MGT");
            if (ap_cur->security & AUTH_CMAC)
                fprintf(fp, " CMAC");
            if (ap_cur->security & AUTH_PSK)
            {
                if (ap_cur->security & STD_WEP)
                {
                    fprintf(fp, " SKA");
                }
                else
                {
                    fprintf(fp, " PSK");
                }
            }
            if (ap_cur->security & AUTH_OWE)
            {
                fprintf(fp, " OWE");
            }
            if (ap_cur->security & AUTH_OPN)
            {
                fprintf(fp, " OPN");
            }
        }

        fprintf(fp,
                ", %3d, %8lu, %8lu, ",
                ap_cur->avg_power,
                ap_cur->nb_bcn,
                ap_cur->nb_data);

        fprintf(fp,
                "%3d.%3d.%3d.%3d, ",
                ap_cur->lanip[0],
                ap_cur->lanip[1],
                ap_cur->lanip[2],
                ap_cur->lanip[3]);

        fprintf(fp, "%3d, ", ap_cur->ssid_length);

        if (verifyssid(ap_cur->essid))
        {
            fprintf(fp, "%s, ", ap_cur->essid);
        }
        else
        {
            temp = format_text_for_csv(ap_cur->essid,
                                       (size_t)ap_cur->ssid_length);
            if (temp != NULL) //-V547
            {
                fprintf(fp, "%s, ", temp);
                free(temp);
            }
        }

        if (ap_cur->key != NULL)
        {
            for (i = 0; i < (int)strlen(ap_cur->key); i++)
            {
                fprintf(fp, "%02X", ap_cur->key[i]);
                if (i < (int)(strlen(ap_cur->key) - 1))
                {
                    fprintf(fp, ":");
                }
            }
        }

        fprintf(fp, "\r\n");
    }

    fprintf(fp,
            "\r\nStation MAC, First time seen, Last time seen, "
            "Power, # packets, BSSID, Probed ESSIDs\r\n");

    struct ST_info * st_cur;

    TAILQ_FOREACH(st_cur, sta_list, entry)
    {
        ap_cur = st_cur->base;

        if (ap_cur->nb_pkt < 2)
        {
            continue;
        }

        fprintf(fp,
                "%02X:%02X:%02X:%02X:%02X:%02X, ",
                st_cur->stmac.addr[0],
                st_cur->stmac.addr[1],
                st_cur->stmac.addr[2],
                st_cur->stmac.addr[3],
                st_cur->stmac.addr[4],
                st_cur->stmac.addr[5]);

        ltime = localtime(&st_cur->tinit);

        fprintf(fp,
                "%04d-%02d-%02d %02d:%02d:%02d, ",
                1900 + ltime->tm_year,
                1 + ltime->tm_mon,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec);

        ltime = localtime(&st_cur->tlast);

        fprintf(fp,
                "%04d-%02d-%02d %02d:%02d:%02d, ",
                1900 + ltime->tm_year,
                1 + ltime->tm_mon,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec);

        fprintf(fp, "%3d, %8lu, ", st_cur->power, st_cur->nb_pkt);

        if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
        {
            fprintf(fp, "(not associated) ,");
        }
        else
        {
            fprintf(fp,
                    "%02X:%02X:%02X:%02X:%02X:%02X,",
                    ap_cur->bssid.addr[0],
                    ap_cur->bssid.addr[1],
                    ap_cur->bssid.addr[2],
                    ap_cur->bssid.addr[3],
                    ap_cur->bssid.addr[4],
                    ap_cur->bssid.addr[5]);
        }

        probes_written = 0;
        for (i = 0; i < NB_PRB; i++)
        {
            if (st_cur->ssid_length[i] == 0)
                continue;

            if (verifyssid((const unsigned char *)st_cur->probes[i]))
            {
                temp = (char *)calloc(
                    1, (st_cur->ssid_length[i] + 1) * sizeof(char));
                ALLEGE(temp != NULL);
                memcpy(temp, st_cur->probes[i], st_cur->ssid_length[i] + 1u);
            }
            else
            {
                temp = format_text_for_csv((unsigned char *)st_cur->probes[i],
                                           (size_t)st_cur->ssid_length[i]);
                ALLEGE(temp != NULL); //-V547
            }

            if (probes_written == 0)
            {
                fprintf(fp, "%s", temp);
                probes_written = 1;
            }
            else
            {
                fprintf(fp, ",%s", temp);
            }

            free(temp);
        }

        fprintf(fp, "\r\n");
    }

    fprintf(fp, "\r\n");
    fflush(fp);

done:
    return;
}

struct csv_dump_context_st
{
    FILE * fp;
};

static void csv_context_free(
    struct csv_dump_context_st * const context)
{
    free(context);
}

static void csv_dump(
    void * const priv,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
    unsigned int const f_encrypt)
{
    struct csv_dump_context_st * const context = priv;

    dump_write_csv(context->fp,
                   ap_list,
                   sta_list,
                   f_encrypt);
}

static void csv_dump_close(
    struct csv_dump_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    if (context->fp != NULL)
    {
        fclose(context->fp);
    }

    csv_context_free(context);

done:
    return;
}

static void csv_close(void * const priv)
{
    struct csv_dump_context_st * const context = priv;

    csv_dump_close(context);
}

struct csv_dump_context_st * csv_dump_context_open(
    char const * const filename)
{
    bool had_error;
    struct csv_dump_context_st * context =
        calloc(1, sizeof *context);

    if (context == NULL)
    {
        had_error = true;
        goto done;
    }

    context->fp = fopen(filename, "wb+");
    if (context->fp == NULL)
    {
        had_error = true;
        goto done;
    }

    had_error = false;

done:
    if (had_error)
    {
        csv_dump_close(context);
        context = NULL;
    }

    return context;
}

bool csv_dump_open(
    struct dump_context_st * const dump,
    char const * const filename)
{
    bool success;
    struct csv_dump_context_st * const context =
        csv_dump_context_open(filename);

    if (context == NULL)
    {
        success = false;
        goto done;
    }

    dump->priv = context;
    dump->dump = csv_dump;
    dump->close = csv_close;

    success = true;

done:
    return success;
}

