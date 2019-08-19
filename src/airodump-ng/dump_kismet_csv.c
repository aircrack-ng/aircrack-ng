#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "aircrack-ng/defs.h"
#include "airodump-ng.h"
#include "aircrack-ng/support/communications.h"

#include "dump_kismet_csv.h"
#include "dump_write_private.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

#define KISMET_HEADER                                                          \
	"Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;Encryption;Decrypted;"   \
	"MaxRate;MaxSeenRate;Beacon;LLC;Data;Crypt;Weak;Total;Carrier;Encoding;"   \
	"FirstTime;LastTime;BestQuality;BestSignal;BestNoise;GPSMinLat;GPSMinLon;" \
	"GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;GPSBestLat;"  \
	"GPSBestLon;GPSBestAlt;DataSize;IPType;IP;\n"

static void kismet_dump_write_csv(
    FILE * const fp,
    struct ap_list_head * ap_list,
    struct sta_list_head * const sta_list,
    unsigned int f_encrypt)
{
    UNUSED_PARAM(sta_list);

    int i; 
    int k;

    if (fp == NULL)
    {
        goto done;
    }

    if (fseek(fp, 0, SEEK_SET) == -1)
    {
        goto done;
    }

    fprintf(fp, KISMET_HEADER);

    k = 1;

    struct AP_info * ap_cur;

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

        if (is_filtered_essid(ap_cur->essid) || ap_cur->nb_pkt < 2)
        {
            continue;
        }

        // Network
        fprintf(fp, "%d;", k);

        // NetType
        fprintf(fp, "infrastructure;");

        // ESSID
        for (i = 0; i < ap_cur->ssid_length; i++)
        {
            fprintf(fp, "%c", ap_cur->essid[i]);
        }
        fprintf(fp, ";");

        // BSSID
        fprintf_mac_address(fp, &ap_cur->bssid);
        fprintf(fp, ";");

        // Info
        fprintf(fp, ";");

        // Channel
        fprintf(fp, "%d;", ap_cur->channel);

        // Cloaked
        fprintf(fp, "No;");

        // Encryption
        if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) != 0)
        {
            if (ap_cur->security & STD_WPA2)
            {
                if (ap_cur->security & AUTH_SAE || ap_cur->security & AUTH_OWE)
                {
                    fprintf(fp, "WPA3,");
                }
                else
                {
                    fprintf(fp, "WPA2,");
                }
            }
            if (ap_cur->security & STD_WPA)
                fprintf(fp, "WPA,");
            if (ap_cur->security & STD_WEP)
                fprintf(fp, "WEP,");
            if (ap_cur->security & STD_OPN)
                fprintf(fp, "OPN,");
        }

        if ((ap_cur->security & ENC_FIELD) == 0)
        {
            fprintf(fp, "None,");
        }
        else
        {
            if (ap_cur->security & ENC_CCMP)
                fprintf(fp, "AES-CCM,");
            if (ap_cur->security & ENC_WRAP)
                fprintf(fp, "WRAP,");
            if (ap_cur->security & ENC_TKIP)
                fprintf(fp, "TKIP,");
            if (ap_cur->security & ENC_WEP104)
                fprintf(fp, "WEP104,");
            if (ap_cur->security & ENC_WEP40)
                fprintf(fp, "WEP40,");
            if (ap_cur->security & ENC_GCMP)
                fprintf(fp, "GCMP,");
            if (ap_cur->security & ENC_GMAC)
                fprintf(fp, "GMAC,");
            if (ap_cur->security & AUTH_SAE)
                fprintf(fp, "SAE,");
            if (ap_cur->security & AUTH_OWE)
                fprintf(fp, "OWE,");
        }

        fseek(fp, -1, SEEK_CUR);
        fprintf(fp, ";");

        // Decrypted
        fprintf(fp, "No;");

        // MaxRate
        fprintf(fp, "%d.0;", ap_cur->max_speed);

        // MaxSeenRate
        fprintf(fp, "0;");

        // Beacon
        fprintf(fp, "%lu;", ap_cur->nb_bcn);

        // LLC
        fprintf(fp, "0;");

        // Data
        fprintf(fp, "%lu;", ap_cur->nb_data);

        // Crypt
        fprintf(fp, "0;");

        // Weak
        fprintf(fp, "0;");

        // Total
        fprintf(fp, "%lu;", ap_cur->nb_data);

        // Carrier
        fprintf(fp, ";");

        // Encoding
        fprintf(fp, ";");

        // FirstTime
        fprintf(fp, "%s", ctime(&ap_cur->tinit));
        fseek(fp, -1, SEEK_CUR);
        fprintf(fp, ";");

        // LastTime
        fprintf(fp, "%s", ctime(&ap_cur->tlast));
        fseek(fp, -1, SEEK_CUR);
        fprintf(fp, ";");

        // BestQuality
        fprintf(fp, "%d;", ap_cur->avg_power);

        // BestSignal
        fprintf(fp, "0;");

        // BestNoise
        fprintf(fp, "0;");

        // GPSMinLat
        fprintf(fp, "%.6f;", ap_cur->gps_loc_min[0]);

        // GPSMinLon
        fprintf(fp, "%.6f;", ap_cur->gps_loc_min[1]);

        // GPSMinAlt
        fprintf(fp, "%.6f;", ap_cur->gps_loc_min[2]);

        // GPSMinSpd
        fprintf(fp, "%.6f;", ap_cur->gps_loc_min[3]);

        // GPSMaxLat
        fprintf(fp, "%.6f;", ap_cur->gps_loc_max[0]);

        // GPSMaxLon
        fprintf(fp, "%.6f;", ap_cur->gps_loc_max[1]);

        // GPSMaxAlt
        fprintf(fp, "%.6f;", ap_cur->gps_loc_max[2]);

        // GPSMaxSpd
        fprintf(fp, "%.6f;", ap_cur->gps_loc_max[3]);

        // GPSBestLat
        fprintf(fp, "%.6f;", ap_cur->gps_loc_best[0]);

        // GPSBestLon
        fprintf(fp, "%.6f;", ap_cur->gps_loc_best[1]);

        // GPSBestAlt
        fprintf(fp, "%.6f;", ap_cur->gps_loc_best[2]);

        // DataSize
        fprintf(fp, "0;");

        // IPType
        fprintf(fp, "0;");

        // IP
        fprintf(fp,
                "%d.%d.%d.%d;",
                ap_cur->lanip[0],
                ap_cur->lanip[1],
                ap_cur->lanip[2],
                ap_cur->lanip[3]);

        fprintf(fp, "\r\n");

        k++;
    }

    fflush(fp);

done:
    return;
}

struct kismet_csv_dump_context_st
{
    FILE * fp;
};

static void kismet_csv_context_free(
    struct kismet_csv_dump_context_st * const context)
{
    free(context);
}

static void kismet_csv_dump(
    void * const priv,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
    unsigned int const f_encrypt)
{
    struct kismet_csv_dump_context_st * const context = priv;

    kismet_dump_write_csv(context->fp,
                          ap_list,
                          sta_list,
                          f_encrypt);
}

static void kismet_csv_dump_close(
    struct kismet_csv_dump_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    if (context->fp != NULL)
    {
        fclose(context->fp);
    }

    kismet_csv_context_free(context);

done:
    return;
}

static void kismet_csv_close(void * const priv)
{
    struct kismet_csv_dump_context_st * const context = priv;

    kismet_csv_dump_close(context);
}

struct kismet_csv_dump_context_st * kismet_csv_dump_context_open(
    char const * const filename)
{
    bool had_error;
    struct kismet_csv_dump_context_st * context =
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
        kismet_csv_dump_close(context);
        context = NULL;
    }

    return context;
}

bool kismet_csv_dump_open(
    struct dump_context_st * const dump,
    char const * const filename)
{
    bool success;
    struct kismet_csv_dump_context_st * const context =
        kismet_csv_dump_context_open(filename);

    if (context == NULL)
    {
        success = false;
        goto done;
    }

    dump->priv = context;
    dump->dump = kismet_csv_dump;
    dump->close = kismet_csv_close;

    success = true;

done:
    return success;
}

