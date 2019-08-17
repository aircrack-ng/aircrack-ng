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
#include "dump_kismet_netxml.h"
#include "dump_write.h"
#include "dump_write_private.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/utf8/verifyssid.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

static char * sanitize_xml(unsigned char * text, size_t length)
{
    size_t len; 
    size_t current_text_len;
    char * newtext = NULL;

    if (text != NULL && length > 0)
    {
        unsigned char * pos;

        len = 8 * length;
        newtext = (char *)calloc(
            1, (len + 1) * sizeof(char)); // Make sure we have enough space
        ALLEGE(newtext != NULL);
        pos = text;
        for (size_t i = 0; i < length; ++i, ++pos)
        {
            switch (*pos)
            {
                case '&':
                    strncat(newtext, "&amp;", len);
                    break;
                case '<':
                    strncat(newtext, "&lt;", len);
                    break;
                case '>':
                    strncat(newtext, "&gt;", len);
                    break;
                case '\'':
                    strncat(newtext, "&apos;", len);
                    break;
                case '"':
                    strncat(newtext, "&quot;", len);
                    break;
                case '\r':
                    strncat(newtext, "&#xD;", len);
                    break;
                case '\n':
                    strncat(newtext, "&#xA;", len);
                    break;
                default:
                    if (isprint((int)(*pos)))
                    {
                        newtext[strlen(newtext)] = *pos;
                    }
                    else
                    {
                        strncat(newtext, "&#x", len);
                        current_text_len = strlen(newtext);
                        snprintf(newtext + current_text_len,
                                 len - current_text_len + 1,
                                 "%4x",
                                 *pos);
                        strncat(newtext, ";", len);
                    }
                    break;
            }
        }
        char * tmp_newtext = realloc(newtext, strlen(newtext) + 1);
        ALLEGE(tmp_newtext != NULL);
        newtext = tmp_newtext;
    }

    return newtext;
}

#define KISMET_NETXML_HEADER_BEGIN                                             \
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE "              \
	"detection-run SYSTEM "                                                    \
	"\"http://kismetwireless.net/kismet-3.1.0.dtd\">\n\n<detection-run "       \
	"kismet-version=\"airodump-ng-1.0\" start-time=\""
#define KISMET_NETXML_HEADER_END "\">\n\n"

#define KISMET_NETXML_TRAILER "</detection-run>"

#define TIME_STR_LENGTH 255
static int dump_write_kismet_netxml_client_info(
    FILE * const fp,
    struct ST_info * client,
    int client_no,
    bool const use_gpsd)
{
    char first_time[TIME_STR_LENGTH];
    char last_time[TIME_STR_LENGTH];
    char * manuf;
    int client_max_rate, average_power, max_power, i, nb_probes_written,
        is_unassociated;
    char * essid = NULL;

    if (client == NULL || (client_no <= 0 || client_no >= INT_MAX))
    {
        return (1);
    }

    is_unassociated = (client->base == NULL
                       || MAC_ADDRESS_IS_BROADCAST(&client->base->bssid));

    strncpy(first_time, ctime(&client->tinit), TIME_STR_LENGTH - 1);
    first_time[strlen(first_time) - 1] = 0; // remove new line

    strncpy(last_time, ctime(&client->tlast), TIME_STR_LENGTH - 1);
    last_time[strlen(last_time) - 1] = 0; // remove new line

    fprintf(fp,
            "\t\t<wireless-client number=\"%d\" "
            "type=\"%s\" first-time=\"%s\""
            " last-time=\"%s\">\n",
            client_no,
            (is_unassociated) ? "tods" : "established",
            first_time,
            last_time);

    fprintf(fp, "\t\t\t<client-mac>");
    fprintf_mac_address(fp, &client->stmac);
    fprintf(fp, "</client-mac>\n");

    /* Manufacturer, if set using standard oui list */
    manuf
        = sanitize_xml((unsigned char *)client->manuf, strlen(client->manuf));
    fprintf(fp,
            "\t\t\t<client-manuf>%s</client-manuf>\n",
            (manuf != NULL) ? manuf : "Unknown");
    free(manuf);

    /* SSID item, aka Probes */
    nb_probes_written = 0;
    for (i = 0; i < NB_PRB; i++)
    {
        if (client->probes[i][0] == '\0')
            continue;

        fprintf(fp,
                "\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
                first_time,
                last_time);
        fprintf(fp,
                "\t\t\t\t<type>Probe Request</type>\n"
                "\t\t\t\t<max-rate>54.000000</max-rate>\n"
                "\t\t\t\t<packets>1</packets>\n"
                "\t\t\t\t<encryption>None</encryption>\n");
        essid = sanitize_xml((unsigned char *)client->probes[i],
                             (size_t)client->ssid_length[i]);
        if (essid != NULL)
        {
            fprintf(fp, "\t\t\t\t<ssid>%s</ssid>\n", essid);
            free(essid);
        }

        fprintf(fp, "\t\t\t</SSID>\n");

        ++nb_probes_written;
    }

    // Unassociated client with broadcast probes
    if (is_unassociated && nb_probes_written == 0)
    {
        fprintf(fp,
                "\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
                first_time,
                last_time);
        fprintf(fp,
                "\t\t\t\t<type>Probe Request</type>\n"
                "\t\t\t\t<max-rate>54.000000</max-rate>\n"
                "\t\t\t\t<packets>1</packets>\n"
                "\t\t\t\t<encryption>None</encryption>\n");
        fprintf(fp, "\t\t\t</SSID>\n");
    }

    /* Channel
       FIXME: Take opt.freqoption in account */
    fprintf(fp, "\t\t\t<channel>%d</channel>\n", client->channel);

    /* Rate: inaccurate because it's the latest rate seen */
    client_max_rate = (client->rate_from > client->rate_to) 
        ? client->rate_from
        : client->rate_to;
    fprintf(fp,
            "\t\t\t<maxseenrate>%.6f</maxseenrate>\n",
            client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
            (0.0f + 1000000));
#else
            1000000.0);
#endif

    /* Those 2 lines always stays the same */
    fprintf(fp, "\t\t\t<carrier>IEEE 802.11b+</carrier>\n");
    fprintf(fp, "\t\t\t<encoding>CCK</encoding>\n");

    /* Packets */
    fprintf(fp,
            "\t\t\t<packets>\n"
            "\t\t\t\t<LLC>0</LLC>\n"
            "\t\t\t\t<data>0</data>\n"
            "\t\t\t\t<crypt>0</crypt>\n"
            "\t\t\t\t<total>%lu</total>\n"
            "\t\t\t\t<fragments>0</fragments>\n"
            "\t\t\t\t<retries>0</retries>\n"
            "\t\t\t</packets>\n",
            client->nb_pkt);

    /* SNR information */
    average_power = (client->power == -1) ? 0 : client->power;
    max_power = (client->best_power == -1) ? average_power : client->best_power;

    fprintf(fp,
            "\t\t\t<snr-info>\n"
            "\t\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
            "\t\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
            "\t\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
            "\t\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
            "\t\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
            "\t\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
            "\t\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
            "\t\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
            "\t\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
            "\t\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
            "\t\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
            "\t\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
            "\t\t\t</snr-info>\n",
            average_power,
            average_power,
            average_power,
            max_power,
            max_power);

    /* GPS Coordinates for clients */

    if (use_gpsd)
    {
        fprintf(fp,
                "\t\t\t<gps-info>\n"
                "\t\t\t\t<min-lat>%.6f</min-lat>\n"
                "\t\t\t\t<min-lon>%.6f</min-lon>\n"
                "\t\t\t\t<min-alt>%.6f</min-alt>\n"
                "\t\t\t\t<min-spd>%.6f</min-spd>\n"
                "\t\t\t\t<max-lat>%.6f</max-lat>\n"
                "\t\t\t\t<max-lon>%.6f</max-lon>\n"
                "\t\t\t\t<max-alt>%.6f</max-alt>\n"
                "\t\t\t\t<max-spd>%.6f</max-spd>\n"
                "\t\t\t\t<peak-lat>%.6f</peak-lat>\n"
                "\t\t\t\t<peak-lon>%.6f</peak-lon>\n"
                "\t\t\t\t<peak-alt>%.6f</peak-alt>\n"
                "\t\t\t\t<avg-lat>%.6f</avg-lat>\n"
                "\t\t\t\t<avg-lon>%.6f</avg-lon>\n"
                "\t\t\t\t<avg-alt>%.6f</avg-alt>\n"
                "\t\t\t</gps-info>\n",
                client->gps_loc_min[0],
                client->gps_loc_min[1],
                client->gps_loc_min[2],
                client->gps_loc_min[3],
                client->gps_loc_max[0],
                client->gps_loc_max[1],
                client->gps_loc_max[2],
                client->gps_loc_max[3],
                client->gps_loc_best[0],
                client->gps_loc_best[1],
                client->gps_loc_best[2],
                /* Can the "best" be considered as average??? */
                client->gps_loc_best[0],
                client->gps_loc_best[1],
                client->gps_loc_best[2]);
    }
    fprintf(fp, "\t\t</wireless-client>\n");

    return 0;
}

#define NETXML_ENCRYPTION_TAG "%s<encryption>%s</encryption>\n"
static void kismet_dump_write_netxml(
    FILE * const fp,
    struct ap_list_head * ap_list,
    struct sta_list_head * const sta_list,
    unsigned int f_encrypt,
    char const * const airodump_start_time,
    bool const use_gpsd)
{
    int network_number, average_power, client_max_rate, max_power, client_nbr;
    off_t fpos;
    struct ST_info * st_cur;
    char first_time[TIME_STR_LENGTH];
    char last_time[TIME_STR_LENGTH];
    char * manuf;
    char * essid = NULL;

    if (fp == NULL)
    {
        goto done;
    }

    if (fseek(fp, 0, SEEK_SET) == -1)
    {
        goto done;
    }

    /* Header and airodump-ng start time */
    fprintf(fp,
            "%s%s%s",
            KISMET_NETXML_HEADER_BEGIN,
            airodump_start_time,
            KISMET_NETXML_HEADER_END);

    network_number = 0;

    struct AP_info * ap_cur;
    TAILQ_FOREACH(ap_cur, ap_list, entry)
    {
        if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
        {
            continue;
        }

        if (ap_cur->security != 0 
            && f_encrypt != 0
            && ((ap_cur->security & f_encrypt) == 0))
        {
            continue;
        }

        if (is_filtered_essid(ap_cur->essid))
        {
            continue;
        }

        ++network_number; // Network Number
        strncpy(first_time, ctime(&ap_cur->tinit), TIME_STR_LENGTH - 1);
        first_time[strlen(first_time) - 1] = 0; // remove new line

        strncpy(last_time, ctime(&ap_cur->tlast), TIME_STR_LENGTH - 1);
        last_time[strlen(last_time) - 1] = 0; // remove new line

        fprintf(fp,
                "\t<wireless-network number=\"%d\" type=\"infrastructure\" ",
                network_number);
        fprintf(fp,
                "first-time=\"%s\" last-time=\"%s\">\n",
                first_time,
                last_time);

        fprintf(fp,
                "\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
                first_time,
                last_time);
        fprintf(fp, "\t\t\t<type>Beacon</type>\n");
        fprintf(fp,
                "\t\t\t<max-rate>%d.000000</max-rate>\n",
                ap_cur->max_speed);
        fprintf(
            fp, "\t\t\t<packets>%lu</packets>\n", ap_cur->nb_bcn);
        fprintf(fp, "\t\t\t<beaconrate>%d</beaconrate>\n", 10);

        // Encryption
        if (ap_cur->security & STD_OPN)
            fprintf(fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "None");
        else if (ap_cur->security & STD_WEP)
            fprintf(fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP");
        else if (ap_cur->security & STD_WPA2 || ap_cur->security & STD_WPA)
        {
            if (ap_cur->security & ENC_TKIP)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+TKIP");
            if (ap_cur->security & AUTH_MGT)
                fprintf(fp,
                        NETXML_ENCRYPTION_TAG,
                        "\t\t\t",
                        "WPA+MGT"); // Not a valid value: NetXML does not have a
            // value for WPA Enterprise
            if (ap_cur->security & AUTH_PSK)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+PSK");
            if (ap_cur->security & AUTH_CMAC)
                fprintf(fp,
                        NETXML_ENCRYPTION_TAG,
                        "\t\t\t",
                        "WPA+PSK+CMAC");
            if (ap_cur->security & ENC_CCMP)
                fprintf(fp,
                        NETXML_ENCRYPTION_TAG,
                        "\t\t\t",
                        "WPA+AES-CCM");
            if (ap_cur->security & ENC_WRAP)
                fprintf(fp,
                        NETXML_ENCRYPTION_TAG,
                        "\t\t\t",
                        "WPA+AES-OCB");
            if (ap_cur->security & ENC_GCMP)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+GCMP");
            if (ap_cur->security & ENC_GMAC)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+GMAC");
            if (ap_cur->security & AUTH_SAE)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+SAE");
            if (ap_cur->security & AUTH_OWE)
                fprintf(
                    fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+OWE");
        }
        else if (ap_cur->security & ENC_WEP104)
            fprintf(fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP104");
        else if (ap_cur->security & ENC_WEP40)
            fprintf(fp, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP40");

        /* ESSID */
        fprintf(fp,
                "\t\t\t<essid cloaked=\"%s\">",
                (ap_cur->essid[0] == 0) ? "true" : "false");
        essid = sanitize_xml(ap_cur->essid, (size_t)ap_cur->ssid_length);
        if (essid != NULL)
        {
            fprintf(fp, "%s", essid);
            free(essid);
        }
        fprintf(fp, "</essid>\n");

        /* End of SSID tag */
        fprintf(fp, "\t\t</SSID>\n");

        /* BSSID */
        fprintf(fp, "\t\t<BSSID>");
        fprintf_mac_address(fp, &ap_cur->bssid);
        fprintf(fp, "</BSSID>\n");

        /* Manufacturer, if set using standard oui list */
        manuf = sanitize_xml((unsigned char *)ap_cur->manuf,
                             strlen(ap_cur->manuf));
        fprintf(fp,
                "\t\t<manuf>%s</manuf>\n",
                (manuf != NULL) ? manuf : "Unknown");
        free(manuf);

        /* Channel
           FIXME: Take opt.freqoption in account */
        fprintf(fp,
                "\t\t<channel>%d</channel>\n",
                (ap_cur->channel) == -1 ? 0 : ap_cur->channel);

        /* Freq (in Mhz) and total number of packet on that frequency
           FIXME: Take opt.freqoption in account */
        fprintf(fp,
                "\t\t<freqmhz>%d %lu</freqmhz>\n",
                (ap_cur->channel) == -1 ? 0 : getFrequencyFromChannel(
                    ap_cur->channel),
                // ap_cur->nb_data + ap_cur->nb_bcn );
                ap_cur->nb_pkt);

        /* XXX: What about 5.5Mbit */
        fprintf(fp,
                "\t\t<maxseenrate>%d</maxseenrate>\n",
                (ap_cur->max_speed == -1) ? 0 : ap_cur->max_speed * 1000);

        /* Those 2 lines always stays the same */
        fprintf(fp, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
        fprintf(fp, "\t\t<encoding>CCK</encoding>\n");

        /* Packets */
        fprintf(fp,
                "\t\t<packets>\n"
                "\t\t\t<LLC>%lu</LLC>\n"
                "\t\t\t<data>%lu</data>\n"
                "\t\t\t<crypt>0</crypt>\n"
                "\t\t\t<total>%lu</total>\n"
                "\t\t\t<fragments>0</fragments>\n"
                "\t\t\t<retries>0</retries>\n"
                "\t\t</packets>\n",
                ap_cur->nb_data,
                ap_cur->nb_data,
                // ap_cur->nb_data + ap_cur->nb_bcn );
                ap_cur->nb_pkt);

        /* XXX: What does that field mean? Is it the total size of data? */
        fprintf(fp, "\t\t<datasize>0</datasize>\n");

        /* Client information */
        client_nbr = 0;

        TAILQ_FOREACH(st_cur, sta_list, entry)
        {
            /* Check if the station is associated to the current AP */
            if (!MAC_ADDRESS_IS_BROADCAST(&st_cur->stmac)
                && st_cur->base != NULL
                && MAC_ADDRESS_EQUAL(&st_cur->base->bssid, &ap_cur->bssid))
            {
                dump_write_kismet_netxml_client_info(fp, st_cur, ++client_nbr, use_gpsd);
            }
        }

        /* SNR information */
        average_power = (ap_cur->avg_power == -1) ? 0 : ap_cur->avg_power;
        max_power
            = (ap_cur->best_power == -1) ? average_power : ap_cur->best_power;
        fprintf(fp,
                "\t\t<snr-info>\n"
                "\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
                "\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
                "\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
                "\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
                "\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
                "\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
                "\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
                "\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
                "\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
                "\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
                "\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
                "\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
                "\t\t</snr-info>\n",
                average_power,
                average_power,
                average_power,
                max_power,
                max_power);

        /* GPS Coordinates */
        if (use_gpsd)
        {
            fprintf(fp,
                    "\t\t<gps-info>\n"
                    "\t\t\t<min-lat>%.6f</min-lat>\n"
                    "\t\t\t<min-lon>%.6f</min-lon>\n"
                    "\t\t\t<min-alt>%.6f</min-alt>\n"
                    "\t\t\t<min-spd>%.6f</min-spd>\n"
                    "\t\t\t<max-lat>%.6f</max-lat>\n"
                    "\t\t\t<max-lon>%.6f</max-lon>\n"
                    "\t\t\t<max-alt>%.6f</max-alt>\n"
                    "\t\t\t<max-spd>%.6f</max-spd>\n"
                    "\t\t\t<peak-lat>%.6f</peak-lat>\n"
                    "\t\t\t<peak-lon>%.6f</peak-lon>\n"
                    "\t\t\t<peak-alt>%.6f</peak-alt>\n"
                    "\t\t\t<avg-lat>%.6f</avg-lat>\n"
                    "\t\t\t<avg-lon>%.6f</avg-lon>\n"
                    "\t\t\t<avg-alt>%.6f</avg-alt>\n"
                    "\t\t</gps-info>\n",
                    ap_cur->gps_loc_min[0],
                    ap_cur->gps_loc_min[1],
                    ap_cur->gps_loc_min[2],
                    ap_cur->gps_loc_min[3],
                    ap_cur->gps_loc_max[0],
                    ap_cur->gps_loc_max[1],
                    ap_cur->gps_loc_max[2],
                    ap_cur->gps_loc_max[3],
                    ap_cur->gps_loc_best[0],
                    ap_cur->gps_loc_best[1],
                    ap_cur->gps_loc_best[2],
                    /* Can the "best" be considered as average??? */
                    ap_cur->gps_loc_best[0],
                    ap_cur->gps_loc_best[1],
                    ap_cur->gps_loc_best[2]);
        }

        /* BSS Timestamp */
        fprintf(fp,
                "\t\t<bsstimestamp>%llu</bsstimestamp>\n",
                ap_cur->timestamp);

        /* Trailing information */
        fprintf(fp,
                "\t\t<cdp-device></cdp-device>\n"
                "\t\t<cdp-portid></cdp-portid>\n");

        /* Closing tag for the current wireless network */
        fprintf(fp, "\t</wireless-network>\n");
        //-------- End of XML

    }

    /* Write all unassociated stations */
    TAILQ_FOREACH(st_cur, sta_list, entry)
    {
        /* If not associated and not Broadcast Mac */
        if (st_cur->base == NULL
            || MAC_ADDRESS_IS_BROADCAST(&st_cur->base->bssid))
        {
            ++network_number; // Network Number

            /* Write new network information */
            strncpy(first_time, ctime(&st_cur->tinit), TIME_STR_LENGTH - 1);
            first_time[strlen(first_time) - 1] = 0; // remove new line

            strncpy(last_time, ctime(&st_cur->tlast), TIME_STR_LENGTH - 1);
            last_time[strlen(last_time) - 1] = 0; // remove new line

            fprintf(fp,
                    "\t<wireless-network number=\"%d\" type=\"probe\" ",
                    network_number);
            fprintf(fp,
                    "first-time=\"%s\" last-time=\"%s\">\n",
                    first_time,
                    last_time);

            /* BSSID */
            fprintf(fp, "\t\t<BSSID>");
            fprintf_mac_address(fp, &st_cur->stmac);
            fprintf(fp, "</BSSID>\n");

            /* Manufacturer, if set using standard oui list */
            manuf = sanitize_xml((unsigned char *)st_cur->manuf,
                                 strlen(st_cur->manuf));
            fprintf(fp,
                    "\t\t<manuf>%s</manuf>\n",
                    (manuf != NULL) ? manuf : "Unknown");
            free(manuf);

            /* Channel
               FIXME: Take opt.freqoption in account */
            fprintf(
                fp, "\t\t<channel>%d</channel>\n", st_cur->channel);

            /* Freq (in Mhz) and total number of packet on that frequency
               FIXME: Take opt.freqoption in account */
            fprintf(fp,
                    "\t\t<freqmhz>%d %lu</freqmhz>\n",
                    getFrequencyFromChannel(st_cur->channel),
                    st_cur->nb_pkt);

            /* Rate: inaccurate because it's the latest rate seen */
            client_max_rate = (st_cur->rate_from > st_cur->rate_to)
                ? st_cur->rate_from
                : st_cur->rate_to;
            fprintf(fp,
                    "\t\t<maxseenrate>%.6f</maxseenrate>\n",
                    client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
                    (0.0f + 1000000));
#else
                    1000000.0);
#endif

            fprintf(fp, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
            fprintf(fp, "\t\t<encoding>CCK</encoding>\n");

            /* Packets */
            fprintf(fp,
                    "\t\t<packets>\n"
                    "\t\t\t<LLC>0</LLC>\n"
                    "\t\t\t<data>0</data>\n"
                    "\t\t\t<crypt>0</crypt>\n"
                    "\t\t\t<total>%lu</total>\n"
                    "\t\t\t<fragments>0</fragments>\n"
                    "\t\t\t<retries>0</retries>\n"
                    "\t\t</packets>\n",
                    st_cur->nb_pkt);

            /* XXX: What does that field mean? Is it the total size of data? */
            fprintf(fp, "\t\t<datasize>0</datasize>\n");

            /* SNR information */
            average_power = (st_cur->power == -1) ? 0 : st_cur->power;
            max_power = (st_cur->best_power == -1) ? average_power
                : st_cur->best_power;

            fprintf(fp,
                    "\t\t<snr-info>\n"
                    "\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
                    "\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
                    "\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
                    "\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
                    "\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
                    "\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
                    "\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
                    "\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
                    "\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
                    "\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
                    "\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
                    "\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
                    "\t\t</snr-info>\n",
                    average_power,
                    average_power,
                    average_power,
                    max_power,
                    max_power);

            /* GPS Coordinates for clients */

            if (use_gpsd)
            {
                fprintf(fp,
                        "\t\t<gps-info>\n"
                        "\t\t\t<min-lat>%.6f</min-lat>\n"
                        "\t\t\t<min-lon>%.6f</min-lon>\n"
                        "\t\t\t<min-alt>%.6f</min-alt>\n"
                        "\t\t\t<min-spd>%.6f</min-spd>\n"
                        "\t\t\t<max-lat>%.6f</max-lat>\n"
                        "\t\t\t<max-lon>%.6f</max-lon>\n"
                        "\t\t\t<max-alt>%.6f</max-alt>\n"
                        "\t\t\t<max-spd>%.6f</max-spd>\n"
                        "\t\t\t<peak-lat>%.6f</peak-lat>\n"
                        "\t\t\t<peak-lon>%.6f</peak-lon>\n"
                        "\t\t\t<peak-alt>%.6f</peak-alt>\n"
                        "\t\t\t<avg-lat>%.6f</avg-lat>\n"
                        "\t\t\t<avg-lon>%.6f</avg-lon>\n"
                        "\t\t\t<avg-alt>%.6f</avg-alt>\n"
                        "\t\t</gps-info>\n",
                        st_cur->gps_loc_min[0],
                        st_cur->gps_loc_min[1],
                        st_cur->gps_loc_min[2],
                        st_cur->gps_loc_min[3],
                        st_cur->gps_loc_max[0],
                        st_cur->gps_loc_max[1],
                        st_cur->gps_loc_max[2],
                        st_cur->gps_loc_max[3],
                        st_cur->gps_loc_best[0],
                        st_cur->gps_loc_best[1],
                        st_cur->gps_loc_best[2],
                        /* Can the "best" be considered as average??? */
                        st_cur->gps_loc_best[0],
                        st_cur->gps_loc_best[1],
                        st_cur->gps_loc_best[2]);
            }

            fprintf(fp, "\t\t<bsstimestamp>0</bsstimestamp>\n");

            /* CDP information */
            fprintf(fp,
                    "\t\t<cdp-device></cdp-device>\n"
                    "\t\t<cdp-portid></cdp-portid>\n");

            /* Write client information */
            dump_write_kismet_netxml_client_info(fp, st_cur, 1, use_gpsd);

            fprintf(fp, "\t</wireless-network>");
        }
    }
    /* TODO: Also go through na_1st */

    /* Trailing */
    fprintf(fp, "%s\n", KISMET_NETXML_TRAILER);

    fflush(fp);

    /* Sometimes there can be crap at the end of the file, so truncating is a
       good idea.
       XXX: Is this really correct? I hope fileno() won't have any 
       side effect 
       */
    int const file_no = fileno(fp);
    fpos = ftell(fp);
    if (file_no == -1 || fpos == -1)
    {
        goto done;
    }

    IGNORE_NZ(ftruncate(file_no, fpos));

done:
    return;
}

struct kismet_netxml_dump_context_st
{
    FILE * fp;
    char const * airodump_start_time;
    bool use_gpsd;
};

static void kismet_netxml_context_free(
    struct kismet_netxml_dump_context_st * const context)
{
    free((void *)context->airodump_start_time);
    free(context);
}

static void kismet_netxml_dump(
    void * const priv,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
    unsigned int const f_encrypt)
{
    struct kismet_netxml_dump_context_st * const context = priv;

    kismet_dump_write_netxml(context->fp,
                             ap_list,
                             sta_list,
                             f_encrypt,
                             context->airodump_start_time,
                             context->use_gpsd);
}

static void kismet_netxml_dump_close(
    struct kismet_netxml_dump_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    if (context->fp != NULL)
    {
        fclose(context->fp);
    }

    kismet_netxml_context_free(context);

done:
    return;
}

static void kismet_netxml_close(void * const priv)
{
    struct kismet_netxml_dump_context_st * const context = priv;

    kismet_netxml_dump_close(context);
}

struct kismet_netxml_dump_context_st * kismet_netxml_dump_context_open(
    char const * const filename,
    char const * const airodump_start_time,
    bool const use_gpsd)
{
    bool had_error;
    struct kismet_netxml_dump_context_st * context =
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

    context->airodump_start_time = strdup(airodump_start_time);
    ALLEGE(context->airodump_start_time != NULL);

    context->use_gpsd = use_gpsd;

    had_error = false;

done:
    if (had_error)
    {
        kismet_netxml_dump_close(context);
        context = NULL;
    }

    return context;
}

bool kismet_netxml_dump_open(
    struct dump_context_st * const dump,
    char const * const filename,
    char const * const airodump_start_time,
    bool const use_gpsd)
{
    bool success;
    struct kismet_netxml_dump_context_st * const context =
        kismet_netxml_dump_context_open(filename, 
                                        airodump_start_time,
                                        use_gpsd);

    if (context == NULL)
    {
        success = false;
        goto done;
    }

    dump->priv = context;
    dump->dump = kismet_netxml_dump;
    dump->close = kismet_netxml_close;

    success = true;

done:
    return success;
}

