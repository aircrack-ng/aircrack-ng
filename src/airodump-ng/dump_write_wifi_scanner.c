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
#include "dump_write_wifi_scanner.h"
#include "dump_write.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/utf8/verifyssid.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

#define FIELD_SEPARATOR "|"

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

static void dump_ap(
    FILE * const fp,
    struct AP_info * const ap_cur,
    unsigned int const f_encrypt,
    time_t const filter_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
    if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
    {
        goto done;
    }

    if (ap_cur->security != 0 
        && f_encrypt != 0
        && (ap_cur->security & f_encrypt) == 0)
    {
        goto done;
    }

    if (is_filtered_essid(ap_cur->essid))
    {
        goto done;
    }

    time_t const current_time = time(NULL);
    time_t const time_since_last_printed =
        current_time - ap_cur->time_printed;

    if (time_since_last_printed < filter_seconds
        && ap_cur->old_channel == ap_cur->channel)
    {
        goto done;
    }

    ap_cur->time_printed = current_time;
    ap_cur->old_channel = ap_cur->channel;

    fprintf(fp, "%s" FIELD_SEPARATOR "%s" FIELD_SEPARATOR , sys_name, loc_name);

    fprintf(fp, "%ld" FIELD_SEPARATOR, ap_cur->tinit);

    fprintf(fp, "%ld" FIELD_SEPARATOR, ap_cur->tlast);

    /* Printed twice to maintain output format. */
    fprintf_mac_address(fp, &ap_cur->bssid);
    fprintf(fp, FIELD_SEPARATOR);

    fprintf_mac_address(fp, &ap_cur->bssid);
    fprintf(fp, FIELD_SEPARATOR);

    fprintf(fp, "%2d" FIELD_SEPARATOR, ap_cur->channel);

    bool const have_essid = 
        ap_cur->ssid_length > 0 && ap_cur->essid[0] != '\0';

    if (!have_essid)
    {
        fprintf(fp, "<hidden-ssid>");
    }
    else
    {
        char * const essid =
            format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);

        if (essid != NULL)
        {
            fprintf(fp, "%s", essid);
            free(essid);
        }
    }
    fprintf(fp, FIELD_SEPARATOR);

    fprintf(fp, "%3d\r\n", ap_cur->avg_power);

done:
    return;
}

static void dump_aps(
    FILE * const fp,
    struct ap_list_head * const ap_list,
    unsigned int const f_encrypt,
    time_t const filter_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
    struct AP_info * ap_cur;

    /* Access Points */
    TAILQ_FOREACH(ap_cur, ap_list, entry)
    {
        dump_ap(fp, ap_cur, f_encrypt, filter_seconds, sys_name, loc_name);
    }

    fflush(fp);
}

static void dump_sta(
    FILE * const fp,
    struct ST_info * st_cur,
    time_t const filter_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
    struct AP_info const * const ap_cur = st_cur->base;

    if (ap_cur->nb_pkt < 2)
    {
        goto done;
    }

    time_t const current_time = time(NULL);
    time_t const time_since_last_printed =
        current_time - st_cur->time_printed;

    if (time_since_last_printed < filter_seconds
        && st_cur->old_channel == st_cur->channel)
    {
        goto done;
    }

    st_cur->time_printed = current_time;
    st_cur->old_channel = st_cur->channel;

    fprintf(fp, "%s" FIELD_SEPARATOR "%s" FIELD_SEPARATOR, sys_name, loc_name);

    fprintf(fp, "%ld" FIELD_SEPARATOR, st_cur->tinit);

    fprintf(fp, "%ld" FIELD_SEPARATOR, st_cur->tlast);

    fprintf_mac_address(fp, &st_cur->stmac);
    fprintf(fp, FIELD_SEPARATOR);

    if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
    {
        fprintf_mac_address(fp, &ap_cur->bssid);
    }
    fprintf(fp, FIELD_SEPARATOR);

    fprintf(fp, "%2d" FIELD_SEPARATOR, st_cur->channel);

    if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
    {
        bool const have_essid = 
            ap_cur->ssid_length > 0 && ap_cur->essid[0] != '\0';

        if (!have_essid)
        {
            fprintf(fp, "<hidden-ssid>");
        }
        else
        {
            char * const essid =
                format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);

            if (essid != NULL)
            {
                fprintf(fp, "%s", essid);
                free(essid);
            }
        }
    }
    fprintf(fp, FIELD_SEPARATOR);

    fprintf(fp, "%3d", st_cur->power);

    fprintf(fp, "\r\n");

done:
    return;
}

static void dump_stas(
    FILE * const fp,
    struct sta_list_head * const sta_list,
    time_t const filter_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
    struct ST_info * st_cur;

    /* Stations */
    TAILQ_FOREACH(st_cur, sta_list, entry)
    {
        dump_sta(fp, st_cur, filter_seconds, sys_name, loc_name);
    }

    fflush(fp); 
}

static void dump_write_wifi_scanner(
    FILE * const fp,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
	unsigned int const f_encrypt,
	time_t const filter_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
	if (fp == NULL)
	{
        /* May be NULL if a reopen fails. */
        goto done;
	}

    dump_aps(fp, ap_list, f_encrypt, filter_seconds, sys_name, loc_name);
    dump_stas(fp, sta_list, filter_seconds, sys_name, loc_name); 

done:
	return;
}

struct wifi_scanner_dump_context_st
{
    FILE * fp;
    char const * filename;
    char const * sys_name;
    char const * location_name;
    time_t filter_seconds;
    int file_reset_seconds;
    time_t last_file_reset;
}; 

static void wifi_context_free(
    struct wifi_scanner_dump_context_st * const wifi_context)
{
    free((void *)wifi_context->filename);
    free((void *)wifi_context->sys_name);
    free((void *)wifi_context->location_name);
    free(wifi_context);
}

static void wifi_scanner_reset_check(
    struct wifi_scanner_dump_context_st * const wifi_context)
{
    time_t const current_time = time(NULL);
    int const time_since_last_reset =
        current_time - wifi_context->last_file_reset;

    if (time_since_last_reset > wifi_context->file_reset_seconds
        && wifi_context->filename != NULL)
    {
        wifi_context->fp = freopen(wifi_context->filename, "w", wifi_context->fp);
        wifi_context->last_file_reset = current_time;
    }
}

static void wifi_scanner_dump(struct dump_context_st * const dump,
                              struct ap_list_head * const ap_list,
                              struct sta_list_head * const sta_list,
                              unsigned int const f_encrypt)
{
    struct wifi_scanner_dump_context_st * const wifi_context = dump->priv;

    dump_write_wifi_scanner(wifi_context->fp,
                            ap_list,
                            sta_list, 
                            f_encrypt, 
                            wifi_context->filter_seconds, 
                            wifi_context->sys_name, 
                            wifi_context->location_name);

    wifi_scanner_reset_check(wifi_context);
}

static void wifi_dump_close(
    struct wifi_scanner_dump_context_st * const wifi_context)
{
    if (wifi_context == NULL)
    {
        goto done;
    }

    if (wifi_context->fp != NULL)
    {
        fclose(wifi_context->fp);
    }

    wifi_context_free(wifi_context);

done:
    return;
}

static void wifi_scanner_close(struct dump_context_st * const dump)
{
    struct wifi_scanner_dump_context_st * const wifi_context = dump->priv;

    wifi_dump_close(wifi_context);

    free(dump);
}

struct wifi_scanner_dump_context_st * wifi_dump_open(
    char const * const filename,
    char const * const sys_name,
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds)
{
    bool had_error;
    struct wifi_scanner_dump_context_st * wifi_context =
        calloc(1, sizeof *wifi_context);

    if (wifi_context == NULL)
    {
        had_error = true;
        goto done;
    }

    wifi_context->fp = fopen(filename, "wb+");
    if (wifi_context->fp == NULL)
    {
        had_error = true;
        goto done;
    }

    wifi_context->file_reset_seconds = file_reset_seconds;
    wifi_context->filter_seconds = filter_seconds;

    wifi_context->filename = strdup(filename);
    ALLEGE(wifi_context->filename != NULL);

    wifi_context->sys_name = strdup(sys_name);
    ALLEGE(wifi_context->sys_name != NULL);

    wifi_context->location_name = strdup(location_name);
    ALLEGE(wifi_context->location_name != NULL);

    had_error = false;

done:
    if (had_error)
    {
        wifi_dump_close(wifi_context);
        wifi_context = NULL;
    }

    return wifi_context;
}

struct dump_context_st * wifi_scanner_dump_open(
    char const * const filename, 
    char const * const sys_name, 
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds)
{
    struct dump_context_st * dump;
    struct wifi_scanner_dump_context_st * const wifi_context = 
        wifi_dump_open(filename, 
                       sys_name, 
                       location_name, 
                       filter_seconds, 
                       file_reset_seconds);

    if (wifi_context == NULL)
    {
        dump = NULL;
        goto done;
    }

    dump = calloc(1, sizeof *dump);
    ALLEGE(dump != NULL);

    dump->priv = wifi_context;
    dump->dump = wifi_scanner_dump;
    dump->close = wifi_scanner_close;
 
done:
    return dump;
}
