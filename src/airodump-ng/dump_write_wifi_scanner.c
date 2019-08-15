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

static char * format_text_for_csv(const unsigned char * input, size_t len)
{
	// Unix style encoding
	char *ret, *rret;
	size_t i, pos;
	int contains_space_end;
	const char * hex_table = "0123456789ABCDEF";

	if (len == 0 || input == NULL)
	{
		ret = (char *) malloc(1);
		ALLEGE(ret != NULL);
		ret[0] = 0;
		return (ret);
	}

	pos = 0;
	contains_space_end = (input[0] == ' ') || input[len - 1] == ' ';

	// Make sure to have enough memory for all that stuff
	ret = (char *) malloc((len * 4) + 1 + 2);
	ALLEGE(ret != NULL);

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	for (i = 0; i < len; i++)
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
		else if (input[i] == '\n' || input[i] == '\r' || input[i] == '\t')
		{
			ret[pos++]
				= (char) ((input[i] == '\n') ? 'n' : (input[i] == '\t') ? 't'
																		: 'r');
		}
		else
		{
			ret[pos++] = 'x';
			ret[pos++] = hex_table[input[i] / 16];
			ret[pos++] = hex_table[input[i] % 16];
		}
	}

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	ret[pos++] = '\0';

	rret = realloc(ret, pos);

	return (rret) ? (rret) : (ret);
}

static int dump_write_wifi_scanner(
    FILE * const fp,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
	unsigned int const f_encrypt,
	time_t const filter_seconds,
    int const file_reset_seconds,
    char const * const sys_name,
    char const * const loc_name)
{
	struct AP_info * ap_cur;

	if (fp == NULL)
	{
		return 0;
	}

	/* Access Points */
	TAILQ_FOREACH(ap_cur, ap_list, entry)
	{
		if ((time(NULL) - ap_cur->time_printed) < filter_seconds
            && ap_cur->old_channel == ap_cur->channel)
		{
			continue;
		}

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

		ap_cur->time_printed = time(NULL);
		ap_cur->old_channel = ap_cur->channel;

		fprintf(fp, "%s|%s|", sys_name, loc_name);

        fprintf(fp, "%ld|", ap_cur->tinit);
        fprintf(fp, "%ld|", ap_cur->tlast);

        fprintf(fp,
				"%02X:%02X:%02X:%02X:%02X:%02X|",
                ap_cur->bssid.addr[0],
                ap_cur->bssid.addr[1],
                ap_cur->bssid.addr[2],
                ap_cur->bssid.addr[3],
                ap_cur->bssid.addr[4],
                ap_cur->bssid.addr[5]);

        fprintf(fp,                   /*printed twice to maintain output format*/
				"%02X:%02X:%02X:%02X:%02X:%02X|",
                ap_cur->bssid.addr[0],
                ap_cur->bssid.addr[1],
                ap_cur->bssid.addr[2],
                ap_cur->bssid.addr[3],
                ap_cur->bssid.addr[4],
                ap_cur->bssid.addr[5]);


        fprintf(fp, "%2d|", ap_cur->channel);

		if ((ap_cur->ssid_length == 0) || (ap_cur->essid[0] == 0))
		{
            fprintf(fp, "<hidden-ssid>|");
		}
		else
		{
			char * const essid = 
				format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);

			if (essid != NULL)
			{
                fprintf(fp, "%s|", essid);
				free(essid);
			}
			else
			{
                fprintf(fp, "|");
			}
		}

        fprintf(fp, "%3d\r\n", ap_cur->avg_power);
	}

	/*   Process Clients */
    struct ST_info * st_cur;

	TAILQ_FOREACH(st_cur, sta_list, entry)
	{
		ap_cur = st_cur->base;
		if (ap_cur->nb_pkt < 2)
		{
			continue;
		}

		if ((time(NULL) - st_cur->time_printed) < filter_seconds
            && st_cur->old_channel == st_cur->channel)
		{
			continue;
		}
		st_cur->time_printed = time(NULL);
		st_cur->old_channel = st_cur->channel;
        fprintf(fp, "%s|%s|", sys_name, loc_name);
        fprintf(fp, "%ld|", st_cur->tinit);

        fprintf(fp, "%ld|", st_cur->tlast);
        fprintf(fp,
				"%02X:%02X:%02X:%02X:%02X:%02X|",
                st_cur->stmac.addr[0],
                st_cur->stmac.addr[1],
                st_cur->stmac.addr[2],
                st_cur->stmac.addr[3],
                st_cur->stmac.addr[4],
                st_cur->stmac.addr[5]);

		if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
        {
            fprintf(fp,
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    ap_cur->bssid.addr[0],
                    ap_cur->bssid.addr[1],
                    ap_cur->bssid.addr[2],
                    ap_cur->bssid.addr[3],
                    ap_cur->bssid.addr[4],
                    ap_cur->bssid.addr[5]);
        }
        fprintf(fp, "|");
        fprintf(fp, "%2d|", st_cur->channel);

		if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
		{
			if ((ap_cur->ssid_length == 0) || (ap_cur->essid[0] == 0))
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
        fprintf(fp, "|");
        fprintf(fp, "%3d", st_cur->power);
        fprintf(fp, "\r\n");
	}

    fflush(fp);

	return 0;
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
    free((void *) wifi_context->sys_name);
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
                            wifi_context->file_reset_seconds, 
                            wifi_context->sys_name, 
                            wifi_context->location_name);

    wifi_scanner_reset_check(wifi_context);
}

static void wifi_scanner_close(struct dump_context_st * const dump)
{
    struct wifi_scanner_dump_context_st * const wifi_context = dump->priv;

    if (wifi_context->fp != NULL)
    {
        fclose(wifi_context->fp);
    }

    wifi_context_free(wifi_context);

    free(dump);
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
        calloc(1, sizeof *wifi_context);
    ALLEGE(wifi_context != NULL);

    wifi_context->fp = fopen(filename, "wb+"); 
    if (wifi_context->fp == NULL)
    {
        wifi_context_free(wifi_context);
        dump = NULL;

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

    dump = calloc(1, sizeof *dump);
    ALLEGE(dump != NULL);

    dump->priv = wifi_context;
    dump->dump = wifi_scanner_dump;
    dump->close = wifi_scanner_close;
 
done:
    return dump;
}
