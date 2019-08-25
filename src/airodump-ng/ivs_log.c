#include "ivs_log.h"
#include "aircrack-ng/support/pcap_local.h"

static bool ivs_log_data(
    FILE * const fp,
    mac_address const * const current_bssid,
    mac_address * const previous_bssid,
    uint16_t const data_type,
    void const * const data,
    size_t const data_length,
    void const * const data2,
    size_t const data2_length)
{
    bool success;
    struct ivs2_pkthdr ivs2;

    memset(&ivs2, '\x00', sizeof ivs2);

    ivs2.len = data_length + data2_length;
    ivs2.flags = data_type;

    if (!MAC_ADDRESS_EQUAL(previous_bssid, current_bssid))
    {
        ivs2.flags |= IVS2_BSSID;
        ivs2.len += MAC_ADDRESS_LEN;
        MAC_ADDRESS_COPY(previous_bssid, current_bssid);
    }

    if (fwrite(&ivs2, 1, sizeof ivs2, fp) != sizeof ivs2)
    {
        perror("fwrite IV header failed");
        success = false;
        goto done;
    }

    if (ivs2.flags & IVS2_BSSID)
    {
        if (fwrite(current_bssid, 1, sizeof * current_bssid, fp)
            != sizeof sizeof *current_bssid)
        {
            perror("fwrite BSSID failed");
            success = false;
            goto done;
        }
    }

    if (fwrite(data, 1, data_length, fp) != data_length)
    {
        perror("fwrite IVS2 data failed");
        success = false;
        goto done;
    }

    if (data2 == NULL || data2_length == 0)
    {
        success = true;
        goto done;
    }

    if (fwrite(data2, 1, data2_length, fp) != data2_length)
    {
        perror("fwrite IVS2 data2 failed");
        success = false;
        goto done;
    }

    fflush(fp);

    success = true;

done:
    return success;
}

bool ivs_log_keystream(
    FILE * const fp,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    uint16_t const type,
    void const * const data,
    size_t const data_size,
    void const * const data2,
    size_t const data2_length)
{
    bool success;

    if (fp == NULL)
    {
        /* Not required. */
        success = true;
        goto done;
    }

    if (!ivs_log_data(fp,
                      bssid,
                      previous_bssid,
                      type,
                      data,
                      data_size,
                      data2,
                      data2_length))
    {
        success = false;
        goto done;
    }

    success = true;

done:
    return success;
}

bool ivs_log_wpa_hdsk(
    FILE * const fp,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    void const * const data,
    size_t const data_size)
{
    bool success;

    if (fp == NULL)
    {
        /* Not required. */
        success = true;
        goto done;
    }

    if (!ivs_log_data(fp,
                      bssid,
                      previous_bssid,
                      IVS2_WPA,
                      data,
                      data_size,
                      NULL, 
                      0))
    {
        success = false;
        goto done;
    }

    success = true;

done:
    return success;
}

bool ivs_log_essid(
    FILE * const fp,
    bool * const already_logged,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    void const * const data,
    size_t const data_size)
{
    bool success;

    if (fp == NULL)
    {
        /* Not required. */
        success = true;
        goto done;
    }

    if (*already_logged)
    {
        success = true;
        goto done;
    }

    if (!ivs_log_data(fp,
                      bssid,
                      previous_bssid,
                      IVS2_ESSID,
                      data,
                      data_size,
                      NULL, 
                      0))
    {
        success = false;
        goto done;
    }

    *already_logged = true;
    success = true;

done:
    return success;
}

FILE * ivs_log_open(char const * const filename)
{
    bool success;
    FILE * fp = fopen(filename, "wb+");

    if (fp == NULL)
    {
        perror("fopen failed");
        fprintf(stderr, "Could not create \"%s\".\n", filename);

        success = false;
        goto done;
    }

    char const ivs2_magic[4] = IVS2_MAGIC;

    if (fwrite(ivs2_magic, 1, sizeof ivs2_magic, fp) != sizeof ivs2_magic)
    {
        perror("fwrite(IVs file MAGIC) failed");

        success = false;
        goto done;
    }

    struct ivs2_filehdr fivs2;

    memset(&fivs2, 0, sizeof fivs2);
    fivs2.version = IVS2_VERSION;

    if (fwrite(&fivs2, 1, sizeof(fivs2), fp) != sizeof(fivs2))
    {
        perror("fwrite(IVs file header) failed");

        success = false;
        goto done;
    }

    success = true;

done:
    if (!success && fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }

    return fp;
}
