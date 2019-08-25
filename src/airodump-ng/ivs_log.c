#include "ivs_log.h"
#include "aircrack-ng/support/pcap_local.h"

static bool ivs_log_data(
    FILE * const fp,
    mac_address const * const current_bssid,
    mac_address * const previous_bssid,
    uint16_t const data_type,
    void const * const data,
    size_t const data_length)
{
    bool success;
    struct ivs2_pkthdr ivs2;

    memset(&ivs2, '\x00', sizeof ivs2);
    ivs2.flags = 0;

    ivs2.len = data_length;
    ivs2.flags |= data_type;

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
                      data_size))
    {
        success = false;
        goto done;
    }

    success = true;

done:
    return success;
}

bool ivs_log_essid(
    bool * const already_logged,
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
                      data_size))
    {
        success = false;
        goto done;
    }

    *already_logged = true;
    success = true;

done:
    return success;
}

