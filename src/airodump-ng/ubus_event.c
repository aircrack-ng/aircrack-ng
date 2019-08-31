#include "ubus_event.h"

static char const access_points[] = "access points";
static char const stations[] = "stations";
static char const first_seen[] = "first seen";
static char const last_seen[] = "last seen";
static char const bssid[] = "bssid";
static char const essid[] = "essid";
static char const channel[] = "channel";
static char const power[] = "power";
static char const station_mac[] = "station MAC";
static char const event_id[] = "wifi_scanner.nodes";

static void append_ap_node_to_blob(
    struct AP_info const * const ap_cur,
    struct blob_buf * const b)
{
    char mac_buffer[MAX_MAC_ADDRESS_STRING_SIZE];

    void * const ap_cookie = blobmsg_open_table(b, NULL);

    blobmsg_add_u64(b, first_seen, ap_cur->tinit);
    blobmsg_add_u64(b, last_seen, ap_cur->tlast);
    blobmsg_add_u16(b, channel, ap_cur->channel);
    blobmsg_add_double(b, power, ap_cur->avg_power);
    blobmsg_add_string(b, essid, (char *)ap_cur->essid);
    blobmsg_add_string(b, bssid, mac_address_format(&ap_cur->bssid,
                                                    mac_buffer,
                                                    sizeof mac_buffer));

    blobmsg_close_table(b, ap_cookie);
}

static void append_ap_nodes_to_blob(
    struct ap_list_head const * const ap_list,
    struct blob_buf * const b)
{
    struct AP_info const * ap_cur;
    void * const cookie = blobmsg_open_array(b, access_points);

    TAILQ_FOREACH(ap_cur, ap_list, entry)
    {
        append_ap_node_to_blob(ap_cur, b);
    }

    blobmsg_close_array(b, cookie);
}

static void append_sta_node_to_blob(
    struct ST_info const * const st_cur,
    struct blob_buf * const b)
{
    char mac_buffer[MAX_MAC_ADDRESS_STRING_SIZE];
    void * const sta_cookie = blobmsg_open_table(b, NULL);

    blobmsg_add_u64(b, first_seen, st_cur->tinit);
    blobmsg_add_u64(b, last_seen, st_cur->tlast);
    blobmsg_add_u16(b, channel, st_cur->channel);
    blobmsg_add_double(b, power, st_cur->power);

    struct AP_info const * const ap_cur = st_cur->base;

    blobmsg_add_string(b, essid, (char *)ap_cur->essid);
    blobmsg_add_string(b, bssid, mac_address_format(&ap_cur->bssid,
                                                    mac_buffer,
                                                    sizeof mac_buffer));

    blobmsg_add_string(b, station_mac, mac_address_format(&st_cur->stmac,
                                                          mac_buffer,
                                                          sizeof mac_buffer));

    blobmsg_close_table(b, sta_cookie);
}

static void append_sta_nodes_to_blob(
    struct sta_list_head const * const sta_list,
    struct blob_buf * const b)
{
    void * const cookie = blobmsg_open_array(b, stations);
    struct ST_info const * st_cur;

    TAILQ_FOREACH(st_cur, sta_list, entry)
    {
        append_sta_node_to_blob(st_cur, b);
    }

    blobmsg_close_array(b, cookie);
}

void ubus_send_nodes_event(
    struct ubus_state_st * state,
    struct ap_list_head const * const ap_list,
    struct sta_list_head const * const sta_list)
{
    struct blob_buf b;

    memset(&b, 0, sizeof b);
	blob_buf_init(&b, 0);

    append_ap_nodes_to_blob(ap_list, &b);
    append_sta_nodes_to_blob(sta_list, &b);

    ubus_state_send_blob_event(state, event_id, &b);

    blob_buf_free(&b);
}

