#ifndef __UBUS_EVENT_H__
#define __UBUS_EVENT_H__

#include "ap_list.h"
#include "aircrack-ng/osdep/sta_list.h"
#include "ubus.h"

void ubus_send_nodes_event(
    struct ubus_state_st * const state,
    struct ap_list_head const * const ap_list,
    struct sta_list_head const * const sta_list);

#endif /* __UBUS_EVENT_H__ */
