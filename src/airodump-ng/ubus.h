#ifndef __UBUS_H__
#define __UBUS_H__

#include <libubus.h>

struct ubus_state_st;

struct ubus_state_st * ubus_initialise(char const * const path);

void ubus_done(struct ubus_state_st * const state);

void
ubus_state_send_blob_event(
    struct ubus_state_st * const state,
    char const * const event_name,
    struct blob_buf * const b);

#endif /* __UBUS_H__ */
