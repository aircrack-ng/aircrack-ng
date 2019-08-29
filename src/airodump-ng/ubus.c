#include "ubus.h"
#include "debug.h"

#include <libubox/blobmsg.h>

#include <string.h>
#include <stdio.h>

struct ubus_state_st
{
    struct ubus_context ubus_ctx;
    char const * ubus_path;
    bool connected;
    struct uloop_timeout retry;
};

struct ubus_state_st ubus_state;

static void
ubus_add_fd(struct ubus_context * const ubus_ctx)
{
    ubus_add_uloop(ubus_ctx);
}

static void
ubus_reconnect_timer(struct uloop_timeout * timeout)
{
    struct ubus_state_st * const state =
        container_of(timeout, struct ubus_state_st, retry);
    int const t = 2;
    int const timeout_millisecs = t * 1000;

    if (ubus_reconnect(&state->ubus_ctx, state->ubus_path) != 0)
    {
        DPRINTF("Failed to reconnect, trying again in %d seconds\n", t);

        timeout->cb = ubus_reconnect_timer;
        uloop_timeout_set(timeout, timeout_millisecs);

        return;
    }

    DPRINTF("Reconnected to ubus, new id: %08x\n", state->ubus_ctx.local_id);

    state->connected = true;
    ubus_add_fd(&state->ubus_ctx);
}

static void
ubus_connection_lost(struct ubus_context * const ctx)
{
    struct ubus_state_st * const state =
        container_of(ctx, struct ubus_state_st, ubus_ctx);

    state->connected = false;
    DPRINTF("disconnected from ubus\n");
    ubus_reconnect_timer(&state->retry);
}

struct ubus_state_st *
ubus_initialise(char const * const path)
{
    struct ubus_state_st * state = &ubus_state;
    bool success;

    state->ubus_path = path;

    if (ubus_connect_ctx(&state->ubus_ctx, path))
    {
        DPRINTF("Failed to connect to ubus on path: %s\n", path);
        success = false;
        goto done;
    }

    DPRINTF("Connected to ubus, new id: %08x\n", state->ubus_ctx.local_id);
    state->connected = true;
    state->ubus_ctx.connection_lost = ubus_connection_lost;

    ubus_add_fd(&state->ubus_ctx);

    success = true;

done:
    if (!success)
    {
        state = NULL;
    }

    return state;
}

void
ubus_done(struct ubus_state_st * const state)
{
    if (state == NULL)
    {
        goto done;
    }

    uloop_timeout_cancel(&state->retry);

    uloop_fd_delete(&state->ubus_ctx.sock);

    state->connected = false;
    ubus_shutdown(&state->ubus_ctx);

done:
    return;
}

void
ubus_state_send_blob_event(
    struct ubus_state_st * const state,
    char const * const event_name,
    struct blob_buf * const b)
{
    ubus_send_event(&state->ubus_ctx, event_name, b->head);
}


