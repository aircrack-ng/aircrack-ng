#include "ubus.h"
#include "debug.h"

#include <libubox/blobmsg.h>

#include <string.h>
#include <stdio.h>


struct ubus_context * ubus_ctx;
static const char * ubus_path;
bool connected;

static void
ubus_add_fd(void)
{
    ubus_add_uloop(ubus_ctx);
}


static void
ubus_reconnect_timer(struct uloop_timeout * timeout)
{
    (void)timeout;

    static struct uloop_timeout retry =
    {
        .cb = ubus_reconnect_timer,
    };
    int const t = 2;
    int const timeout_millisecs = t * 1000;

    if (ubus_reconnect(ubus_ctx, ubus_path) != 0)
    {
        DPRINTF("Failed to reconnect, trying again in %d seconds\n", t);
        uloop_timeout_set(&retry, timeout_millisecs);
        return;
    }

    DPRINTF("Reconnected to ubus, new id: %08x\n", ubus_ctx->local_id);
    connected = true;
    ubus_add_fd();
}

static void
ubus_connection_lost(struct ubus_context * ctx)
{
    (void)ctx;
    connected = false;
    DPRINTF("disconnected from ubus\n");
    ubus_reconnect_timer(NULL);
}

struct ubus_context *
ubus_initialise(char const * const path)
{
    ubus_path = path;
    ubus_ctx = ubus_connect(path);

    if (ubus_ctx == NULL) 
    {
        DPRINTF("Failed to connect to ubus on path: %s\n", path);
        goto done;
    }

    DPRINTF("Connected to ubus, new id: %08x\n", ubus_ctx->local_id);
    connected = true;
    ubus_ctx->connection_lost = ubus_connection_lost;

    ubus_add_fd();

done:
    return ubus_ctx;
}

void
ubus_done(void)
{
    if (ubus_ctx != NULL)
    {
        uloop_fd_delete(&ubus_ctx->sock);

        connected = false;
        ubus_free(ubus_ctx);
        ubus_ctx = NULL;
    }
}

