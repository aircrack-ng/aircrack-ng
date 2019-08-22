#ifndef __UBUS_H__
#define __UBUS_H__

#include <libubus.h>

struct ubus_context * ubus_initialise(char const * const path);

void ubus_done(void);

#endif /* __UBUS_H__ */
