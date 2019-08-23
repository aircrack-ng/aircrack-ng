#ifndef __OUI_H__
#define __OUI_H__

#include <stdint.h>

typedef struct oui_context_st oui_context_st;

oui_context_st * load_oui_file(void);

char *
get_manufacturer_by_oui(
    oui_context_st * const context,
    uint8_t const * const mac);

void oui_context_free(oui_context_st * const context);


#endif

