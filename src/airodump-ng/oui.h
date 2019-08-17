#ifndef __OUI_H__
#define __OUI_H__

typedef struct oui_context_st oui_context_st;

oui_context_st * load_oui_file(void);

char *
get_manufacturer_by_oui(
    oui_context_st * const context,
    unsigned char const mac0,
    unsigned char const mac1,
    unsigned char const mac2);

void oui_context_free(oui_context_st * const context);


#endif

