#include "oui.h"
#include "aircrack-ng/osdep/queue.h"
#include "aircrack-ng/support/common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_RAM_SIZE_LOAD_OUI_RAM 32768

#define OUI_ID_SIZE 3

struct oui
{
    TAILQ_ENTRY(oui) entry;

    uint8_t id[OUI_ID_SIZE];
    char * manufacturer;
};

TAILQ_HEAD(oui_list_head, oui);

struct oui_context_st
{
    bool have_loaded_list;
    struct oui_list_head list_head;
};

static char const unknown_manufacturer[] = "Unknown";

static char const * const OUI_PATHS[] = 
{ 
    "./airodump-ng-oui.txt",
    "/etc/aircrack-ng/airodump-ng-oui.txt",
    "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
    "/usr/share/aircrack-ng/airodump-ng-oui.txt",
    "/var/lib/misc/oui.txt",
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/etc/manuf/oui.txt",
    "/usr/share/wireshark/wireshark/manuf/oui.txt",
    "/usr/share/wireshark/manuf/oui.txt",
    NULL 
};

static FILE * open_oui_file(void)
{
    FILE * fp = NULL;

    for (size_t i = 0; OUI_PATHS[i] != NULL; i++)
    {
        fp = fopen(OUI_PATHS[i], "r");
        if (fp != NULL)
        {
            break;
        }
    }

    return fp;
}

static void oui_free(struct oui * const oui)
{
    free(oui->manufacturer);
    free(oui);
}

static void oui_list_free(struct oui_list_head * const list)
{
    struct oui * oui;
    struct oui * oui_tmp; 

    TAILQ_FOREACH_SAFE(oui, list, entry, oui_tmp)
    {
        TAILQ_REMOVE(list, oui, entry);

        oui_free(oui);
    }
}

static void strip_eol(char * const buffer)
{
    size_t len;
    char * last_char;

    len = strlen(buffer);
    if (len == 0)
    {
        goto done;
    }
    last_char = &buffer[len - 1];
    if (*last_char == '\n' || *last_char == '\r')
    {
        *last_char = '\0';
    }

    len = strlen(buffer);
    if (len == 0)
    {
        goto done;
    }
    last_char = &buffer[len - 1];
    if (*last_char == '\n' || *last_char == '\r')
    {
        *last_char = '\0';
    }

done:
    return;
}

static char * get_manufacturer_from_string(char * const buffer)
{
    char * manuf = NULL;
    char * buffer_manuf;

    if (buffer == NULL || strlen(buffer) == 0)
    {
        goto done;
    }
    static char const hex_field[] = "(hex)";

    buffer_manuf = strstr(buffer, hex_field);

    if (buffer_manuf == NULL)
    {
        goto done;
    }
    buffer_manuf += strlen(hex_field);
    while (*buffer_manuf == '\t' || *buffer_manuf == ' ')
    {
        ++buffer_manuf;
    }

    // Did we stop at the manufacturer
    if (*buffer_manuf == '\0')
    {
        goto done;
    }
    // First make sure there's no end of line
    strip_eol(buffer_manuf);

    if (*buffer_manuf == '\0')
    {
        goto done;
    }

    manuf = strdup(buffer_manuf);

done:
    return manuf;
}

static void oui_initialise(
    struct oui * const oui, 
    char * const manufacturer, 
    uint8_t const a, 
    uint8_t const b, 
    uint8_t const c)
{
    oui->manufacturer = manufacturer;

    if (oui->manufacturer == NULL)
    {
        oui->manufacturer = strdup(unknown_manufacturer);
    }

    oui->id[0] = a;
    oui->id[1] = b;
    oui->id[3] = c;
}

oui_context_st * load_oui_file(void)
{
    oui_context_st * context = calloc(1, sizeof *context);
    FILE * fp = NULL; 

    if (context == NULL)
    {
        goto done;
    }

    TAILQ_INIT(&context->list_head);
    context->have_loaded_list = false;

    /* fill oui struct if ram is greater than 32 MB */
    if (get_ram_size() < MIN_RAM_SIZE_LOAD_OUI_RAM)
    {
        goto done;
    }

    char buffer[BUFSIZ];

    fp = open_oui_file();
    if (fp == NULL)
    {
        goto done;
    }

    context->have_loaded_list = true;

    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        unsigned int a;
        unsigned int b;
        unsigned int c; 

        if (strstr(buffer, "(hex)") == NULL)
        {
            continue;
        }

        if (sscanf(buffer, "%2x-%2x-%2x", &a, &b, &c) == 3)
        {
            struct oui * const oui = calloc(1, sizeof *oui);

            if (oui == NULL)
            {
                oui_list_free(&context->list_head);
                context->have_loaded_list = false;
                perror("oui_alloc failed");

                goto done;
            }

            oui_initialise(oui, 
                           get_manufacturer_from_string(buffer), 
                           a, 
                           b, 
                           c);

            TAILQ_INSERT_TAIL(&context->list_head, oui, entry);
        }
    }

done:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return context;
}

void oui_context_free(oui_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    oui_list_free(&context->list_head);
    free(context);

done:
    return;
}

static struct oui * oui_lookup(
    struct oui_list_head * const list, 
    uint8_t const * const id)
{
    struct oui * oui;

    /* A hash table might be better than a linked list in this 
     * case. This list could get quite long, so a hash table 
     * could speed lookups quite a bit. 
     */
    TAILQ_FOREACH(oui, list, entry)
    {
        bool const found = memcmp(oui->id, id, sizeof oui->id) == 0;

        if (found)
        {
            goto done;
        }
    }

done:
    return oui;
}

char *
get_manufacturer_by_oui(
    oui_context_st * const context,
    uint8_t const * const mac)
{
    char * manuf;
    FILE * fp = NULL;

    if (context != NULL && context->have_loaded_list)
    {
        // Search in the list
        struct oui const * const ptr = oui_lookup(&context->list_head, mac);

        if (ptr != NULL)
        {
            manuf = strdup(ptr->manufacturer);
        }
        else
        {
            manuf = NULL;
        }

        goto done;
    }
    else
    {
        // If the file exist, then query it each time we need to get a
        // manufacturer.
        fp = open_oui_file();

        if (fp == NULL)
        {
            manuf = NULL;

            goto done;
        }

        char buffer[BUFSIZ];

        while (fgets(buffer, sizeof(buffer), fp) != NULL)
        {
            /* TODO: Remove this duplicated code. 
             * The same code is in load_oui_file(). 
             */

            if (strstr(buffer, "(hex)") == NULL)
            {
                continue;
            }

            unsigned int a;
            unsigned int b;
            unsigned int c;

            if (sscanf(buffer, "%2x-%2x-%2x", &a, &b, &c) == 3)
            {
                uint8_t const id[OUI_ID_SIZE] = {a, b, c};
                bool const found = memcmp(id, mac, sizeof id) == 0;

                if (found)
                {
                    manuf = get_manufacturer_from_string(buffer);

                    goto done;
                }
            }
        }
    }

    manuf = NULL;

done:
    if (manuf == NULL)
    {
        // Not found.
        manuf = strdup(unknown_manufacturer);
        ALLEGE(manuf != NULL);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    return manuf;
}

