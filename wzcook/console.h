#ifndef _CONSOLE_H
#define _CONSOLE_H

#define BLACK_WHITE        \
    BACKGROUND_INTENSITY | \
    BACKGROUND_BLUE      | \
    BACKGROUND_GREEN     | \
    BACKGROUND_RED

#define BLUE_WHITE         \
    FOREGROUND_BLUE      | \
    BACKGROUND_INTENSITY | \
    BACKGROUND_BLUE      | \
    BACKGROUND_GREEN     | \
    BACKGROUND_RED

#define RED_WHITE          \
    FOREGROUND_RED       | \
    FOREGROUND_INTENSITY | \
    BACKGROUND_INTENSITY | \
    BACKGROUND_BLUE      | \
    BACKGROUND_GREEN     | \
    BACKGROUND_RED

#define TEXTATTR BLACK_WHITE

void set_text_color( int col );
void set_cursor_pos( int x, int y );
void clear_console( int *ws_row, int *ws_col );
void set_console_size( int ws_row, int ws_col );
void set_console_icon( char *title );

#endif /* console.h */
