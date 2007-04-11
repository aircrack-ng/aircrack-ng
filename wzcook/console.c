#include <windows.h>

#include "console.h"
#include "resource.h"

COORD dwPos;
HANDLE hOutput = NULL;
CONSOLE_SCREEN_BUFFER_INFO csbi;

void set_text_color( int col )
{
    if( hOutput == NULL )
        hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

    SetConsoleTextAttribute( hOutput, (WORD) col );
}

void set_cursor_pos( int x, int y )
{
    if( hOutput == NULL )
        hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

    dwPos.X = x;
    dwPos.Y = y;

    SetConsoleCursorPosition( hOutput, dwPos );
}

void clear_console( int *ws_row, int *ws_col )
{
    int n, length;

    if( hOutput == NULL )
        hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

    SetConsoleTextAttribute( hOutput, TEXTATTR );
    GetConsoleScreenBufferInfo( hOutput, &csbi );

    if( ws_row != NULL ) *ws_row = csbi.dwSize.Y;
    if( ws_col != NULL ) *ws_col = csbi.dwSize.X;

    length = ( csbi.dwSize.Y - csbi.dwCursorPosition.Y )
           * ( csbi.dwSize.X - csbi.dwCursorPosition.X );

    dwPos.X = csbi.dwCursorPosition.X;
    dwPos.Y = csbi.dwCursorPosition.Y;

    FillConsoleOutputAttribute( hOutput, TEXTATTR, length, dwPos, &n );
    FillConsoleOutputCharacter( hOutput, 0x20,     length, dwPos, &n );
}

void set_console_size( int ws_row, int ws_col )
{
    if( hOutput == NULL )
        hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

    GetConsoleScreenBufferInfo( hOutput, &csbi );

    csbi.dwSize.Y = ws_row;
    csbi.dwSize.X = ws_col;

    SetConsoleScreenBufferSize( hOutput, csbi.dwSize );

    csbi.srWindow.Left      = 1;
    csbi.srWindow.Top       = 1;
    csbi.srWindow.Right     = ws_col;
    csbi.srWindow.Bottom    = ws_row;

    SetConsoleWindowInfo( hOutput, TRUE, &csbi.srWindow );;

    set_cursor_pos( 0, 0 );
    clear_console( NULL, NULL );
}

void set_console_icon( char *title )
{
    HANDLE hWnd;
    HANDLE hInst;
    HICON hAppIcon;

    SetConsoleTitle( title );
    hWnd = FindWindow( NULL, title );
    hInst = GetModuleHandle( NULL );
    hAppIcon = LoadIcon( hInst, MAKEINTRESOURCE( IDI_APP_ICON ) );
    SendMessage( hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hAppIcon );
    SendMessage( hWnd, WM_SETICON, ICON_BIG  , (LPARAM) hAppIcon );
}