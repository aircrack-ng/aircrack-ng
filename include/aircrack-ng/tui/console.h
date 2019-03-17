/*
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef AIRCRACK_NG_CONSOLE_H
#define AIRCRACK_NG_CONSOLE_H

/**
 * Styling attributes for \a textstyle function.
 */
#define TEXT_RESET 0
#define TEXT_BRIGHT 1
#define TEXT_DIM 2
#define TEXT_UNDERLINE 3
#define TEXT_BLINK 4
#define TEXT_REVERSE 7
#define TEXT_HIDDEN 8
#define TEXT_MAX_STYLE 8

/**
 * Color definitions for \a textcolor functions.
 */
#define TEXT_BLACK 0
#define TEXT_RED 1
#define TEXT_GREEN 2
#define TEXT_YELLOW 3
#define TEXT_BLUE 4
#define TEXT_MAGENTA 5
#define TEXT_CYAN 6
#define TEXT_WHITE 7
#define TEXT_MAX_COLOR 7

/**
 * Movement direction definitions for \a move function.
 */
#define CURSOR_UP 0
#define CURSOR_DOWN 1
#define CURSOR_FORWARD 2
#define CURSOR_BACK 3

/**
 * Character codes for common keyboard keys.
 */
#define KEY_TAB 0x09
#define KEY_ESCAPE 0x1B
#define KEY_SPACE 0x20
#define KEY_ARROW_UP 0x41
#define KEY_ARROW_DOWN 0x42
#define KEY_ARROW_RIGHT 0x43
#define KEY_ARROW_LEFT 0x44
#define KEY_a 0x61
#define KEY_c 0x63
#define KEY_d 0x64
#define KEY_i 0x69
#define KEY_m 0x6D
#define KEY_n 0x6E
#define KEY_q 0x71
#define KEY_r 0x72
#define KEY_s 0x73
#define KEY_o 0x6F //color on
#define KEY_p 0x70 //color off

/// Changes the styling, foreground, and background
/// character color, as shown in the user's terminal
/// console.
void textcolor(int attr, int fg, int bg);

/// Changes the foreground character color, as shown in the
/// user's terminal console.
void textcolor_fg(int fg);

/// Changes the background character color, as shown in the
/// user's terminal console.
void textcolor_bg(int bg);

/// Switch to normal color or intensity, as shown in the
/// user's terminal console.
void textcolor_normal(void);

/// Switches the styling applied to future written characters to
/// the user's terminal console.
void textstyle(int attr);

/// Moves the cursor to specified column and row, 1-based.
void moveto(int x, int y);

/// Move the cursor a specified number of positions, in the specified
/// direction.
void move(int which, int n);

/// \brief Erase a subset of the terminal console.
/**
 * From Wikipedia:
 *
 * Clears part of the screen. If n {\displaystyle n} n is 0 (or missing),
 * clear from cursor to end of screen. If n {\displaystyle n} n is 1,
 * clear from cursor to beginning of the screen. If n {\displaystyle n} n
 * is 2, clear entire screen (and moves cursor to upper left on DOS
 * ANSI.SYS). If n {\displaystyle n} n is 3, clear entire screen and
 * delete all lines saved in the scrollback buffer (this feature was
 * added for xterm and is supported by other terminal applications).
 */
void erase_display(int n);

/// \brief Erase part of the line; of the user's terminal console.
void erase_line(int n);

/// Hide the cursor within the terminal console.
void hide_cursor(void);

/// Show the cursor within the terminal console.
void show_cursor(void);

/// Reset the terminal console display back to a known working state.
void reset_term(void);

/// Wrapper around \a getch to avoid displaying the character on the terminal
/// console.
int mygetch(void);

void console_utf8_enable(void);

static inline void console_puts(const char * msg)
{
	printf("%s", msg);
	erase_line(0);
	putchar('\n');
}

#endif // AIRCRACK_NG_CONSOLE_H
