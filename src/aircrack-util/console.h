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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
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

#define TEXT_RESET	0
#define TEXT_BRIGHT 	1
#define TEXT_DIM	2
#define TEXT_UNDERLINE 	3
#define TEXT_BLINK	4
#define TEXT_REVERSE	7
#define TEXT_HIDDEN	8

#define TEXT_MAX_STYLE	8

#define TEXT_BLACK 	0
#define TEXT_RED	1
#define TEXT_GREEN	2
#define TEXT_YELLOW	3
#define TEXT_BLUE	4
#define TEXT_MAGENTA	5
#define TEXT_CYAN	6
#define	TEXT_WHITE	7

#define TEXT_MAX_COLOR	7

#define KEY_TAB		    0x09	//switch between APs/clients for scrolling
#define KEY_SPACE	    0x20	//pause/resume output
#define KEY_ARROW_UP	0x41	//scroll
#define KEY_ARROW_DOWN	0x42	//scroll
#define KEY_ARROW_RIGHT 0x43	//scroll
#define KEY_ARROW_LEFT	0x44	//scroll
#define KEY_a		    0x61	//cycle through active information (ap/sta/ap+sta/ap+sta+ack)
#define KEY_c		    0x63	//cycle through channels
#define KEY_d		    0x64	//default mode
#define KEY_i		    0x69	//inverse sorting
#define KEY_m		    0x6D	//mark current AP
#define KEY_n		    0x6E	//?
#define KEY_r		    0x72	//realtime sort (de)activate
#define KEY_s		    0x73	//cycle through sorting

void textcolor(int attr, int fg, int bg);
void textcolor_fg(int fg);
void textcolor_bg(int bg);
void textstyle(int attr);
void moveto(int x, int y);
void erase_display(int n);
void hide_cursor(void);
void show_cursor(void);

/// Reset the terminal console display back to a known working state.
void reset_term(void);

/// Wrapper around \a getch to avoid displaying the character on the terminal console.
int mygetch(void);

#endif //AIRCRACK_NG_CONSOLE_H
