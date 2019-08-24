#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include <stddef.h>

void terminal_prepare(void);

void terminal_restore(void);

void terminal_clear_screen(void);

void terminal_clear_to_end_of_screen(void);

void terminal_clear_line_from_cursor_right(void);

void terminal_move_cursor_down(size_t const num_lines);

void terminal_move_cursor_to(int const col, int const row);


#endif /* __TERMINAL_H__ */
