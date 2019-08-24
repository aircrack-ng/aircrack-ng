#include "terminal.h"
#include "aircrack-ng/tui/console.h"

void terminal_clear_screen(void)
{
    erase_display(2);
}

void terminal_clear_to_end_of_screen(void)
{
    erase_display(0);
}

void terminal_clear_line_from_cursor_right(void)
{
    erase_line(0);
}

void terminal_move_cursor_down(size_t const num_lines)
{
    move(CURSOR_DOWN, num_lines);
}

void terminal_move_cursor_to(int const col, int const row)
{
    moveto(col, row);
}

void terminal_prepare(void)
{
    hide_cursor();
    terminal_clear_screen();
}

void terminal_restore(void)
{
    textcolor_normal();
    textcolor_fg(TEXT_WHITE);
    reset_term();
    show_cursor();
}

