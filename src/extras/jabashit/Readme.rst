About Jabashit
------------
Jabashit is a set of tools and functions designed to improve a terminal 
user's working speed.

To view jabashit documentation, simply execute

::
    source $(source_jabashit); jabashit_api;

Or, if you dare to see a probably outdated version, have a look at doc/API

It also includes a set of nice bash configurations, wich, for using it, 
you'll just have to execute (as normal user), but first, you'll have to get 
bash-powerline, wich has been added to this repo as a submodule.
Bash powerline is a nice bash prompt by milkbikis, with the style of 
vim-powerline, written in python.

::
    git submodule init; git submodule update;

::

    make conf

Then source it in your bashrc:

::

    source ~/.jabashit/bashrc

Don't forget to modify it to fit your needs, there is a ~/.jabashit/config 
file for that purpose.
Also, this enables by default "bash-powerline", wich is provided as 
a submodule, as said before.


Usage examples
---------------

Now my favourite example, a menu creator:

::

    source $(source_jabashit)
    load screen_display TUI
    mkmenu -t "Menu title" -o "Option Foo bar baz"  -f "echo" -o "Option baz 
    stuff" -f "echo"

Now, we serve a directory:

::

    source $(source_jabashit)
    load network
    serve_directory
    # And to stop it...
    stop_serving_directory


All right, what about writing a DIRECTORY to a cd?

::

    source $(source_jabashit)
    load device_utils
    cdtool /dev/cdrom /home/foo/bar
    # And we delete a cdrw
    cdtool erase_dev /dev/cdrom 
    # And what about writing a simple iso image?
    cdtool write_iso /dev/cdrom image.iso
    # And to save a copy of the current cd
    cdtool save /dev/cdrom saved_image.iso

One of my favourites, set all output devices connected to the reso xrandr 
says its its best.

::
    source $(source_jabashit)
    load screen_display
    set_auto_X11_reso


Hell, and I just mentioned half of them, and I've documented just a few!
