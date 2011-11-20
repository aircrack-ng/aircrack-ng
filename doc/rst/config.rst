Airoscript-ng configuration file
---------------------------------

Airoscript-ng's config is divided in two files, and some (not all) oiptions are configurable by arguments.
Conffiles are airoscript-ng.conf and airoscript-ng_advanced.conf.

Standard configuration file
===========================

Here, we'll find a couple of sections, defining sets of arrays or variables.

Wordlists
++++++++++

*WORDLIST*
The variable WORDLIST sets the original location of the wordlist that will be used by airoscript to crack WPA or manual dictionary WEP (see crack section).

Note that this file will be copied to DUMP_DIR, so, if you want to use a custom wordlist, AFTER airoscript-ng initialization, you've got to copy it to *DUMP_PATH/WORDLIST_FILE_NAME* having in account that WORDLIST_FILE_NAME contains no directories, is the basename of the WORDLIST variable.

*db_location*
This variable will be passed to aircrack as the PMK database location.

Plugins support
++++++++++++++++

The variable enabled_plugins is just an array of the plugins that will be loaded by default
Actually, those are john the ripper and MDK3

Wireless interfaces
+++++++++++++++++++

You can setup here wifi and iwifi interfaces.
Wifi interface is the standard wifi interface, this will allow you to setup a iwifi interface, it will also make it not ask you to select an interface each time you start airoscript-ng.


Appearance
++++++++++

This configuration section will allow you to make airoscript prettier for you.
Variables:

- *theme* : The theme file, theme files are stored in path/themes/
- *DEFAULT_MONITOR_MODE* : (Bool) start or not monitor mode on selected interface by default.
- *SHOW_SMALL_MENU* : (Bool) Show a small version of all the menus, with just the title, perfect for small screens.
- *show_only_wireless_extensions*: (Bool) Show only interfaces with wireless extensions enabled. If your card is not detected by airoscript, you might set this to 0.
- *Show warning* (Bool) (Currently no effect) Shows an usage warning at startup
- *INTERACTIVE* (Bool): Asks for some more stuffs than usual
- *force_mac_address* (Bool): Do not check for mac address mode.
- *MON_PREFIX* : Prefix to use for airoscript-created virtual interfaces (passed to airmon_ng), this will be used, for example, for interface cleanup.
- *ADDOPTIONS* : HARDCORE: THIS WILL ASK YOU FOR EXTRA OPTIONS FOREACH COMMAND IT EXECUTES.

Advanced configuration file
===========================

Advanced configuration will not be covered here, it's allways changing, and the most remarcable things are aircrack-ng configuration values and debug mode.
