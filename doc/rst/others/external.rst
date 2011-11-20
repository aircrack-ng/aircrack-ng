External plugins
=================
Here, plugins enabled in config or startup parameters will have its menus.
Each plugin gets itself into menu by adding its menu entry directly to ${plugins_menu} array, this way:

:: 
    
    plugins_menu+=("This is the menu entry");


And then creating a function, composed by the menu name, replacing spaces by underscores.

::
    This_is_the_menu_entry(){

        # Here do stuff

    }

For more info on plugin creation you can have a look at the manual page.
