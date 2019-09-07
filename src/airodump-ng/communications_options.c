#include "aircrack-ng/support/communications.h"

/* Yuk. Needed to get the program to link. The communications 
 * library file expects to see a global variable with this 
 * name. 
 */

struct communication_options opt;
