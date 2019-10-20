import os
import sys

class bcolors:
    """
    class for using colored text
    """
    HEADER = '\033[95m' #pink   
    OKBLUE = '\033[94m' #blue   
    OKGREEN = '\033[92m' #green    
    WARNING = '\033[93m' #yellow
    FAIL = '\033[91m'    #red
    ENDC = '\033[0m'    #white

    def disable(self):
        """
        function to disable colored text
        """
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

encoding = sys.getfilesystemencoding()
current_file=""
if hasattr(sys, 'frozen'):
	current_file = sys.executable
else:
	current_file = __file__
if sys.version_info[0] < 3:
	current_file = unicode(current_file, encoding)

install_dir = os.path.abspath(os.path.dirname(current_file))
try:
    os.mkdir(install_dir + "/support")
except:
    pass
