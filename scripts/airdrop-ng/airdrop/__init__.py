import os, sys

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
        fucntion to disable colored text
        """
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

encoding = sys.getfilesystemencoding()
if hasattr(sys, 'frozen'):
    install_dir = os.path.abspath(os.path.dirname(unicode(sys.executable, encoding)))
install_dir = os.path.abspath(os.path.dirname(unicode(__file__, encoding)))
try:
    os.mkdir(install_dir + "/support")
except:
    pass
