#!/usr/bin/env python
"""
Python module for adding colors to print statements
"""
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

