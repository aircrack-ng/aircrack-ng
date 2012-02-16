#!/usr/bin/env python
# This file is Copyright David Francos Cuartero, licensed under the GPL2 license.

from distutils.core import setup
import os

setup(name='airdrop-ng',
      version='1.1',
      description='Rule based Deauth Tool',
      author='TheX1le',
      console = [{"script": "airdrop-ng" }],
      url='http://aircrack-ng.org',
      license='GPL2',
      classifiers=[ 'Development Status :: 4 - Beta', ],
      packages=['airdrop'],
      scripts=['airdrop-ng'],
     )
