#!/usr/bin/env python
# This file is Copyright David Francos Cuartero, licensed under the GPL2 license.

from distutils.core import setup

setup(name='airdrop-ng',
      version='1.1',
      description='Rule based Deauth Tool',
      author='TheX1le',
      console = [{"script": "airdrop-ng" }],
      url='https://aircrack-ng.org',
      license='GPL2',
      classifiers=[ 'Development Status :: 4 - Beta', ],
      packages=['airdrop'],
      scripts=['airdrop-ng'],
     )
