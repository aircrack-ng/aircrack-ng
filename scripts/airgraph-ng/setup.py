#!/usr/bin/env python
# This file is Copyright David Francos Cuartero, licensed under the GPL2 license.

from distutils.core import setup
import os

setup(name='airgraph-ng',
      version='1.1',
      description='Aircrack-ng network grapher',
      author='TheX1le',
      console = [{"script": "airgraph-ng" }],
      url='http://aircrack-ng.org',
      license='GPL2',
      classifiers=[
          'Development Status :: 4 - Beta',
      ],
      packages=['graphviz'],
      scripts=['dump-join', 'airgraph-ng'],
     )
