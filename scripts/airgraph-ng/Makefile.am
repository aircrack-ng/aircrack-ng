# Aircrack-ng
#
# Copyright (C) 2017 Joseph Benden <joe@benden.us>
#
# Autotool support was written by: Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
#
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.
#
# If you modify file(s) with this exception, you may extend this
# exception to your dnl version of the file(s), but you are not obligated
# to do so.
#
# If you dnl do not wish to do so, delete this exception statement from your
# version.
#
# If you delete this exception statement from all source files in the
# program, then also delete it here.

SUBDIRS = man

all-local:
	( cd $(srcdir) && $(PYTHON) setup.py build \
		--build-base $(shell $(READLINK) -f $(builddir))/build \
		--verbose )

install-exec-local:
	( cd $(srcdir) && $(MKDIR_P) $(DESTDIR)$(pkgpythondir) && \
		$(PYTHON) $(srcdir)/setup.py install \
			--prefix $(DESTDIR)$(prefix) \
			--record $(DESTDIR)$(pkgpythondir)/airgraph-ng-install_files.txt \
			--verbose )

uninstall-local:
	cat $(DESTDIR)$(pkgpythondir)/airgraph-ng-install_files.txt | xargs rm -rf
	rm -rf $(DESTDIR)$(pkgpythondir)/airgraph-ng-install_files.txt
	rmdir $(DESTDIR)$(pkgpythondir) || :

clean-local:
	rm -fr $(shell $(READLINK) -f $(builddir))/build

EXTRA_DIST = airgraph-ng \
			 dump-join \
			 lib \
			 setup.py \
			 graphviz \
			 README \
			 test


@CODE_COVERAGE_RULES@
