dnl Aircrack-ng
dnl
dnl Copyright (C) 2018 Joseph Benden <joe@benden.us>
dnl
dnl Autotool support was written by: Joseph Benden <joe@benden.us>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
dnl
dnl In addition, as a special exception, the copyright holders give
dnl permission to link the code of portions of this program with the
dnl OpenSSL library under certain conditions as described in each
dnl individual source file, and distribute linked combinations
dnl including the two.
dnl
dnl You must obey the GNU General Public License in all respects
dnl for all of the code used other than OpenSSL.
dnl
dnl If you modify file(s) with this exception, you may extend this
dnl exception to your dnl version of the file(s), but you are not obligated
dnl to do so.
dnl
dnl If you dnl do not wish to do so, delete this exception statement from your
dnl version.
dnl
dnl If you delete this exception statement from all source files in the
dnl program, then also delete it here.

AC_DEFUN([AIRCRACK_NG_PTHREAD], [

AX_PTHREAD([
    AC_CHECK_LIB([pthread], [pthread_create], [ PTHREAD_LIBS="-lpthread" ])
    dnl AC_DEFINE([_REENTRANT], [], [Define this if your library functions are re-entrant])
])

AC_MSG_CHECKING([for pthread_setaffinity_np])
AS_VAR_PUSHDEF([FLAGS],[_AC_LANG_PREFIX[]FLAGS])dnl
ac_save_[]FLAGS="$[]FLAGS"
ac_save_LDFLAGS="$LDFLAGS"
FLAGS="$ac_save_[]FLAGS -pthread"
LDFLAGS="$LDFLAGS $PTHREAD_LIBS -pthread"
# Check for pthread_{,attr_}[sg]etaffinity_np.
AC_LINK_IFELSE([
	AC_LANG_PROGRAM([
		#define _GNU_SOURCE
   		#include <pthread.h>
   	], [
   		cpu_set_t cpuset;
   		pthread_attr_t attr;
   		pthread_getaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
   		if (CPU_ISSET (0, &cpuset))
     		CPU_SET (1, &cpuset);
   		else
     		CPU_ZERO (&cpuset);
   		pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
   		pthread_attr_init (&attr);
   		pthread_attr_getaffinity_np (&attr, sizeof (cpu_set_t), &cpuset);
   		pthread_attr_setaffinity_np (&attr, sizeof (cpu_set_t), &cpuset);
   	])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_PTHREAD_AFFINITY_NP, 1,
		[Define if pthread_{,attr_}{g,s}etaffinity_np is supported.])
], [
	AC_MSG_RESULT([no])
])
LDFLAGS="$ac_save_LDFLAGS"
FLAGS="$ac_save_[]FLAGS"
AS_VAR_POPDEF([FLAGS])dnl

])