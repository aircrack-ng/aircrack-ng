# ===========================================================================
#
# SYNOPSIS
#
#   AX_EXT_HAVE_STATIC_LIB(VARIABLE-PREFIX, SEARCH-PATHS, LIBRARY-NAMES,
#                          FUNCTION-NAME, [EXTRA-LIBRARIES])
#
# DESCRIPTION
#
#   Provides a generic test for locating an appropriate static library
#   to force link against, even when one's application is dynamically
#   linked. The macro was inspired by the PKG_CHECK_MODULES macro.
#
#   If the library is found, [VARIABLE-PREFIX]_FOUND is defined, and
#   in all cases [VARIABLE-PREFIX]_LIBS is substituted.
#
#   Example:
#
#     AX_EXT_HAVE_STATIC_LIB_DETECT
#     AX_EXT_HAVE_STATIC_LIB(ZLIB, [${DEFAULT_STATIC_LIB_SEARCH_PATHS}],
#                            z libz, compress)
#
# LICENSE
#
#   Copyright (c) 2018 Joseph Benden <joe@benden.us>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 1

AC_DEFUN([AX_EXT_HAVE_STATIC_LIB_DETECT],
[
AC_REQUIRE([AC_CANONICAL_HOST])
AC_ARG_VAR([STATIC_HOST_ALIAS], [The alias name for host, default @<:@HOST@:>@.])dnl
AC_ARG_VAR([STATIC_LIBDIR_NAME], [The libdir name for host, default @<:@lib@:>@.])dnl

AC_CACHE_VAL([ext_cv_static_libdir_name], [
	ext_cv_static_libdir_name="${STATIC_LIBDIR_NAME:-lib}"
])

AC_CACHE_VAL([ext_cv_default_static_lib_search_paths], [
	AC_MSG_CHECKING([Default static library search path])

	static_extpath=""
	if test -n "${STATIC_HOST_ALIAS}"
	then
		static_host="${STATIC_HOST_ALIAS}"
	else
		if test "${GCC}" = "yes"
		then
			static_host=`${CC} -dumpmachine 2>/dev/null`
			static_extpath=`${CC} -print-search-dirs 2> /dev/null | grep '^libraries' | sed -e 's/@<:@^=@:>@*=//' -e 's/:/ /g'`
		else
			static_host="${host}"
		fi
	fi

	ext_cv_default_static_lib_search_paths=" \
		${static_extpath} \
		/opt/${ext_cv_static_libdir_name}/${static_host} \
		/opt/${ext_cv_static_libdir_name} \
		/usr/local/${ext_cv_static_libdir_name}/${static_host} \
		/usr/local/${ext_cv_static_libdir_name} \
		/usr/${ext_cv_static_libdir_name}/${static_host} \
		/usr/${ext_cv_static_libdir_name} \
		/${ext_cv_static_libdir_name} \
		/opt/lib/${static_host} \
		/opt/lib \
	"
	AC_MSG_RESULT([${ext_cv_default_static_lib_search_paths}])
])
DEFAULT_STATIC_LIB_SEARCH_PATHS="${ext_cv_default_static_lib_search_paths}"
STATIC_LIBDIR_NAME="${ext_cv_static_libdir_name}"
])

AC_DEFUN([AX_EXT_HAVE_STATIC_LIB],
[
AC_ARG_VAR([$1][_FOUND], [set if the static library $1 is available, already.])dnl
AC_ARG_VAR([$1][_LIBS], [static library linker flags for $1.])dnl

for dir in m4_normalize($2)
do
	ext_haslib_cvdir=`echo $dir | $as_tr_sh`
	ext_haslib_cvname=`echo $3 | $as_tr_sh`

	AC_CACHE_VAL([ext_cv${ext_haslib_cvdir}_haslib_${ext_haslib_cvname}], [
		for name in $3
		do
			dnl Does an archive file exists in our current path?
			AC_CHECK_FILE("${dir}/${name}.a", [
				dnl If so, can we link a simple program with it?

				ext_func_search_save_LIBS=$LIBS
				ext_func_save_ldflags=${LDFLAGS}
				LIBS="${dir}/${name}.a $5 ${ext_func_search_save_LIBS}"
				LDFLAGS="${ext_func_save_ldflags}"

				AC_LINK_IFELSE([AC_LANG_CALL([], [$4])], [
					eval "ext_cv${ext_haslib_cvdir}_haslib_${ext_haslib_cvname}"="${dir}/${name}.a"
					AC_MSG_NOTICE([Found static library: ${dir}/${name}.a])
				], [
					eval "ext_cv${ext_haslib_cvdir}_haslib_${ext_haslib_cvname}"=""
				])

				LIBS=$ext_func_search_save_LIBS
				LDFLAGS=$ext_func_save_ldflags
			])
		done
	])

	if eval `echo 'test x${'ext_cv${ext_haslib_cvdir}_haslib_${ext_haslib_cvname}'}' != "x"`; then
		$1[]_LIBS="`eval echo '\${'ext_cv${ext_haslib_cvdir}_haslib_${ext_haslib_cvname}'}'`"
		$1[]_FOUND=yes
		ext_lib_found="yes"

		AC_SUBST($1[]_LIBS)
		AC_SUBST($1[]_FOUND)
	fi
done
])