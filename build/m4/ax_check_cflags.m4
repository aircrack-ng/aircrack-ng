AC_DEFUN([AX_CHECK_CFLAGS],
[
  AC_MSG_CHECKING([whether compiler accepts "$1"])
  cat > conftest.c++ << EOF
  int main(){
    return 0;
  }
EOF
  if $CC $CPPFLAGS $CFLAGS -o conftest.o conftest.c++ [$1] > /dev/null 2>&1
  then
    AC_MSG_RESULT([yes])
    CFLAGS="${CFLAGS} [$1]"
    [$2]
  else
    AC_MSG_RESULT([no])
   [$3]
  fi
])dnl AX_CHECK_CFLAGS

