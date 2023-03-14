#!/bin/bash
#
# Adapted from:
#   https://github.com/baldurk/renderdoc/raw/v1.x/util/clang_format_all.sh
#

CLANG_VERSION=(12 13 14 15)

# Locate the clang-format executable. We try:
#   - the existing value of $CLANG_FORMAT
#   - the first command line argument to the script
#   - in order:
#      clang-format-Maj
#      clang-format

# define a function to check the current $CLANG_FORMAT
valid_clang_format() {
	if which "$CLANG_FORMAT" > /dev/null 2>&1; then
		# we need to make the grep pattern strict because if clang-format was built from source
		# then the version number contains a hash and grep could match numbers from it
		# for example:
		# $ clang-format-12 --version
		# clang-format version 12.0.1 (https://github.com/llvm/llvm-project.git fed41342a82f5a3a9201819a82bf7a48313e296b)
		if $CLANG_FORMAT --version | grep -q "version $1"; then
			echo "Located $CLANG_FORMAT"
			return 0
		fi
	fi

	return 1
}

# Format all source code
format_code() {
	find src -iname '*.h' -a \( ! -path "include/aircrack-ng/third-party/*" -a ! -path "lib/radiotap/*" \) -print0 | \
			xargs -0 -n1 "$CLANG_FORMAT" -i -style=file
	find src -iname '*.cpp' -a \( ! -path "include/aircrack-ng/third-party/*" -a ! -path "lib/radiotap/*" \) -print0 | \
			xargs -0 -n1 "$CLANG_FORMAT" -i -style=file
	find src -iname '*.c' -a \( ! -path "include/aircrack-ng/third-party/*" -a ! -path "lib/radiotap/*" \) -print0 | \
			xargs -0 -n1 "$CLANG_FORMAT" -i -style=file
	$CLANG_FORMAT -i -style=file include/aircrack-ng/third-party/eapol.h
	$CLANG_FORMAT -i -style=file include/aircrack-ng/third-party/hashcat.h
}

if test ! -e configure.ac; then
	echo "Must be at the root of the entire project."
	exit 1
fi;

for clang_version in "${CLANG_VERSION[@]}"; do
	# First try the command line parameter
	CLANG_FORMAT=$1
	if valid_clang_format "$clang_version"; then
		format_code
		exit 0
	fi
done
for clang_version in "${CLANG_VERSION[@]}"; do
	# Then -maj just in case
	CLANG_FORMAT=clang-format-$clang_version
	if valid_clang_format "$clang_version"; then
		format_code
		exit 0
	fi
done
for clang_version in "${CLANG_VERSION[@]}"; do
	# Then finally with no version suffix
	CLANG_FORMAT=clang-format
	if valid_clang_format "$clang_version"; then
		format_code
		exit 0
	fi
done

# We didn't find a valid $CLANG_FORMAT, bail out
echo -n "Couldn't find a correct clang-format version, was looking for "; IFS='/';echo "${CLANG_VERSION[*]}";IFS=$' \t\n'
echo "Aircrack-ng requires a very specific clang-format version to ensure there isn't"
echo "any variance between versions that can happen. You can install it as"
echo -n "'clang-format-"; IFS='/';echo -n "${CLANG_VERSION[*]}";IFS=$' \t\n'; echo "' so that it doesn't interfere with any other"
echo "versions you might have installed, and this script will find it there"
exit 1
