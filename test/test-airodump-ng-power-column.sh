#!/bin/sh

set -eu

source_file=${1:-src/airodump-ng/airodump-ng.c}

assert_source_contains() {
	if ! grep -F "$1" "${source_file}" > /dev/null; then
		printf 'missing expected power-column format: %s\n' "$1" >&2
		exit 1
	fi
}

assert_source_contains '"  %4d %3d %8lu %8lu %4d"'
assert_source_contains '"  %4d %8lu %8lu %4d"'
assert_source_contains 'printf("  %4d ", st_cur->power);'
assert_source_contains 'printf(" %4d", na_cur->power);'

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

cat > "${tmpdir}/power-column.c" <<'EOF'
#include <stdio.h>
#include <string.h>

int main(void)
{
	const int powers[] = {9, -1, -99, -100, -127};
	size_t i;

	for (i = 0; i < sizeof(powers) / sizeof(powers[0]); i++)
	{
		char row[32];
		char * separator;

		snprintf(row, sizeof(row), "  %4d |NEXT", powers[i]);
		separator = strchr(row, '|');
		if (separator == NULL || separator - row != 7)
		{
			fprintf(stderr, "misaligned power row: %s\n", row);
			return 1;
		}
	}

	return 0;
}
EOF

"${CC:-cc}" -Wall -Wextra -Werror -o "${tmpdir}/power-column" \
	"${tmpdir}/power-column.c"
"${tmpdir}/power-column"

printf 'airodump-ng power column regression test: ok\n'
