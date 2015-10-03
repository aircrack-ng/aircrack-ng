#! /bin/bash

HEX_FAILING=('F' 'A' 'a' '1' '9' 'G' 'AG' '9U' 'aO' 'FF:FF:FF:AS' 'BLAH')
HEX_SUCCESS=('FF' 'AA' 'aa' '11' '22' 'FF:AA:FF' 'C0:FF:EE:' '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF')

./test-hex_string_to_array >/dev/null 2>/dev/null
RET=$?
if [ ${RET} -ne 1 ]; then
	"Hex string test fail. Expected return value of 1 (missing parameter), got ${RET} with no parameter."
	exit 1
fi
echo "Test Hex string to array with empty string: failure - Test successful"

for failure in ${HEX_FAILING[@]}
do
	./test-hex_string_to_array "${failure}" >/dev/null 2>/dev/null
	RET=$?
	if [ ${RET} -ne 2 ]; then
		echo "Hex string failed. Expected return value of 2 (failure), got ${RET} with ${failure}."
		exit 1
	fi
	echo "Test Hex string to array with ${failure}: failure - Test successful"
done

for success in ${HEX_SUCCESS[@]}
do
	./test-hex_string_to_array "${success}" >/dev/null 2>/dev/null
	RET=$?
	if [ ${RET} -ne 0 ]; then
		echo "Hex string test failed. Expected return value of 0 (success), got ${RET} with ${success}"
		exit 1
	fi
	echo "Test Hex string to array with ${success}: success - Test successful"
done

echo "Hex string tests successful."
exit 0
