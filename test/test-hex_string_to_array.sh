#! /bin/sh

./test-hex_string_to_array >/dev/null 2>/dev/null
RET=$?
if [ ${RET} -ne 1 ]; then
	"Hex string test fail. Expected return value of 1 (missing parameter), got ${RET} with no parameter."
	exit 1
fi
echo "Test Hex string to array with empty string: failure - Test successful"

hex_failing_test() {
	./test-hex_string_to_array "${1}" >/dev/null 2>/dev/null
	RET=$?
	if [ ${RET} -ne 2 ]; then
	echo "Hex string failed. Expected return value of 2 (failure), got ${RET} with ${failure}."
		exit 1
	fi
	echo "Test Hex string to array with ${failure}: failure - Test successful"
}

# sh does not support arrays, so we have to do it this way
hex_failing_test 'F'
hex_failing_test 'A'
hex_failing_test 'a'
hex_failing_test '1'
hex_failing_test '9'
hex_failing_test 'G'
hex_failing_test 'AG'
hex_failing_test '9U'
hex_failing_test 'aO'
hex_failing_test 'FF:FF:FF:AS'
hex_failing_test 'BLAH'


hex_success_test() {
	./test-hex_string_to_array "${1}" >/dev/null 2>/dev/null
	RET=$?
	if [ ${RET} -ne 0 ]; then
		echo "Hex string test failed. Expected return value of 0 (success), got ${RET} with ${success}"
		exit 1
	fi
	echo "Test Hex string to array with ${success}: success - Test successful"
}

hex_success_test 'FF'
hex_success_test 'AA'
hex_success_test 'aa'
hex_success_test '11'
hex_success_test '22'
hex_success_test 'FF:AA:FF'
hex_success_test 'C0:FF:EE:'
hex_success_test '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF'

echo "Hex string tests successful."
exit 0
