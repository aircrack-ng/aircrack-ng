#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/aireplay-ng/csa.h"

#define CHECK(condition)                                                     \
	do                                                                         \
	{                                                                          \
		if (!(condition))                                                       \
		{                                                                      \
			fprintf(stderr, "check failed at %s:%d: %s\n",                    \
					__FILE__,                                                      \
					__LINE__,                                                      \
					#condition);                                                   \
			return (1);                                                          \
		}                                                                      \
	} while (0)

static size_t fill_ie_payload(uint8_t * beacon, size_t payload_len)
{
	size_t written = 0;

	while (written < payload_len)
	{
		size_t remaining = payload_len - written;
		size_t value_len = remaining - 2;
		if (value_len > 255) value_len = 255;

		beacon[36 + written] = 0;
		beacon[36 + written + 1] = (uint8_t) value_len;
		memset(beacon + 36 + written + 2, 0, value_len);
		written += value_len + 2;
	}

	return (written);
}

int main(void)
{
	uint8_t beacon[4096] = {0};
	size_t beacon_len = 36;
	size_t payload_len;
	const uint8_t expected_csa[] = {37, 3, 1, 14, 0};

	CHECK(csa_check_channels(6, 6, 0) == CSA_CHANNEL_MATCH);
	CHECK(csa_check_channels(6, 11, 0) == CSA_CHANNEL_MISMATCH);
	CHECK(csa_check_channels(-1, 6, 0) == CSA_CHANNEL_MISMATCH);
	CHECK(csa_check_channels(-1, 6, 1) == CSA_CHANNEL_UNKNOWN_ALLOWED);

	CHECK(csa_build_beacon(beacon, &beacon_len, 41, 37, 14) == 0);
	CHECK(beacon_len == 41);
	CHECK(memcmp(beacon + 36, expected_csa, sizeof(expected_csa)) == 0);

	memset(beacon, 0, sizeof(beacon));
	beacon[36] = 0;
	beacon[37] = 1;
	beacon[38] = 'a';
	beacon[39] = 37;
	beacon[40] = 3;
	beacon[41] = 0;
	beacon[42] = 6;
	beacon[43] = 1;
	beacon[44] = 221;
	beacon[45] = 1;
	beacon[46] = 0x7f;
	beacon_len = 47;
	CHECK(csa_build_beacon(beacon, &beacon_len, sizeof(beacon), 37, 14) == 0);
	CHECK(beacon_len == 47);
	CHECK(beacon[39] == 221 && beacon[40] == 1 && beacon[41] == 0x7f);
	CHECK(memcmp(beacon + 42, expected_csa, sizeof(expected_csa)) == 0);

	memset(beacon, 0, sizeof(beacon));
	beacon[36] = 0;
	beacon_len = 37;
	CHECK(csa_build_beacon(beacon, &beacon_len, sizeof(beacon), 37, 14) != 0);

	beacon[37] = 2;
	beacon_len = 38;
	CHECK(csa_build_beacon(beacon, &beacon_len, sizeof(beacon), 37, 14) != 0);

	beacon_len = 36;
	CHECK(csa_build_beacon(beacon, &beacon_len, 40, 37, 14) != 0);
	beacon_len = 42;
	CHECK(csa_build_beacon(beacon, &beacon_len, 41, 37, 14) != 0);

	memset(beacon, 0, sizeof(beacon));
	payload_len = fill_ie_payload(beacon, 4055);
	beacon_len = 36 + payload_len;
	CHECK(beacon_len == 4091);
	CHECK(csa_build_beacon(beacon, &beacon_len, sizeof(beacon), 37, 14) == 0);
	CHECK(beacon_len == sizeof(beacon));

	memset(beacon, 0, sizeof(beacon));
	payload_len = fill_ie_payload(beacon, 4060);
	beacon_len = 36 + payload_len;
	CHECK(beacon_len == sizeof(beacon));
	CHECK(csa_build_beacon(beacon, &beacon_len, sizeof(beacon), 37, 14) != 0);

	return (0);
}
