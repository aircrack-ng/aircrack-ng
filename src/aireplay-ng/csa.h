/*
 *  Copyright (C) 2026 Aircrack-ng contributors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef AIRCRACK_NG_AIREPLAY_CSA_H
#define AIRCRACK_NG_AIREPLAY_CSA_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum
{
	CSA_CHANNEL_MISMATCH = -1,
	CSA_CHANNEL_MATCH = 0,
	CSA_CHANNEL_UNKNOWN_ALLOWED = 1,
};

static int csa_check_channels(int input_channel,
							  int output_channel,
							  int allow_unknown)
{
	if (input_channel == -1 || output_channel == -1)
	{
		if (allow_unknown) return (CSA_CHANNEL_UNKNOWN_ALLOWED);
		return (CSA_CHANNEL_MISMATCH);
	}

	if (input_channel == output_channel) return (CSA_CHANNEL_MATCH);
	return (CSA_CHANNEL_MISMATCH);
}

static int csa_strip_tag(uint8_t * tagged_params,
						 size_t * tp_length,
						 const uint8_t exclude_tag_id)
{
	size_t dst_pos = 0, src_pos = 0;

	if (tagged_params == NULL || tp_length == NULL) return (-1);

	while (src_pos < *tp_length)
	{
		uint8_t cur_tag_id;
		size_t cur_tag_total_len;

		if (*tp_length - src_pos < 2) return (-1);

		cur_tag_id = tagged_params[src_pos];
		cur_tag_total_len = (size_t) tagged_params[src_pos + 1] + 2;
		if (cur_tag_total_len > *tp_length - src_pos) return (-1);

		if (cur_tag_id != exclude_tag_id)
		{
			if (src_pos != dst_pos)
			{
				memmove(tagged_params + dst_pos,
						tagged_params + src_pos,
						cur_tag_total_len);
			}
			dst_pos += cur_tag_total_len;
		}

		src_pos += cur_tag_total_len;
	}

	*tp_length = dst_pos;
	return (0);
}

static int csa_build_beacon(uint8_t * beacon,
							size_t * beacon_len,
							size_t beacon_capacity,
							uint8_t csa_element_id,
							uint8_t channel)
{
	const size_t beacon_header_len = 36;
	const uint8_t csa_ie[] = {csa_element_id, 3, 1, channel, 0};
	size_t tagged_len;

	if (beacon == NULL || beacon_len == NULL) return (-1);
	if (*beacon_len < beacon_header_len || *beacon_len > beacon_capacity)
		return (-1);

	tagged_len = *beacon_len - beacon_header_len;
	if (csa_strip_tag(beacon + beacon_header_len,
				  &tagged_len,
				  csa_element_id)
		!= 0)
	{
		return (-1);
	}

	if (tagged_len > beacon_capacity - beacon_header_len) return (-1);
	if (sizeof(csa_ie) > beacon_capacity - beacon_header_len - tagged_len)
		return (-1);

	memcpy(beacon + beacon_header_len + tagged_len, csa_ie, sizeof(csa_ie));
	*beacon_len = beacon_header_len + tagged_len + sizeof(csa_ie);

	return (0);
}

#endif /* AIRCRACK_NG_AIREPLAY_CSA_H */
