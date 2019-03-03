#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>

#include "aircrack-ng/support/common.h"

int main(int nbarg, char * argv[])
{
#define OUT_LEN 1024
	unsigned char out[OUT_LEN];
	int out_bytes, i;

	if (nbarg != 2)
	{
		printf("Missing parameter\n");
		return 1;
	}

	for (i = 0; i < OUT_LEN; ++i) out[i] = 0;

	out_bytes = hexStringToArray(argv[1], strlen(argv[1]), out, OUT_LEN);
	if (out_bytes == -1)
	{
		printf("Invalid\n");
		return 2;
	}
	else
	{
		printf("Valid (len: %d): ", out_bytes);
	}

	for (i = 0; i < out_bytes; ++i)
	{
		if (i != 0) printf(":");
		printf("%d", out[i]);
	}
	return 0;
}
