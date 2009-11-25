#define _BSD_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <endian.h>
#include <errno.h>
#include "radiotap_iter.h"

int main(int argc, char *argv[])
{
	struct ieee80211_radiotap_iterator iter;
	struct stat statbuf;
	int fd, err;
	void *data;

	if (argc != 2) {
		fprintf(stderr, "usage: parse <file>\n");
		return 2;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 2;
	}

	if (fstat(fd, &statbuf)) {
		perror("fstat");
		return 2;
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

	err = ieee80211_radiotap_iterator_init(&iter, data, statbuf.st_size);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return 3;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_TSFT:
			printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter.this_arg));
			break;
		case IEEE80211_RADIOTAP_FLAGS:
			printf("\tflags: %02x\n", *iter.this_arg);
			break;
		case IEEE80211_RADIOTAP_RATE:
		case IEEE80211_RADIOTAP_CHANNEL:
		case IEEE80211_RADIOTAP_FHSS:
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		case IEEE80211_RADIOTAP_LOCK_QUALITY:
		case IEEE80211_RADIOTAP_TX_ATTENUATION:
		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		case IEEE80211_RADIOTAP_DBM_TX_POWER:
		case IEEE80211_RADIOTAP_ANTENNA:
		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		case IEEE80211_RADIOTAP_DB_ANTNOISE:
		case IEEE80211_RADIOTAP_RX_FLAGS:
		case IEEE80211_RADIOTAP_TX_FLAGS:
		case IEEE80211_RADIOTAP_RTS_RETRIES:
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			break;
		}
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return 3;
	}

	return 0;
}
