#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "radiotap_iter.h"

int main(int argc, char *argv[])
{
	struct ieee80211_radiotap_iterator iter;
	struct stat statbuf;
	int fd, err;
	void *data;

	if (argc != 2) {
		fprintf(stderr, "usage: test <file>\n");
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
		
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return 3;
	}
}
