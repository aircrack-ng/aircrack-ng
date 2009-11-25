#ifndef __RADIOTAP_ITER_H
#define __RADIOTAP_ITER_H

#include "radiotap.h"

/* Radiotap header iteration
 *   implemented in radiotap.c
 */

struct radiotap_align_size {
	uint8_t align:4, size:4;
};

struct ieee80211_radiotap_namespace {
	const struct radiotap_align_size *align_size;
	int n_bits;
	uint32_t oui;
	uint8_t subns;
};

struct ieee80211_radiotap_vendor_namespaces {
	const struct ieee80211_radiotap_namespace *ns;
	int n_ns;
};

/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @rtheader: pointer to the radiotap header we are walking through
 * @max_length: length of radiotap header in cpu byte ordering
 * @this_arg_index: index of current arg
 * @this_arg: pointer to current radiotap arg
 * @arg_index: internal next argument index
 * @arg: internal next argument pointer
 * @next_bitmap: internal pointer to next present u32
 * @bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 */

struct ieee80211_radiotap_iterator {
	struct ieee80211_radiotap_header *rtheader;
	int max_length;
	int this_arg_index;
	unsigned char *this_arg;

	int arg_index;
	unsigned char *arg, *end_ns;
	uint32_t *next_bitmap;
	uint32_t bitmap_shifter;
	int reset_on_ext;
	int is_radiotap_ns;
	const struct ieee80211_radiotap_vendor_namespaces *vns;
	const struct ieee80211_radiotap_namespace *current_namespace;
};

extern int ieee80211_radiotap_iterator_init(
   struct ieee80211_radiotap_iterator *iterator,
   struct ieee80211_radiotap_header *radiotap_header,
   int max_length,
   const struct ieee80211_radiotap_vendor_namespaces *vns);

extern int ieee80211_radiotap_iterator_next(
   struct ieee80211_radiotap_iterator *iterator);

#endif /* __RADIOTAP_ITER_H */
