
#include "ap_compare.h"

typedef int (*ap_compare_fn)(struct AP_info const * const a,
							 struct AP_info const * const b,
							 int const sort_direction);

typedef struct ap_sort_info_st ap_sort_info_st;
struct ap_sort_info_st
{
	char const * description;
	ap_compare_fn ap_compare;
};

struct ap_sort_context_st
{
	int sort_direction;
	ap_sort_info_st const * sort_method;
};

static int sort_bssid(struct AP_info const * const a,
					  struct AP_info const * const b,
					  int const sort_direction)
{
	int const result
		= MAC_ADDRESS_COMPARE(&a->bssid, &b->bssid) * sort_direction;

	return result;
}

static int sort_power(struct AP_info const * const a,
					  struct AP_info const * const b,
					  int const sort_direction)
{
	int const result = (a->avg_power - b->avg_power) * sort_direction;

	return result;
}

static int sort_beacon(struct AP_info const * const a,
					   struct AP_info const * const b,
					   int const sort_direction)
{
	int const result = ((a->nb_bcn < b->nb_bcn) ? -1 : 1) * sort_direction;

	return result;
}

static int sort_data(struct AP_info const * const a,
					 struct AP_info const * const b,
					 int const sort_direction)
{
	int const result = ((a->nb_data < b->nb_data) ? -1 : 1) * sort_direction;

	return result;
}

static int sort_packet_rate(struct AP_info const * const a,
							struct AP_info const * const b,
							int const sort_direction)
{
	int const result = (a->nb_dataps - b->nb_dataps) * sort_direction;

	return result;
}

static int sort_channel(struct AP_info const * const a,
						struct AP_info const * const b,
						int const sort_direction)
{
	int const result = (a->channel - b->channel) * sort_direction;

	return result;
}

static int sort_mbit(struct AP_info const * const a,
					 struct AP_info const * const b,
					 int const sort_direction)
{
	int const result = (a->max_speed - b->max_speed) * sort_direction;

	return result;
}

static int sort_enc(struct AP_info const * const a,
					struct AP_info const * const b,
					int const sort_direction)
{
	int const result
		= ((int) (a->security & STD_FIELD) - (int) (b->security & STD_FIELD))
		  * sort_direction;

	return result;
}

static int sort_cipher(struct AP_info const * const a,
					   struct AP_info const * const b,
					   int const sort_direction)
{
	int const result
		= ((int) (a->security & ENC_FIELD) - (int) (b->security & ENC_FIELD))
		  * sort_direction;

	return result;
}

static int sort_auth(struct AP_info const * const a,
					 struct AP_info const * const b,
					 int const sort_direction)
{
	int const result
		= ((int) (a->security & AUTH_FIELD) - (int) (b->security & AUTH_FIELD))
		  * sort_direction;

	return result;
}

static int sort_essid(struct AP_info const * const a,
					  struct AP_info const * const b,
					  int const sort_direction)
{
	int const result = strncasecmp((char *) a->essid,
								   (char *) b->essid,
								   sizeof(a->essid) - 1)
					   * sort_direction;

	return result;
}

static int sort_nothing(struct AP_info const * const a,
						struct AP_info const * const b,
						int const sort_direction)
{
	(void) a;
	(void) b;
	(void) sort_direction;

	return 0;
}

static ap_sort_info_st const ap_sort_infos[SORT_MAX] = {
	[SORT_BY_NOTHING]
	= {.description = "first seen", .ap_compare = sort_nothing},
	[SORT_BY_BSSID] = {.description = "bssid", .ap_compare = sort_bssid},
	[SORT_BY_POWER] = {.description = "power level", .ap_compare = sort_power},
	[SORT_BY_BEACON]
	= {.description = "beacon number", .ap_compare = sort_beacon},
	[SORT_BY_DATA]
	= {.description = "number of data packets", .ap_compare = sort_data},
	[SORT_BY_PRATE]
	= {.description = "packet rate", .ap_compare = sort_packet_rate},
	[SORT_BY_CHAN] = {.description = "channel", .ap_compare = sort_channel},
	[SORT_BY_MBIT] = {.description = "max data rate", .ap_compare = sort_mbit},
	[SORT_BY_ENC] = {.description = "encryption", .ap_compare = sort_enc},
	[SORT_BY_CIPHER] = {.description = "cipher", .ap_compare = sort_cipher},
	[SORT_BY_AUTH] = {.description = "authentication", .ap_compare = sort_auth},
	[SORT_BY_ESSID] = {.description = "ESSID", .ap_compare = sort_essid}};

static ap_sort_info_st const *
ap_sort_method_assign(ap_sort_type_t const sort_method_in)
{
	ap_sort_info_st const * sort_info;
	ap_sort_type_t sort_method = sort_method_in;

	if (sort_method >= SORT_MAX)
	{
		sort_method = SORT_FIRST;
	}

	sort_info = &ap_sort_infos[sort_method];

	return sort_info;
}

static ap_sort_info_st const *
ap_sort_method_assign_next(ap_sort_info_st const * current)
{
	ALLEGE(current != NULL);

	size_t const current_method_index = current - ap_sort_infos;
	size_t const next_method_index = current_method_index + 1;

	return ap_sort_method_assign(next_method_index);
}

static char const *
ap_sort_method_description(ap_sort_info_st const * const sort_info)
{
	return sort_info->description;
}

char const *
ap_sort_context_description(struct ap_sort_context_st const * const context)
{
	char const * description;

	if (context == NULL)
	{
		description = "null";
		goto done;
	}

	description = ap_sort_method_description(context->sort_method);

done:
	return description;
}

int ap_sort_compare(struct ap_sort_context_st const * const context,
					struct AP_info const * const a,
					struct AP_info const * const b)
{
	int comparison;

	if (context == NULL)
	{
		comparison = 0;
		goto done;
	}

	comparison
		= context->sort_method->ap_compare(a, b, context->sort_direction);

done:
	return comparison;
}

void ap_sort_context_next_sort_method(struct ap_sort_context_st * const context)
{
	if (context == NULL)
	{
		goto done;
	}

	context->sort_method = ap_sort_method_assign_next(context->sort_method);

done:
	return;
}

void ap_sort_context_assign_sort_method(
	struct ap_sort_context_st * const context, ap_sort_type_t const sort_method)
{
	if (context == NULL)
	{
		goto done;
	}

	context->sort_method = ap_sort_method_assign(sort_method);

done:
	return;
}

bool ap_sort_context_invert_direction(struct ap_sort_context_st * const context)
{
	bool inverted;

	if (context == NULL)
	{
		inverted = false;
		goto done;
	}

	context->sort_direction *= -1;

	inverted = context->sort_direction < 0;

done:
	return inverted;
}

void ap_sort_context_free(struct ap_sort_context_st * const context)
{
	free(context);
}

static void
ap_sort_context_initialise(struct ap_sort_context_st * const context,
						   ap_sort_type_t const sort_method)
{
	context->sort_method = ap_sort_method_assign(sort_method);
	context->sort_direction = 1;
}

struct ap_sort_context_st *
ap_sort_context_alloc(ap_sort_type_t const sort_method)
{
	struct ap_sort_context_st * const context = calloc(1, sizeof *context);

	if (context == NULL)
	{
		goto done;
	}

	ap_sort_context_initialise(context, sort_method);

done:
	return context;
}
