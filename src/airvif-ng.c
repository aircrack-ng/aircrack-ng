/*
 * nl80211 userspace tool
 *
 * Copyright 2007, 2008	Johannes Berg <johannes@sipsolutions.net>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "nl80211.h"

#include "airvif-ng.h"


static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_handle = nl_handle_alloc();
	if (!state->nl_handle) {
		fprintf(stderr, "Failed to allocate netlink handle.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_handle)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl_cache = genl_ctrl_alloc_cache(state->nl_handle);
	if (!state->nl_cache) {
		fprintf(stderr, "Failed to allocate generic netlink cache.\n");
		err = -ENOMEM;
		goto out_handle_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_cache_free;
	}

	return 0;

 out_cache_free:
	nl_cache_free(state->nl_cache);
 out_handle_destroy:
	nl_handle_destroy(state->nl_handle);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_handle_destroy(state->nl_handle);
}

/*
 * return
 *	0 - error
 *	1 - phy
 *	2 - dev
 */
static int get_phy_or_dev(int *argc, char ***argv, char **name)
{
	char *type = (*argv)[0];

	if (*argc < 2)
		return 0;

	*name = (*argv)[1];

	*argc -= 2;
	*argv += 2;

	if (strcmp(type, "phy") == 0)
		return 1;
	if (strcmp(type, "dev") == 0)
		return 2;

	return 0;
}

static void usage(char *argv0)
{
	fprintf(stderr, "Usage:	%1$s dev <phydev> <OBJECT> <COMMAND> [OPTIONS]"
			"\n	%1$s dev <phydev> info\n"
			"\n"
			"where OBJECT := { interface | station | mpath }\n"
			"and COMMAND := { add | del | set | get | dump }\n",
			argv0);
}

int main(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err = 0, pod;
	char *ifname = NULL, *phyname = NULL, *type, *argv0;

	err = nl80211_init(&nlstate);
	if (err)
		return 1;

	/* strip off self */
	argc--;
	argv0 = *argv++;

	if (argc == 0 || (argc == 1 && strcmp(*argv, "help") == 0)) {
		usage(argv0);
		goto out;
	}

	pod = get_phy_or_dev(&argc, &argv, &ifname);
	if (pod == 0) {
		err = 1;
		goto out;
	}

	if (pod == 1) {
		phyname = ifname;
		ifname = NULL;
	}

	if (argc <= 0) {
		err = 1;
		goto out;
	}

	type = argv[0];
	argc--;
	argv++;

	if (strcmp(type, "interface") == 0)
		err = handle_interface(&nlstate, phyname, ifname, argc, argv);
	else if (strcmp(type, "info") == 0)
		err = handle_info(&nlstate, phyname, ifname);
	else if (strcmp(type, "station") == 0)
		err = handle_station(&nlstate, ifname, argc, argv);
	else if (strcmp(type, "mpath") == 0)
		err = handle_mpath(&nlstate, ifname, argc, argv);
	else {
		fprintf(stderr, "No such object type %s\n", type);
		err = 1;
	}

 out:
	nl80211_cleanup(&nlstate);

	return err;
}
