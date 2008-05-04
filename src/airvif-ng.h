#ifndef __AIRVIF_NG_H
#define __AIRVIF_NG_H

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

struct nl80211_state {
	struct nl_handle *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};


int handle_interface(struct nl80211_state *state,
		     char *phy, char *dev, int argc, char **argv);

int handle_info(struct nl80211_state *state, char *phy, char *dev);

#endif /* __AIRVIF_NG_H */
