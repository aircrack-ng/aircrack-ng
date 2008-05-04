#include "nl80211.h"
#include <net/if.h>
#include <errno.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "airvif-ng.h"

enum plink_state {
	LISTEN,
	OPN_SNT,
	OPN_RCVD,
	CNF_RCVD,
	ESTAB,
	HOLDING,
	BLOCKED
};

enum plink_actions {
	PLINK_ACTION_UNDEFINED,
	PLINK_ACTION_OPEN,
	PLINK_ACTION_BLOCK,
};


static int wait_handler(struct nl_msg *msg, void *arg)
{
	int *finished = arg;

	*finished = 1;
	return NL_STOP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	fprintf(stderr, "nl80211 error %d\n", err->error);
	exit(err->error);
}

static int print_sta_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	char mac_addr[20], state_name[10], dev[20];
	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	/*
	 * TODO: validate the interface and mac address!
	 * Otherwise, there's a race condition as soon as
	 * the kernel starts sending station notifications.
	 */

	if (!tb[NL80211_ATTR_STA_INFO]) {
		fprintf(stderr, "sta stats missing!");
		return NL_SKIP;
	}
	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			     tb[NL80211_ATTR_STA_INFO],
			     stats_policy)) {
		fprintf(stderr, "failed to parse nested attributes!");
		return NL_SKIP;
	}

	mac_addr_n2a(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
	printf("Station %s (on %s)", mac_addr, dev);

	if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
		printf("\n\tinactive time:\t%d ms",
			nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
	if (sinfo[NL80211_STA_INFO_RX_BYTES])
		printf("\n\trx bytes:\t%d",
			nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
	if (sinfo[NL80211_STA_INFO_TX_BYTES])
		printf("\n\ttx bytes:\t%d",
			nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));
	if (sinfo[NL80211_STA_INFO_LLID])
		printf("\n\tmesh llid:\t%d",
			nla_get_u16(sinfo[NL80211_STA_INFO_LLID]));
	if (sinfo[NL80211_STA_INFO_PLID])
		printf("\n\tmesh plid:\t%d",
			nla_get_u16(sinfo[NL80211_STA_INFO_PLID]));
	if (sinfo[NL80211_STA_INFO_PLINK_STATE]) {
		switch (nla_get_u16(sinfo[NL80211_STA_INFO_PLINK_STATE])) {
		case LISTEN:
			strcpy(state_name, "LISTEN");
			break;
		case OPN_SNT:
			strcpy(state_name, "OPN_SNT");
			break;
		case OPN_RCVD:
			strcpy(state_name, "OPN_RCVD");
			break;
		case CNF_RCVD:
			strcpy(state_name, "CNF_RCVD");
			break;
		case ESTAB:
			strcpy(state_name, "ESTAB");
			break;
		case HOLDING:
			strcpy(state_name, "HOLDING");
			break;
		case BLOCKED:
			strcpy(state_name, "BLOCKED");
			break;
		default:
			strcpy(state_name, "UNKNOWN");
			break;
		}
		printf("\n\tmesh plink:\t%s", state_name);
	}

	printf("\n");
	return NL_SKIP;
}

static int handle_station_get(struct nl80211_state *state,
				char *dev, int argc, char **argv)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	int ret = -1;
	int err;
	int finished = 0;
	unsigned char mac_addr[ETH_ALEN];

	if (argc < 1) {
		fprintf(stderr, "not enough arguments\n");
		return -1;
	}

	if (mac_addr_a2n(mac_addr, argv[0])) {
		fprintf(stderr, "invalid mac address\n");
		return -1;
	}

	argc--;
	argv++;

	if (argc) {
		fprintf(stderr, "too many arguments\n");
		return -1;
	}

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_GET_STATION, 0);

	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, mac_addr);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(dev));

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(state->nl_handle, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wait_handler, &finished);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);

	err = nl_recvmsgs(state->nl_handle, cb);

	if (!finished)
		err = nl_wait_for_ack(state->nl_handle);

	if (err < 0)
		goto out;

	ret = 0;

 out:
	nl_cb_put(cb);
 nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int handle_station_set(struct nl80211_state *state,
				char *dev, int argc, char **argv)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	int ret = -1;
	int err;
	int finished = 0;
	unsigned char plink_action;
	unsigned char mac_addr[ETH_ALEN];

	if (argc < 3) {
		fprintf(stderr, "not enough arguments\n");
		return -1;
	}

	if (mac_addr_a2n(mac_addr, argv[0])) {
		fprintf(stderr, "invalid mac address\n");
		return -1;
	}
	argc--;
	argv++;

	if (strcmp("plink_action", argv[0]) != 0) {
		fprintf(stderr, "parameter not supported\n");
		return -1;
	}
	argc--;
	argv++;

	if (strcmp("open", argv[0]) == 0)
		plink_action = PLINK_ACTION_OPEN;
	else if (strcmp("block", argv[0]) == 0)
		plink_action = PLINK_ACTION_BLOCK;
	else {
		fprintf(stderr, "plink action not supported\n");
		return -1;
	}
	argc--;
	argv++;

	if (argc) {
		fprintf(stderr, "too many arguments\n");
		return -1;
	}

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_SET_STATION, 0);

	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, mac_addr);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(dev));
	NLA_PUT_U8(msg, NL80211_ATTR_STA_PLINK_ACTION, plink_action);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(state->nl_handle, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wait_handler, &finished);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);

	err = nl_recvmsgs(state->nl_handle, cb);

	if (!finished)
		err = nl_wait_for_ack(state->nl_handle);

	if (err < 0)
		goto out;

	ret = 0;

 out:
	nl_cb_put(cb);
 nla_put_failure:
	nlmsg_free(msg);
	return ret;
}
static int handle_station_dump(struct nl80211_state *state,
				char *dev, int argc, char **argv)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	int ret = -1;
	int err;
	int finished = 0;

	if (argc) {
		fprintf(stderr, "too many arguments\n");
		return -1;
	}

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(dev));

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(state->nl_handle, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, wait_handler, &finished);

	err = nl_recvmsgs(state->nl_handle, cb);

	if (err < 0)
		goto out;

	ret = 0;

 out:
	nl_cb_put(cb);
 nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int handle_station_del(struct nl80211_state *state,
				char *dev, int argc, char **argv)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	int ret = -1;
	int err;
	int finished = 0;
	unsigned char mac[ETH_ALEN];

	if (argc > 1) {
		fprintf(stderr, "too many arguments\n");
		return -1;
	}

	if (argc && mac_addr_a2n(mac, argv[0])) {
		fprintf(stderr, "invalid mac address\n");
		return -1;
	}

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0, 0,
		    NL80211_CMD_DEL_STATION, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(dev));
	if (argc)
		NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, mac);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(state->nl_handle, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wait_handler, &finished);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);

	err = nl_recvmsgs(state->nl_handle, cb);

	if (!finished)
		err = nl_wait_for_ack(state->nl_handle);

	if (err < 0)
		goto out;

	ret = 0;

 out:
	nl_cb_put(cb);
 nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

int handle_station(struct nl80211_state *state,
		   char *dev, int argc, char **argv)
{
	char *cmd = argv[0];

	if (argc < 1) {
		fprintf(stderr, "you must specify an station command\n");
		return -1;
	}

	argc--;
	argv++;

	if (strcmp(cmd, "del") == 0)
		return handle_station_del(state, dev, argc, argv);
	if (strcmp(cmd, "get") == 0)
		return handle_station_get(state, dev, argc, argv);
	if (strcmp(cmd, "set") == 0)
		return handle_station_set(state, dev, argc, argv);
	if (strcmp(cmd, "dump") == 0)
		return handle_station_dump(state, dev, argc, argv);

	printf("invalid interface command %s\n", cmd);
	return -1;
}
