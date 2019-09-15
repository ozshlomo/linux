// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
//#include <net/netfilter/nf_conntrack_labels.h>

#include <net/netfilter/nf_conntrack_acct.h>

#include <linux/workqueue.h>
#include <linux/mlx5/device.h>

#include "en/tc_ct.h"
#include "en_rep.h"

#define CT_FLOW_AGING 300
#define CT_FLOW_AGING_STEP 1
#define NF_FLOWTABLE_TCP_PICKUP_TIMEOUT	(30 * HZ)
#define NF_FLOWTABLE_UDP_PICKUP_TIMEOUT	(30 * HZ)

#define printct(ct, format, ...)\
	do {\
		struct nf_conntrack_tuple *__tuple_o;\
		struct nf_conntrack_tuple *__tuple_r;\
		\
		__tuple_o= &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;\
		__tuple_r = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;\
		pr_debug("%s %d %s @@ ct: %px proto: %d, %pI4:%d %pI4:%d (reply: %pI4:%d %pI4:%d),  zone: %d, tcp_state: %d - " format "\n",\
			__FILE__, __LINE__, __func__,\
			ct,\
			__tuple_o->dst.protonum,\
			&__tuple_o->src.u3.ip,\
			ntohs(__tuple_o->src.u.udp.port),\
			&__tuple_o->dst.u3.ip,\
			ntohs(__tuple_o->dst.u.udp.port),\
			&__tuple_r->src.u3.ip,\
			ntohs(__tuple_r->src.u.udp.port),\
			&__tuple_r->dst.u3.ip,\
			ntohs(__tuple_r->dst.u.udp.port),\
			nf_ct_zone(ct)->id,\
			ct->proto.tcp.state,\
				## __VA_ARGS__);\
	} while (0);

#define ctflow_tuple(ct_flow)\
	ct_flow->ce->ct->tuplehash[ct_flow->ce->dir].tuple

#define printtuple(ct_flow, format, ...)\
	pr_debug("%s %d %s @@ ct_flow: %px, tuple: (ethtype: %x) %d, IPs %pI4, %pI4 ports %d, %d @ flow: %px, zone: %d, entry: %px, flows: %d - " format "\n",\
		 __FILE__, __LINE__, __func__,\
			ct_flow,\
			(int) ntohs(ctflow_tuple(ct_flow).src.l3num),\
			ctflow_tuple(ct_flow).dst.protonum,\
			&ctflow_tuple(ct_flow).src.u3.ip,\
			&ctflow_tuple(ct_flow).dst.u3.ip,\
			ntohs(ctflow_tuple(ct_flow).src.u.udp.port),\
			ntohs(ctflow_tuple(ct_flow).dst.u.udp.port),\
			ct_flow->flow,\
			ct_flow->zone_id,\
			ct_flow->ce,\
			ct_flow->ce->flows,\
## __VA_ARGS__);

struct mlx5e_ct_control {
	struct rhashtable work_ht;
	struct idr tunnel_ids;
	struct idr match_ids;
	struct idr tuple_ids;
	struct idr label_ids;
	struct mlx5_flow_handle **miss_rules;
	int *mod_hdr_ids;
	DECLARE_HASHTABLE(tuple_tbl, 16);
	struct mlx5_eswitch *esw;
	struct mlx5_core_dev *mdev;
	struct delayed_work aging;
	struct workqueue_struct *wq;
	struct list_head cts;
	DECLARE_HASHTABLE(ct_flows, 16);
	DECLARE_HASHTABLE(ct, 16);
};

static struct mlx5e_ct_control *get_control(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *uplink_rpriv;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;
	return uplink_priv->ct_control;
}

struct ct_flow {
	struct mlx5e_tc_flow *flow;
	struct mlx5_esw_flow_attr esw_attr_ct;
	struct mlx5_flow_handle *rule;
	struct mlx5_fc *counter;
	struct hlist_node node;
	u16 zone_id;
	int mod_hdr_id;
	int tuple_id;
	u64 packets;
	u64 bytes;
	unsigned long lastuse;
	struct mlx5_fc_cb cb;

	struct list_head entry; /*ct flows sharing the same ct */
	struct ct_entry *ce;
};

struct ct_entry {
	struct list_head children;
	struct list_head node;
	unsigned long lastuse;
	unsigned long cookie;
	int flows;
	u16 zone_id;

	/* Debug: */
	enum ip_conntrack_dir dir;
	struct nf_conn *ct;
};

struct ct_work {
	struct rhash_head node;
	struct work_struct work;
	struct mlx5e_priv *priv;

	/* key follows here */
	struct nf_conn *ct;
	bool del;
};

#define	DAY	(86400 * HZ)

/* Set an arbitrary timeout large enough not to ever expire, this save
 * us a check for the IPS_OFFLOAD_BIT from the packet path via
 * nf_ct_is_expired().
 */
/*
static void nf_ct_offload_timeout(struct nf_conn *ct)
{
	if (nf_ct_expires(ct) < DAY / 2)
		ct->timeout = nfct_time_stamp + DAY;
}

static void flow_offload_fixup_tcp(struct ip_ct_tcp *tcp)
{
	tcp->seen[0].td_maxwin = 0;
	tcp->seen[1].td_maxwin = 0;
}

static void flow_offload_fixup_ct_state(struct nf_conn *ct, bool start)
{
	const struct nf_conntrack_l4proto *l4proto;
	unsigned int timeout;
	int l4num;

	l4num = nf_ct_protonum(ct);
	if (l4num == IPPROTO_TCP) {
		if (start) {
			flow_offload_fixup_tcp(&ct->proto.tcp);
			ct->proto.tcp.state = TCP_CONNTRACK_ESTABLISHED;
		}
	}

	if (start)
		return;

	l4proto = nf_ct_l4proto_find(l4num);
	if (!l4proto)
		return;

	if (l4num == IPPROTO_TCP)
		timeout = NF_FLOWTABLE_TCP_PICKUP_TIMEOUT;
	else if (l4num == IPPROTO_UDP)
		timeout = NF_FLOWTABLE_UDP_PICKUP_TIMEOUT;
	else
		return;

	ct->timeout = nfct_time_stamp + timeout;
}
*/

void mlx5e_ct_update_pkts(struct mlx5_fc_cb *cb, u64 packets, u64 bytes)
{
	struct ct_flow *ct_flow = container_of(cb, struct ct_flow, cb);
	u64 dpkts, dbytes;

	dpkts = packets - ct_flow->packets;
	dbytes = bytes - ct_flow->bytes;

	ct_flow->packets = packets;
	ct_flow->bytes = bytes;
	ct_flow->lastuse = jiffies;
	if (ct_flow->ce->lastuse != ct_flow->lastuse)
		ct_flow->ce->lastuse = max(ct_flow->ce->lastuse, ct_flow->lastuse);

	/* TODO: sync with priv->wq and fs_counters->wq,
	 * as this counter is actually deleted after the ct_flow
	 * is deleted.
	 * Maybe take the ct ref, and check for offload as we clear it
	 * before deletion of all related ct_flows */
}

int alloc_mod_hdr_actions(struct mlx5e_priv *priv,
				 int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr);
static int ct_flow_build_modhdr_nat(struct mlx5e_ct_control *control,
				    struct mlx5e_tc_flow *flow,
				    struct ct_flow *ct_flow,
				    struct flow_action *action)
{
	size_t action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);
	uint16_t ct_action = flow->esw_attr->ct_action;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct flow_action_entry *entry;
	int i, err, field;
	char *modact;
	u32 offset;

	if (!(ct_action & TCA_CT_ACT_NAT))
		return 0;

	parse_attr = ct_flow->esw_attr_ct.parse_attr;

	for (i = 0; i < action->num_entries; i++) {
		entry = &action->entries[i];
		offset = entry->mangle.offset;

		printk(KERN_ERR "%s %d %s @@ i: %d id: %d, val: %d, ntohs: %d, ntohl: %d, offset: %d, htype: %d\n", __FILE__, __LINE__, __func__, i, entry->id,
		       entry->mangle.val, entry->mangle.val, htons(entry->mangle.val), htonl(entry->mangle.offset), entry->mangle.htype);

		err = alloc_mod_hdr_actions(flow->priv, MLX5_FLOW_NAMESPACE_FDB, parse_attr);
		if (err)
			return err;

		modact = parse_attr->mod_hdr_actions +
			parse_attr->num_mod_hdr_actions * action_size;
		MLX5_SET(set_action_in, modact, action_type, MLX5_ACTION_TYPE_SET);
		MLX5_SET(set_action_in, modact, offset, 0);
		MLX5_SET(set_action_in, modact, data, entry->mangle.val);
		switch (entry->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				MLX5_SET(set_action_in, modact, length, 0);
				field = (offset == offsetof(struct iphdr, saddr)) ?
					 MLX5_ACTION_IN_FIELD_OUT_SIPV4 :
					 MLX5_ACTION_IN_FIELD_OUT_DIPV4;
				break;
			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
				MLX5_SET(set_action_in, modact, length, 16);
				field = (offset == offsetof(struct iphdr, saddr)) ?
					 MLX5_ACTION_IN_FIELD_OUT_TCP_SPORT :
					 MLX5_ACTION_IN_FIELD_OUT_TCP_DPORT;
				break;
			default:
				return -EOPNOTSUPP;
		}
		MLX5_SET(set_action_in, modact, field, field);
	}

	return 0;
}

static int ct_flow_build_modhdr(struct mlx5e_ct_control *control,
				struct mlx5e_tc_flow *flow,
				struct ct_flow *ct_flow,
				struct flow_rule *rule,
				uint16_t tupleid,
				int *mod_hdr_id)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct flow_action *action = &rule->action;
	struct mlx5e_priv *priv = flow->priv;
	int num_actions, err;
	char *actions;

	err = get_direct_match_mapping(priv, &ct_flow->esw_attr_ct, mp_tupleid,
				       tupleid, 0, true);
	if (err)
		return  err;

	err = get_direct_match_mapping(priv, &ct_flow->esw_attr_ct, mp_statezone,
				       0xFFFF0000 | action->entries[0].ct_metadata.zone, 0, true);
	if (err)
		return  err;
	err = get_direct_match_mapping(priv, &ct_flow->esw_attr_ct, mp_mark,
				       action->entries[0].ct_metadata.mark, 0, true);
	if (err)
		return  err;

	err = get_direct_match_mapping(priv, &ct_flow->esw_attr_ct,
			mp_labels, action->entries[0].ct_metadata.labels[0], 0, true);
	if (err)
		return err;

	err = ct_flow_build_modhdr_nat(control, flow, ct_flow, action);
	if (err)
		return err;

	parse_attr = ct_flow->esw_attr_ct.parse_attr;
	num_actions = parse_attr->num_mod_hdr_actions;
	actions = parse_attr->mod_hdr_actions;
	err = mlx5_modify_header_alloc(priv->mdev, MLX5_FLOW_NAMESPACE_FDB,
				       num_actions,
				       actions,
				       mod_hdr_id);
	if (err) {
		printk(KERN_ERR "%s %d %s @@ ERR mod hdr: %d\n", __FILE__, __LINE__, __func__, err);
		return err;
	}
	printk(KERN_ERR "%s %d %s @@ ct_flow: %px, mod_hdr: %d\n", __FILE__, __LINE__, __func__, ct_flow, mod_hdr_id);

	ct_flow->esw_attr_ct.action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	ct_flow->esw_attr_ct.mod_hdr_id = *mod_hdr_id;

	return err;
}

static bool ct_more_restricting_match(unsigned char *old_mask,
				      unsigned char *old_value,
				      unsigned char *new_value,
				      size_t __sz) {
	while (__sz--) {
		if (((*old_value & *old_mask) != (*new_value & *old_mask)))
			return false;

		*old_mask |= 0xFF;
		*old_value = *new_value;
		old_mask++; old_value++; new_value++;
	}

	return true;
}

#define TUPLE_SET_MATCH_PTR(fld, new) ({ \
	char *__m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c, fld); \
	char *__v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, fld); \
	const size_t __sz = MLX5_FLD_SZ_BYTES(fte_match_set_lyr_2_4, fld); \
	char *__n = (char *) (new); \
	bool __ret = false; \
	__ret = ct_more_restricting_match(__m, __v, __n, __sz); \
	__ret; \
})

#define TUPLE_SET_MATCH(fld, new) ({ \
	char *__m = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c, fld); \
	char *__v = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, fld); \
	const size_t __sz = MLX5_FLD_SZ_BYTES(fte_match_set_lyr_2_4, fld); \
	typeof(new) __n = (new); \
	bool __ret = false; \
	printk(KERN_ERR "%s %d %s @@ new 0x%08x\n", __FILE__, __LINE__, __func__, __n);\
	__ret = ct_more_restricting_match(__m, __v, (char *) &__n, __sz); \
	__ret; \
})

static int ct_flow_add_tuple_match(struct mlx5e_tc_flow *flow,
				   struct ct_flow *ct_flow,
				   struct flow_rule *rule)
{
	struct mlx5_flow_spec *spec = &ct_flow->esw_attr_ct.parse_attr->spec;
	u32 flags, flags_m, wanted, wanted_m;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports tps;
	void *headers_c, *headers_v;
	u16 addr_type = 0;
	u8 ip_proto = 0;

	if (flow_flag_test(flow, EGRESS) && !flow->esw_attr->chain) {
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 inner_headers);
		ct_flow->esw_attr_ct.inner_match_level = MLX5_MATCH_L4;
	} else {
		headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
					 outer_headers);
		ct_flow->esw_attr_ct.outer_match_level = MLX5_MATCH_L4;
	}

	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_ports(rule, &tps);

	ip_proto = basic.key->ip_proto;
	addr_type = control.key->addr_type;

	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
		 ntohs(basic.key->n_proto));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
		 basic.key->ip_proto);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &match.key->src, sizeof(match.key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &match.key->dst, sizeof(match.key->dst));
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
				 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
				 src_ipv4_src_ipv6.ipv4_layout.ipv4);
	} else if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &match.key->src, sizeof(match.key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &match.key->dst, sizeof(match.key->dst));
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0, sizeof(match.key->src));
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0, sizeof(match.key->dst));
	}

	switch (ip_proto) {
	case IPPROTO_TCP:
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 tcp_sport, ntohs(tps.key->src));

		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 tcp_dport, ntohs(tps.key->dst));
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_dport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_sport);

		flags = MLX5_GET(fte_match_set_lyr_2_4, headers_c, tcp_flags);
		flags_m = MLX5_GET(fte_match_set_lyr_2_4, headers_v, tcp_flags);

		// Set tcp flags, FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
		wanted = 0x10;
		wanted_m = 0x17;
		if (((flags & flags_m) != (wanted & flags_m)) ||
		    (flags_m & ~(wanted_m)))
			return -EOPNOTSUPP;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags, wanted_m);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags, wanted);
		break;

	case IPPROTO_UDP:
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_sport, ntohs(tps.key->src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 udp_dport, ntohs(tps.key->dst));
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_sport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int ct_flow_insert(struct mlx5e_ct_control *control,
			  struct ct_entry *entry,
			  struct flow_rule *rule,
			  struct mlx5e_tc_flow *flow)
{
	struct mlx5e_tc_flow_parse_attr parse_attr;
	struct ct_flow *ct_flow = NULL;
	struct mlx5_fc *counter = NULL;
	u16 zone_id = entry->zone_id;
	struct mlx5_flow_spec *spec;
	int mod_hdr_id, index = 0;
	int err = 0;

	ct_flow = kzalloc(sizeof(*ct_flow), GFP_KERNEL);
	if (!ct_flow) {
		return -ENOMEM;
	}
	ct_flow->ce = entry;

	/* Base ct flow on original flow */
	memcpy(&ct_flow->esw_attr_ct, flow->esw_attr, sizeof(struct mlx5_esw_flow_attr));
	memcpy(&parse_attr, flow->esw_attr->parse_attr, sizeof(parse_attr));
	ct_flow->esw_attr_ct.parse_attr = &parse_attr;
	spec = &parse_attr.spec;
	err = ct_flow_add_tuple_match(flow, ct_flow, rule);
	if (err)
		goto err_tuple;

	/* Get tuple unique id */
	index = 0x1AAA;
	/* TODO: IF WE FAIL HERE, SEEM TO BE A BUG WITH some CONNECTIONS remain
	 * established,
	 * CHANGE THE index to something close to MAX_TUPLE_ID  */
	err = idr_alloc_u32(&control->tuple_ids, ct_flow, &index, MAX_TUPLE_ID,
			    GFP_KERNEL);
	if (err)
		goto err_idr;

	err = ct_flow_build_modhdr(control, flow, ct_flow, rule, index,
				   &mod_hdr_id);
	if (err)
		goto err_modhdr;

	counter = mlx5_fc_create_linked(flow->esw_attr->counter_dev, true, flow->esw_attr->counter);
	if (IS_ERR(counter)) {
		err = PTR_ERR(counter);
		printk(KERN_ERR "%s %d %s @@ ERR counter: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_counter;
	}
	ct_flow->esw_attr_ct.counter = counter;

	ct_flow->rule = mlx5_eswitch_add_offloaded_rule(control->esw, spec,
					                &ct_flow->esw_attr_ct);
	if (IS_ERR(ct_flow->rule)) {
		err = PTR_ERR(ct_flow->rule);
		printk(KERN_ERR "%s %d %s @@ ERR add: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_rule;
	}

	ct_flow->flow = flow;
	ct_flow->counter = counter;
	ct_flow->mod_hdr_id = mod_hdr_id;
	ct_flow->tuple_id = index;
	ct_flow->zone_id = zone_id;
	ct_flow->lastuse = jiffies;
	list_add(&ct_flow->entry, &entry->children);

	entry->flows++;
	printtuple(ct_flow, "offloaded");

	/* TODO: rule was already in idr so after we offloaded the above,
	 * we can find it. we just won't delete it on del since it's not in
	 * the hash till the next line */
	hash_add(control->tuple_tbl, &ct_flow->node, (u32) flow->cookie);

	ct_flow->cb.updated = mlx5e_ct_update_pkts;
	mlx5_fc_register_set_cb(counter, &ct_flow->cb);

	return 0;

err_rule:
	mlx5_fc_destroy(flow->esw_attr->counter_dev, counter);
err_counter:
	mlx5_modify_header_dealloc(flow->priv->mdev, mod_hdr_id);
err_modhdr:
	idr_remove(&control->tuple_ids, index);
err_idr:
err_tuple:
	kfree(ct_flow);
	return err;
}

static bool ct_flow_delete(struct mlx5e_ct_control *control,
			   struct ct_flow *ct_flow)
{
	struct mlx5_eswitch *esw = control->esw;
	struct ct_entry *entry = ct_flow->ce;


	printtuple(ct_flow, "delete");

	hash_del(&ct_flow->node);

	list_del(&ct_flow->entry);

	mlx5_eswitch_del_offloaded_rule(esw, ct_flow->rule, &ct_flow->esw_attr_ct);
	mlx5_modify_header_dealloc(control->mdev, ct_flow->mod_hdr_id);
	idr_remove(&control->tuple_ids, ct_flow->tuple_id);
	mlx5_fc_destroy(ct_flow->esw_attr_ct.counter_dev, ct_flow->esw_attr_ct.counter);

	kfree(ct_flow);

	if (--entry->flows == 0) {
		list_del(&entry->node);

		kfree(entry);
		return true;
	}

	return false;
}

static void ct_entry_delete(struct mlx5e_ct_control *control,
			   struct ct_entry *entry)
{
	struct ct_flow *ct_flow, *tmp;

	list_for_each_entry_safe(ct_flow, tmp, &entry->children, entry) {
		if (ct_flow_delete(control, ct_flow))
			return;
	}

	WARN_ON_ONCE(1);
}


static void mlx5e_ct_aging(struct work_struct *work)
{
	struct mlx5e_ct_control *control = container_of(work,
							struct mlx5e_ct_control,
							aging.work);
	struct ct_entry *entry, *tmpe;
	unsigned long tend;

	tend = jiffies - msecs_to_jiffies(CT_FLOW_AGING * 1000);

	list_for_each_entry_safe(entry, tmpe, &control->cts, node) {
		if (time_after(tend, entry->lastuse)) {
			printk(KERN_ERR "%s %d %s @@ %px, evicting entry %px (flows: %d) \n", __FILE__, __LINE__, __func__, control, entry, entry->flows);
			ct_entry_delete(control, entry);
		}
	}

	queue_delayed_work(control->wq, &control->aging,
			   msecs_to_jiffies(CT_FLOW_AGING_STEP * 1000));
}

int mlx5e_configure_ct(struct net_device *dev, struct mlx5e_priv *priv,
		       struct flow_cls_offload *f, int flags)
{
	return -EOPNOTSUPP;
}

static int mlx5e_ct_block_flow_offload_add(struct mlx5e_ct_control *control,
					   struct ct_flow_offload *ct_flow)
{
	struct flow_rule *rule = &ct_flow->rule;
	unsigned long cookie = ct_flow->cookie;
	struct ct_flow_table *ft = ct_flow->ft;
	struct mlx5e_tc_flow *flow;
	struct ct_entry *entry;
	struct hlist_node *tmp;
	u32 hash_key;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&entry->children);
	entry->zone_id = ft->zone;
	entry->lastuse = jiffies;
	entry->cookie = cookie;
	entry->ct = ct_flow->ct;
	entry->dir = ct_flow->dir;

	hash_key = (u32) entry->zone_id;
	hash_for_each_possible_safe(control->ct_flows, flow, tmp,
				    ct_node, hash_key) {
		printct(entry->ct, "flow->esw_attr->zone: %d", flow->esw_attr->zone);
		if (entry->zone_id == flow->esw_attr->zone)
			ct_flow_insert(control, entry, rule, flow);
	}

	list_add(&entry->node, &control->cts);

	return 0;
}

static int mlx5e_ct_block_flow_offload_del(struct mlx5e_ct_control *control,
					   struct ct_flow_offload *ct_flow)
{
	unsigned long cookie = ct_flow->cookie;
	struct ct_entry *entry;

	list_for_each_entry(entry, &control->cts, node) {
		if (entry->cookie == cookie) {
			ct_entry_delete(control, entry);
			return 0;
		}
	}

	return -ENOENT;
}

static int mlx5e_ct_block_flow_offload_stats(struct mlx5e_ct_control *control,
					     struct ct_flow_offload *ct_flow)
{
	struct flow_stats *stats = &ct_flow->stats;
	unsigned long cookie = ct_flow->cookie;
	struct ct_entry *entry;
	u64 lastused;

	list_for_each_entry(entry, &control->cts, node) {
		if (entry->cookie == cookie) {
			lastused = entry->lastuse;

			flow_stats_update(stats, 0, 0, lastused);
			return 0;
		}
	}

	return -ENOENT;
}

static int mlx5e_ct_block_flow_offload(enum tc_setup_type type, void *type_data,
				       void *cb_priv)
{
	struct mlx5e_ct_control *control = cb_priv;
	struct ct_flow_offload *ct_flow = type_data;
	struct ct_flow_table *ft = ct_flow->ft;
	unsigned long cookie = ct_flow->cookie;

	switch (ct_flow->command) {
		case CT_FLOW_ADD:
			printk(KERN_ERR "%s %d %s @@ ft: %px, ADD, cookie: %lu\n", __FILE__, __LINE__, __func__, ft, cookie);
			return mlx5e_ct_block_flow_offload_add(control, ct_flow);
			break;
		case CT_FLOW_DEL:
			printk(KERN_ERR "%s %d %s @@ ft: %px, DEL, cookie: %lu\n", __FILE__, __LINE__, __func__, ft, cookie);
			return mlx5e_ct_block_flow_offload_del(control, ct_flow);
		case CT_FLOW_STATS:
			printk(KERN_ERR "%s %d %s @@ ft: %px, STATS, cookie: %lu\n", __FILE__, __LINE__, __func__, ft, cookie);
			return mlx5e_ct_block_flow_offload_stats(control, ct_flow);
		default:
			break;
	};

	return -EOPNOTSUPP;
}

int mlx5e_ct_flow_offload(struct mlx5e_tc_flow *flow)
{
	struct mlx5e_ct_control *control = get_control(flow->priv);
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;

	if (!mlx5_eswitch_vport_match_metadata_enabled(control->esw))
		return -EOPNOTSUPP;

	if (attr->block) {
		struct flow_block *block = attr->block;
		struct flow_block_cb *block_cb;
		bool found = false;
		int err;

		printk(KERN_ERR "%s %d %s @@ block: %px\n", __FILE__, __LINE__, __func__, block);
		list_for_each_entry(block_cb, &block->cb_list, list) {
			printk(KERN_ERR "%s %d %s @@ block: %px, has control? %px\n", __FILE__, __LINE__, __func__, block, control);
			if (block_cb->cb_ident == control) {
				printk(KERN_ERR "%s %d %s @@ block: %px, has control? %px: yes\n", __FILE__, __LINE__, __func__, block, control);
				found = true;
				break;
			}
		}

		if (!found) {
			printk(KERN_ERR "%s %d %s @@ block: %px, adding cb: %px, with ident/priv: %px\n", __FILE__, __LINE__, __func__, block, mlx5e_ct_block_flow_offload, control);
			block_cb = flow_block_cb_alloc(mlx5e_ct_block_flow_offload, control, control, NULL);
			if (IS_ERR(block_cb)) {
				err = PTR_ERR(block_cb);
				printk(KERN_ERR "%s %d %s @@ failed alloc block %d\n", __FILE__, __LINE__, __func__, err);
				return err;
			}

			list_add_tail(&block_cb->list, &block->cb_list);
			printk(KERN_ERR "%s %d %s @@ Binded to block: %px\n", __FILE__, __LINE__, __func__, block);
		}
	}

	/*
	 * TODO reply offload
	list_for_each_entry(entry, &control->cts, node) {
		if (entry->zone_id == attr->zone) {
			ct_flow_...(control, entry, flow, IP_CT_DIR_ORIGINAL);
			ct_flow_(control, entry, flow, IP_CT_DIR_REPLY);
		}
	}
	*/

	hash_add(control->ct_flows, &flow->ct_node, (u32) attr->zone);

	printk(KERN_ERR "%s %d %s @@ offloaded tc flow: %px\n", __FILE__, __LINE__, __func__, flow);

	return 0;
}

void mlx5e_ct_delete_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5e_ct_control *control = get_control(flow->priv);
	struct ct_flow *ct_flow;
	struct hlist_node *tmp;
	u32 hash_key;

	printk(KERN_ERR "%s %d %s @@ delete ct tc flow: %px\n", __FILE__, __LINE__, __func__, flow);

	hash_key = (u32) flow->cookie;
	hash_for_each_possible_safe(control->tuple_tbl, ct_flow, tmp,
				    node, hash_key) {
		if (ct_flow->flow == flow)
			ct_flow_delete(control, ct_flow);
	}

	hash_del(&flow->ct_node);

	return;
}

int mlx5e_ct_parse_match(struct mlx5e_tc_flow *flow,
			 struct flow_cls_offload *f,
			 struct netlink_ext_ack *extack)
{
	struct mlx5e_ct_control *control = get_control(flow->priv);
	uint32_t statezone = 0, statezone_mask = 0;
	struct flow_dissector_key_ct *mask, *key;
	struct mlx5e_priv *priv = flow->priv;
	uint16_t ct_state_on, ct_state_off;
	uint16_t ct_state, ct_state_mask;
	bool trk, est, untrk, unest;
	struct flow_match_ct match;

	if (!flow_rule_match_key(f->rule, FLOW_DISSECTOR_KEY_CT))
		return 0;

	if (!mlx5_eswitch_vport_match_metadata_enabled(control->esw)) {
		NL_SET_ERR_MSG_MOD(extack,
				"ct matching isn't available");
		return -EOPNOTSUPP;
	}

	flow_rule_match_ct(f->rule, &match);

	key = match.key;
	mask = match.mask;

	ct_state = key->ct_state;
	ct_state_mask = mask->ct_state;

	if (ct_state_mask & ~(TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
			      TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED)) {
		NL_SET_ERR_MSG_MOD(extack,
				"only ct_state trk, est and -new are supported");
		return -EOPNOTSUPP;
	}

	ct_state_on = ct_state & ct_state_mask;
	ct_state_off = (ct_state & ct_state_mask) ^ ct_state_mask;
	trk = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	est = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
	untrk = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	unest = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;

	if (untrk) {
		if (est) {
			NL_SET_ERR_MSG_MOD(extack,
					   "ct_state -trk+est isn't supported");
			return -EOPNOTSUPP;
		}
		statezone_mask |= 0xFFFF << 16;
	} else if (trk || est) {
		if (!est) {
			NL_SET_ERR_MSG_MOD(extack,
					   "ct_state +trk without +est isn't supported");
			return -EOPNOTSUPP;
		}

		statezone |= 0xFFFF << 16;
		statezone_mask |= 0xFFFF << 16;
	} else if (unest) {
		NL_SET_ERR_MSG_MOD(extack,
				   "ct_state -est without -trk isn't supported");
		return -EOPNOTSUPP;
	}

	if (mask->ct_zone) {
		statezone_mask |= 0xFFFF;
		statezone |= key->ct_zone & 0xFFFF;
	}

	if (statezone_mask)
		get_direct_match_mapping(priv, flow->esw_attr, mp_statezone, statezone, statezone_mask, false);
	if (mask->ct_mark)
		get_direct_match_mapping(priv, flow->esw_attr, mp_mark, key->ct_mark, mask->ct_mark, false);
	if (memchr_inv(mask->ct_labels, 0, 16))
		get_direct_match_mapping(priv, flow->esw_attr, mp_labels, key->ct_labels[0],
					 mask->ct_labels[0], false);

	return 0;
}

int mlx5e_ct_parse_action(struct mlx5e_tc_flow *flow,
			  const struct flow_action_entry *act,
			  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_flow_attr *attr = flow->esw_attr;

	attr->zone = act->ct.zone;
	attr->ct_action = act->ct.action;
	attr->block = act->ct.block;

	return 0;
}

int mlx5e_ct_init(struct mlx5_rep_uplink_priv *uplink_priv)
{
	struct mlx5e_rep_priv *priv = container_of(uplink_priv,
						   struct mlx5e_rep_priv,
						   uplink_priv);
	struct mlx5e_priv *npriv = netdev_priv(priv->netdev);
	struct mlx5e_ct_control *control;

	uplink_priv->ct_control = kzalloc(sizeof(struct mlx5e_ct_control),
					  GFP_KERNEL);
	if (!uplink_priv->ct_control)
		return -ENOMEM;

	control = uplink_priv->ct_control;

	idr_init(&control->match_ids);
	idr_init(&control->tuple_ids);
	idr_init(&control->label_ids);

	hash_init(control->tuple_tbl);
	hash_init(control->ct_flows);
	INIT_LIST_HEAD(&control->cts);

	control->mdev = npriv->mdev;
	control->esw = npriv->mdev->priv.eswitch;
	control->wq = npriv->wq;

	INIT_DELAYED_WORK(&control->aging, mlx5e_ct_aging);
	if (!queue_delayed_work(control->wq, &control->aging,
				msecs_to_jiffies(CT_FLOW_AGING_STEP * 1000)))
		WARN_ON(1);

	return 0;
}

void mlx5e_ct_clean(struct mlx5_rep_uplink_priv *uplink_priv)
{
	struct mlx5e_ct_control *control = uplink_priv->ct_control;
	struct ct_entry *entry, *tmpe;

	cancel_delayed_work_sync(&control->aging);

	flush_workqueue(control->wq);

	list_for_each_entry_safe(entry, tmpe, &control->cts, node) {
		ct_entry_delete(control, entry);
	}

	idr_destroy(&control->tunnel_ids);
	idr_destroy(&control->match_ids);
	idr_destroy(&control->tuple_ids);
	idr_destroy(&control->label_ids);

	kfree(control);
	uplink_priv->ct_control = NULL;
}

int mlx5e_ct_restore_flow(struct mlx5_rep_uplink_priv *uplink_priv,
			  struct sk_buff *skb, u32 tupleid, int *tunnel_id)
{
	struct mlx5e_ct_control *control = uplink_priv->ct_control;
	struct ct_flow *ct_flow;

	//printk(KERN_ERR "%s %d %s @@ tupleid: %d\n", __FILE__, __LINE__, __func__, tupleid);

	*tunnel_id = 0;

	ct_flow = idr_find(&control->tuple_ids, tupleid);
	if (!ct_flow) {
		printk(KERN_ERR "%s %d %s @@ id: %d not found to restore..., skb: %px\n", __FILE__, __LINE__, __func__, tupleid, skb);
		return 0;
	}

	/*
	nf_conntrack_get(&ct_flow->ct->ct_general);
	nf_ct_set(skb, ct_flow->ct, ct_flow->dir == IP_CT_DIR_ORIGINAL ?
				    IP_CT_ESTABLISHED :
				    IP_CT_ESTABLISHED_REPLY);
	*/

	//printk(KERN_ERR "%s %d %s @@ restored tuple id: %d, skb: %px, ct_flow: %px,  px: %px, tunnel_id: %d\n", __FILE__, __LINE__, __func__, tupleid, skb, ct_flow, ct_flow->ct, ct_flow->esw_attr_ct.tunnel_id);
	*tunnel_id = ct_flow->esw_attr_ct.tunnel_id;
	return 0;
}
