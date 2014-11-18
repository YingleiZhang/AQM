/*
 * net/sched/sch_blue.c	Random Early Detection queue.
 *
 *		This program is free software; you can blueistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 * J Hadi Salim 980914:	computation fixes
 * Alexey Makarenko <makar@phoenix.kharkov.ua> 990814: qave on idle link was calculated incorrectly.
 * J Hadi Salim 980816:  ECN support
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/blue.h>


/*	Parameters, settable by user:
	-----------------------------

	limit		- bytes (must be > qth_max + burst)

	Hard limit on queue length, should be chosen >qth_max
	to allow packet bursts. This parameter does not
	affect the algorithms behaviour and can be chosen
	arbitrarily high (well, less than ram size)
	Really, this limit will never be reached
	if BLUE works correctly.
 */

struct blue_sched_data {
	u32			limit;		/* HARD maximal queue length */
	unsigned char		flags;
	struct timer_list	adapt_timer;
	struct blue_parms	parms;
	struct blue_vars	vars;
	struct blue_stats	stats;
	struct Qdisc		*qdisc;
};

static inline int blue_use_ecn(struct blue_sched_data *q)
{
	return q->flags & TC_BLUE_ECN;
}

static inline int blue_use_harddrop(struct blue_sched_data *q)
{
	return q->flags & TC_BLUE_HARDDROP;
}

static int blue_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	int ret;
	//need to implement blue enqueue
}

static struct sk_buff *blue_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	struct blue_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	//need to implement blue dequeue
}

//this should be the same function as red, so no need to change.
static struct sk_buff *blue_peek(struct Qdisc *sch)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	return child->ops->peek(child);
}

static unsigned int blue_drop(struct Qdisc *sch)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	unsigned int len;

	//the drop mechanism is different, need to implement drop function.
}

//No need to change
static void blue_reset(struct Qdisc *sch)
{
	struct blue_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	sch->q.qlen = 0;
	blue_restart(&q->vars);
}
//So far i don't see the point of changing this.
static void blue_destroy(struct Qdisc *sch)
{
	struct blue_sched_data *q = qdisc_priv(sch);

	del_timer_sync(&q->adapt_timer);
	qdisc_destroy(q->qdisc);
}

static const struct nla_policy blue_policy[TCA_BLUE_MAX + 1] = {
	[TCA_BLUE_PARMS]	= { .len = sizeof(struct tc_blue_qopt) },
	[TCA_BLUE_STAB]	= { .len = BLUE_STAB_SIZE },
	[TCA_BLUE_MAX_P] = { .type = NLA_U32 },
};

static int blue_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_BLUE_MAX + 1];
	struct tc_blue_qopt *ctl;
	struct Qdisc *child = NULL;
	int err;
	u32 max_P;

	//need to implement blue change, this is pretty complicated.
}
//Not sure how this worked in blue, 
static inline void blue_adaptative_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct blue_sched_data *q = qdisc_priv(sch);
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));
	// need to implement this, or may be we don't need this function.
}

static int blue_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct blue_sched_data *q = qdisc_priv(sch);

	q->qdisc = &noop_qdisc;
	setup_timer(&q->adapt_timer, blue_adaptative_timer, (unsigned long)sch);
	return blue_change(sch, opt);
}
// We should be able to use this function, or may be we need to change something.
static int blue_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	struct tc_blue_qopt opt = {
		.limit		= q->limit,
		.flags		= q->flags,
		.qth_min	= q->parms.qth_min >> q->parms.Wlog,
		.qth_max	= q->parms.qth_max >> q->parms.Wlog,
		.Wlog		= q->parms.Wlog,
		.Plog		= q->parms.Plog,
		.Scell_log	= q->parms.Scell_log,
	};

	sch->qstats.backlog = q->qdisc->qstats.backlog;
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	if (nla_put(skb, TCA_BLUE_PARMS, sizeof(opt), &opt) ||
	    nla_put_u32(skb, TCA_BLUE_MAX_P, q->parms.max_P))
		goto nla_put_failure;
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static int blue_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	struct tc_blue_xstats st = {
		.early	= q->stats.prob_drop + q->stats.forced_drop,
		.pdrop	= q->stats.pdrop,
		.other	= q->stats.other,
		.marked	= q->stats.prob_mark + q->stats.forced_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}
//We should be able to use this.
static int blue_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct blue_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;
	return 0;
}


static int blue_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	// need to implement this
}
//no need to change.
static struct Qdisc *blue_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct blue_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}
// no need to change
static unsigned long blue_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}
//no need to change
static void blue_put(struct Qdisc *sch, unsigned long arg)
{
}
//I don't quite understand how this works at this moment, but i don't think we need to change it.
static void blue_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops blue_class_ops = {
	.graft		=	blue_graft,
	.leaf		=	blue_leaf,
	.get		=	blue_get,
	.put		=	blue_put,
	.walk		=	blue_walk,
	.dump		=	blue_dump_class,
};

static struct Qdisc_ops blue_qdisc_ops __read_mostly = {
	.id		=	"blue",
	.priv_size	=	sizeof(struct blue_sched_data),
	.cl_ops		=	&blue_class_ops,
	.enqueue	=	blue_enqueue,
	.dequeue	=	blue_dequeue,
	.peek		=	blue_peek,
	.drop		=	blue_drop,
	.init		=	blue_init,
	.reset		=	blue_reset,
	.destroy	=	blue_destroy,
	.change		=	blue_change,
	.dump		=	blue_dump,
	.dump_stats	=	blue_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init blue_module_init(void)
{
	return register_qdisc(&blue_qdisc_ops);
}

static void __exit blue_module_exit(void)
{
	unregister_qdisc(&blue_qdisc_ops);
}

module_init(blue_module_init)
module_exit(blue_module_exit)

MODULE_LICENSE("GPL");
