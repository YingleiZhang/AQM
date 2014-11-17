
#ifndef __NET_SCHED_BLUE_H
#define __NET_SCHED_BLUE_H

#include <linux/types.h>
#include <linux/bug.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/dsfield.h>
#include <linux/reciprocal_div.h>



/*
 * Add instructions for the blue algorithm, how it works.
 * 
 */
#define BLUE_ONE_PERCENT ((u32)DIV_ROUND_CLOSEST(1ULL<<32, 100))

#define MAX_P_MIN (1 * BLUE_ONE_PERCENT)
#define MAX_P_MAX (50 * BLUE_ONE_PERCENT)
#define MAX_P_ALPHA(val) min(MAX_P_MIN, val / 4)

#define BLUE_STAB_SIZE	256
#define BLUE_STAB_MASK	(BLUE_STAB_SIZE - 1)
//so far, just a copy of parameters and variables in red, we might need to add a few for blue later.
struct blue_stats {
	u32		prob_drop;	/* Early probability drops */
	u32		prob_mark;	/* Early probability marks */
	u32		forced_drop;	/* Forced drops, qavg > max_thresh */
	u32		forced_mark;	/* Forced marks, qavg > max_thresh */
	u32		pdrop;          /* Drops due to queue limits */
	u32		other;          /* Drops due to drop() calls */
};

struct blue_parms {
	/* Parameters */
	u32		qth_min;	/* Min avg length threshold: Wlog scaled */
	u32		qth_max;	/* Max avg length threshold: Wlog scaled */
	u32		Scell_max;
	u32		max_P;		/* probability, [0 .. 1.0] 32 scaled */
	u32		max_P_reciprocal; /* reciprocal_value(max_P / qth_delta) */
	u32		qth_delta;	/* max_th - min_th */
	u32		target_min;	/* min_th + 0.4*(max_th - min_th) */
	u32		target_max;	/* min_th + 0.6*(max_th - min_th) */
	u8		Scell_log;
	u8		Wlog;		/* log(W)		*/
	u8		Plog;		/* random number bits	*/
	u8		Stab[BLUE_STAB_SIZE];
};

struct blue_vars {
	/* Variables */
	int		qcount;		/* Number of packets since last random
					   number generation */
	u32		qR;		/* Cached random number */

	unsigned long	qavg;		/* Average queue length: Wlog scaled */
	ktime_t		qidlestart;	/* Start of current idle period */
};
//leave it
static inline u32 blue_maxp(u8 Plog)
{
	return Plog < 32 ? (~0U >> Plog) : ~0U;
}
//leave it
static inline void blue_set_vars(struct blue_vars *v)
{
	/* Reset average queue length, the value is strictly bound
	 * to the parameters below, reseting hurts a bit but leaving
	 * it might result in an unreasonable qavg for a while. --TGR
	 */
	v->qavg		= 0;

	v->qcount	= -1;
}
// leave it
static inline void blue_set_parms(struct blue_parms *p,
				 u32 qth_min, u32 qth_max, u8 Wlog, u8 Plog,
				 u8 Scell_log, u8 *stab, u32 max_P)
{
	int delta = qth_max - qth_min;
	u32 max_p_delta;

	p->qth_min	= qth_min << Wlog;
	p->qth_max	= qth_max << Wlog;
	p->Wlog		= Wlog;
	p->Plog		= Plog;
	if (delta < 0)
		delta = 1;
	p->qth_delta	= delta;
	if (!max_P) {
		max_P = blue_maxp(Plog);
		max_P *= delta; /* max_P = (qth_max - qth_min)/2^Plog */
	}
	p->max_P = max_P;
	max_p_delta = max_P / delta;
	max_p_delta = max(max_p_delta, 1U);
	p->max_P_reciprocal  = reciprocal_value(max_p_delta);

	/* BLUE Adaptative target :
	 * [min_th + 0.4*(min_th - max_th),
	 *  min_th + 0.6*(min_th - max_th)].
	 */
	delta /= 5;
	p->target_min = qth_min + 2*delta;
	p->target_max = qth_min + 3*delta;

	p->Scell_log	= Scell_log;
	p->Scell_max	= (255 << Scell_log);

	if (stab)
		memcpy(p->Stab, stab, sizeof(p->Stab));
}

//The following two function will tell if link is idle or not.
static inline int blue_is_idling(const struct blue_vars *v)
{
	return v->qidlestart.tv64 != 0;
}

static inline void blue_start_of_idle_period(struct blue_vars *v)
{
	v->qidlestart = ktime_get();
}
//leave it.
static inline void blue_end_of_idle_period(struct blue_vars *v)
{
	v->qidlestart.tv64 = 0;
}
//so far, leave it.
static inline void blue_restart(struct blue_vars *v)
{
	blue_end_of_idle_period(v);
	v->qavg = 0;
	v->qcount = -1;
}
// we don't need to calculate the length of the queue.
static inline unsigned long blue_calc_qavg_from_idle_time(const struct blue_parms *p,
							 const struct blue_vars *v)
{
	
}
//we don't need to calculate the length of the queue.
static inline unsigned long blue_calc_qavg_no_idle_time(const struct blue_parms *p,
						       const struct blue_vars *v,
						       unsigned int backlog)
{
	/*
	we don't need to calculate the length of the queue, so we might not need this function.
	 */
	return v->qavg + (backlog - (v->qavg >> p->Wlog));
}

static inline unsigned long blue_calc_qavg(const struct blue_parms *p,
					  const struct blue_vars *v,
					  unsigned int backlog)
{
	//need to implement this
}


static inline u32 blue_random(const struct blue_parms *p)
{
	return reciprocal_divide(net_random(), p->max_P_reciprocal);
}

static inline int blue_mark_probability(const struct blue_parms *p,
				       const struct blue_vars *v,
				       unsigned long qavg)
{
	/* the way to calculate probability in blue is different from that in red
		we need to figure out how to implement this.
	 */
	return !(((qavg - p->qth_min) >> p->Wlog) * v->qcount < v->qR);
}
//we might not need the threshold, or the length of the queue.
enum {
	BLUE_BELOW_MIN_THRESH,
	BLUE_BETWEEN_TRESH,
	BLUE_ABOVE_MAX_TRESH,
};

static inline int blue_cmp_thresh(const struct blue_parms *p, unsigned long qavg)
{
	//since we don't determine the probability from Queue length, we might not need this function
}

enum {
	BLUE_DONT_MARK,
	BLUE_PROB_MARK,
	BLUE_HARD_MARK,
};

static inline int blue_action(const struct blue_parms *p,
			     struct blue_vars *v,
			     unsigned long qavg)
{
	//need to implement this
}

static inline void blue_adaptative_algo(struct blue_parms *p, struct blue_vars *v)
{
	unsigned long qavg;
	u32 max_p_delta;

	//need to implement this
}
#endif
