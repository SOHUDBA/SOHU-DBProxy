/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

 $%ENDLICENSE%$ */

#ifndef _LB_WRR_H_
#define _LB_WRR_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "chassis-exports.h"

typedef struct lb_wrr_s LB_WRR;

struct lb_wrr_s {
	GArray *s; /**< 后端权重放在GArray数组里，数组下标是后端编号，数组元素值是后端权重，是gint类型的 */
	gint gcd; /**< greatest common divisor: 最大公约数 */
	gint maxweight; /**< max weight: 最大权重 */
	gint sumweight; /**< sum weight: 权重总和 */
	gint index; /**< index: 当前后端标识，用于WRR计算 */
	gint curweight; /**< current weight: 当前权重 */
	GArray *wrr_s; /**< 经WRR计算后输出的后端下标序列 */
	gint wrr_index; /**< wrr index: 当前后端标识，用于RR轮询 */
	GMutex wrr_s_mutex; /**< wrr相关变量互斥锁 */
};

CHASSIS_API gint lb_wrr__getelement(GArray *s, gint i);
#define lb_wrr__getweight lb_wrr__getelement
#define lb_wrr__getwrrindex lb_wrr__getelement
CHASSIS_API gint lb_wrr__getmaxweight(GArray *s);
CHASSIS_API gint lb_wrr__getsumweight(GArray *s);
CHASSIS_API gint lb_wrr__gcd(gint x, gint y);
CHASSIS_API gint lb_wrr__getgcd(GArray *s);
CHASSIS_API gint lb_wrr__getwrr(GArray *s, gint gcd, gint maxweight, gint *i, gint *cw);

CHASSIS_API void lb_wrr_init_lock(LB_WRR *wrr);
CHASSIS_API void lb_wrr_init(LB_WRR *wrr, gboolean locked, gboolean initlock);
CHASSIS_API void lb_wrr_clear_lock(LB_WRR *wrr);
CHASSIS_API void lb_wrr_clear(LB_WRR *wrr, gboolean locked, gboolean initlock);
CHASSIS_API void lb_wrr_append(LB_WRR *wrr, gint weight);
CHASSIS_API void lb_wrr_calc(LB_WRR *wrr, gboolean locked);
CHASSIS_API gint lb_wrr_get(LB_WRR *wrr);
CHASSIS_API gint lb_wrr_get_locked(LB_WRR *wrr);

#endif



/*eof*/
