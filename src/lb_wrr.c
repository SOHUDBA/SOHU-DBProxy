/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

 $%ENDLICENSE%$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "lb_wrr.h"

/**
 * 从数组里获取指定下标的元素的值，元素的数据类型是gint
 * @param[in] *s 数组指针
 * @param[out] i 下标
 * @return 元素的值
 */
gint lb_wrr__getelement(GArray *s, gint i) {
	gint len = s->len; /**@fixme warning: comparison between signed and unsigned*/
	if (i >= len || i < 0) {
		return -1;
	} else {
		return g_array_index(s, gint, i);
	}
}

/**
 * 取最大权重
 * @param[in] *s 数组指针
 * @return 最大权重
 */
gint lb_wrr__getmaxweight(GArray *s) {
	guint len = s->len;
	guint i = 0;
	gint w = 0;
	gint cw = 0;
	for (i = 0; i < len; i++) {
		cw = lb_wrr__getweight(s, i);
		if (w < cw) {
			w = cw;
		}
	}
	return w;
}

/**
 * 取权重总和
 * @param[in] *s 数组指针
 * @return 权重之和
 */
gint lb_wrr__getsumweight(GArray *s) {
	guint len = s->len;
	guint i = 0;
	gint n = 0;
	gint cw = 0;
	for (i = 0; i < len; i++) {
		cw = lb_wrr__getweight(s, i);
		n = n + cw;
	}
	return n;
}

/**
 * 计算两数的最大公约数
 * @param[in] x 整数
 * @param[in] y 整数
 * @return 最大公约数
 */
gint lb_wrr__gcd(gint x, gint y) {
	while (y != 0) {
		gint t = x % y;
		x = y;
		y = t;
	}
	return x;
}

/**
 * 取最大公约数
 * @param[in] *s 数组指针
 * @return 最大公约数
 */
gint lb_wrr__getgcd(GArray *s) {
	guint len = s->len;
	gint cw = 0;
	gint g = 1;
	guint i = 1;

	if (len < 1)
		return 1;

	cw = lb_wrr__getweight(s, 0);
	g = cw;
	for (i = 1; i < len; i++) {
		cw = lb_wrr__getweight(s, i);
		g = lb_wrr__gcd(cw, g);
	}
	return g;
}

/**
 * @param[in] *s 数组指针
 * @param[in] gcd 最大公约数
 * @param[in] maxweight 最大权重
 * @param[inout] *i (*i % len)等于当前下标
 * @Prime[inout] *cw 当前权重
 * @return 数组下标
 */
gint lb_wrr__getwrr(GArray *s, gint gcd, gint maxweight, gint *i, gint *cw) {
	guint len = s->len;
	while (TRUE) {
		*i = (*i + 1) % len;
		if (*i == 0) {
			*cw = *cw - gcd;
			if (*cw <= 0) {
				*cw = maxweight;
				if (*cw == 0) {
					return -1;
				}
			}
		}
		if (lb_wrr__getweight(s, *i) >= *cw) {
			return *i;
		}
	}
}

/**
 * 初始化互斥锁
 * @param[inout] wrr结构
 * @return 无
 */
void lb_wrr_init_lock(LB_WRR *wrr) {
	g_assert(wrr);
	/*
	if (wrr->wrr_s_mutex != NULL) {
		g_mutex_clear(wrr->wrr_s_mutex);
		wrr->wrr_s_mutex = NULL;
	}
	*/
	g_mutex_init(&(wrr->wrr_s_mutex));
	return;
}

/**
 * 初始化
 * @param[inout] wrr结构
 * @param[in] locked 是否加锁
 * @param[in] initlock 是否初始化锁(只能执行一次)
 * @return 无
 */
void lb_wrr_init(LB_WRR *wrr, gboolean locked, gboolean initlock) {
	g_assert(wrr);

	/** 初始化锁 */
	//g_debug("%s.%d: lb_wrr_init_lock", __FILE__, __LINE__);
	if (initlock == TRUE)
		lb_wrr_init_lock(wrr);

	//g_debug("%s.%d: g_array_free(wrr->s, TRUE)", __FILE__, __LINE__);
	if (wrr->s != NULL) {
		g_array_free(wrr->s, TRUE);
		wrr->s = NULL;
	}
	wrr->s = g_array_new(FALSE, FALSE, sizeof(gint));
	wrr->gcd = 1;
	wrr->maxweight = 0;
	wrr->sumweight = 0;
	wrr->index = -1;
	wrr->curweight = 0;

	/** 加锁 */
	//g_debug("%s.%d: g_mutex_lock", __FILE__, __LINE__);
	if (locked == TRUE)
		g_mutex_lock(&(wrr->wrr_s_mutex));
	//g_debug("%s.%d: g_array_free(wrr->wrr_s, TRUE)", __FILE__, __LINE__);
	if (wrr->wrr_s != NULL) {
		g_array_free(wrr->wrr_s, TRUE);
		wrr->wrr_s = NULL;
	}
	wrr->wrr_s = g_array_new(FALSE, FALSE, sizeof(gint));
	wrr->wrr_index = -1;
	//g_debug("%s.%d: g_mutex_unlock", __FILE__, __LINE__);
	if (locked == TRUE)
		g_mutex_unlock(&(wrr->wrr_s_mutex));

	//g_debug("%s.%d: return", __FILE__, __LINE__);
	return;
}

/**
 * 销毁互斥锁
 * @param[inout] wrr结构
 * @return 无
 */
void lb_wrr_clear_lock(LB_WRR *wrr) {
	g_assert(wrr);
	/*
	if (wrr->wrr_s_mutex != NULL) {
		g_mutex_clear(wrr->wrr_s_mutex);
		wrr->wrr_s_mutex = NULL;
	}
	*/
	g_mutex_clear(&(wrr->wrr_s_mutex));
	return;
}

/**
 * 销毁
 * @param[inout] wrr结构
 * @param[in] locked 是否加锁
 * @param[in] initlock 是否清除锁(只能执行一次)
 * @return 无
 */
void lb_wrr_clear(LB_WRR *wrr, gboolean locked, gboolean initlock) {
	g_assert(wrr);
	if (wrr->s != NULL) {
		g_array_free(wrr->s, TRUE);
		wrr->s = NULL;
	}
	wrr->gcd = 1;
	wrr->maxweight = 0;
	wrr->sumweight = 0;
	wrr->index = -1;
	wrr->curweight = 0;

	/** 加锁 */
	if (locked == TRUE)
		g_mutex_lock(&(wrr->wrr_s_mutex));
	if (wrr->wrr_s != NULL) {
		g_array_free(wrr->wrr_s, TRUE);
		wrr->wrr_s = NULL;
	}
	wrr->wrr_index = -1;
	if (locked == TRUE)
		g_mutex_unlock(&(wrr->wrr_s_mutex));

	/** 销毁锁 */
	if (initlock == TRUE)
		lb_wrr_clear_lock(wrr);

	return;
}

/**
 * 增加权重
 * @param[inout] wrr结构
 * @param[in] weight 权重
 * @return 无
 */
void lb_wrr_append(LB_WRR *wrr, gint weight) {
	g_assert(wrr);
	g_assert(wrr->s);
	g_array_append_val(wrr->s, weight);
	return;
}

/**
 * 开始计算wrr序列
 * @param[inout] wrr结构
 * @param[in] locked是否加锁
 * @return 无
 */
void lb_wrr_calc(LB_WRR *wrr, gboolean locked) {
	gint i = 0;
	gint wrr_i = 0;
	g_assert(wrr);
	g_assert(wrr->s);
	g_assert(wrr->wrr_s);
	wrr->gcd = lb_wrr__getgcd(wrr->s);
	wrr->maxweight = lb_wrr__getmaxweight(wrr->s);
	wrr->sumweight = lb_wrr__getsumweight(wrr->s);
	wrr->index = -1;
	wrr->curweight = 0;
	/** 加锁 */
	if (locked == TRUE)
		g_mutex_lock(&(wrr->wrr_s_mutex));
	for (i = 0; i < wrr->sumweight; i++) {
		wrr_i = lb_wrr__getwrr(wrr->s, wrr->gcd, wrr->maxweight, &(wrr->index),
				&(wrr->curweight));
		g_array_append_val(wrr->wrr_s, wrr_i);
	}
	if (locked == TRUE)
		g_mutex_unlock(&(wrr->wrr_s_mutex));
	wrr->wrr_index = -1;
	return;
}

/**
 * 取一个下标
 * @param[inout] wrr结构
 * @return 返回下标
 */
gint lb_wrr_get(LB_WRR *wrr) {
	g_assert(wrr);
	if (wrr->wrr_s == NULL)
		return -1;
	if (wrr->wrr_s->len == 0)
		return -1;
	if (wrr->wrr_index < -1)
		wrr->wrr_index = -1;
	(wrr->wrr_index)++;
	if (wrr->wrr_index >= (gint)(wrr->wrr_s->len)) /**@fixme warning: comparison between signed and unsigned*/
		wrr->wrr_index = 0;
	return g_array_index(wrr->wrr_s, gint, wrr->wrr_index);
}

/**
 * 取一个下标，加锁
 * @param[inout] wrr结构
 * @return 返回下标
 */
gint lb_wrr_get_locked(LB_WRR *wrr) {
	gint i = -1;
	g_assert(wrr);
	/*g_assert(wrr->wrr_s_mutex);*/
	g_mutex_lock (&(wrr->wrr_s_mutex));
	i = lb_wrr_get(wrr);
	g_mutex_unlock (&(wrr->wrr_s_mutex));
	return i;
}


/*eof*/
