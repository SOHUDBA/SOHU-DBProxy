/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

 $%ENDLICENSE%$ */

/** @addtogroup unittests Unit tests */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "lb_wrr.h"

#if GLIB_CHECK_VERSION(2, 32, 0)
#define C(x) x, sizeof(x) - 1

GArray *s1 = NULL;
GArray *s2 = NULL;
GArray *s3 = NULL;

LB_WRR wrr1 = { .s=NULL };
GMutex m1;
GArray *wrr_a1 = NULL;
gint counter = 0;

void test_lb_wrr__getelement(void) {
	g_assert_cmpint(lb_wrr__getelement(s1, -1), ==, -1);
	g_assert_cmpint(lb_wrr__getelement(s1, 3), ==, -1);
	g_assert_cmpint(lb_wrr__getelement(s1, 0), ==, 5);
	g_assert_cmpint(lb_wrr__getelement(s1, 1), ==, 2);
	g_assert_cmpint(lb_wrr__getelement(s1, 2), ==, 3);
	return;
}

void test_lb_wrr__getmaxweight(void) {
	g_assert_cmpint(lb_wrr__getmaxweight(s1), ==, 5);
	g_assert_cmpint(lb_wrr__getmaxweight(s2), ==, 8);
	g_assert_cmpint(lb_wrr__getmaxweight(s3), ==, 8);
	return;
}

void test_lb_wrr__getsumweight(void) {
	g_assert_cmpint(lb_wrr__getsumweight(s1), ==, 10);
	g_assert_cmpint(lb_wrr__getsumweight(s2), ==, 16);
	g_assert_cmpint(lb_wrr__getsumweight(s3), ==, 24);
	return;
}

void test_lb_wrr__gcd(void) {
	g_assert_cmpint(lb_wrr__gcd(5,5), ==, 5);
	g_assert_cmpint(lb_wrr__gcd(5,3), ==, 1);
	g_assert_cmpint(lb_wrr__gcd(5,2), ==, 1);
	g_assert_cmpint(lb_wrr__gcd(5,1), ==, 1);
	g_assert_cmpint(lb_wrr__gcd(8,8), ==, 8);
	g_assert_cmpint(lb_wrr__gcd(8,4), ==, 4);
	g_assert_cmpint(lb_wrr__gcd(8,2), ==, 2);
	g_assert_cmpint(lb_wrr__gcd(8,1), ==, 1);
	return;
}

void test_lb_wrr__getgcd(void) {
	g_assert_cmpint(lb_wrr__getgcd(s1), ==, 1);
	g_assert_cmpint(lb_wrr__getgcd(s2), ==, 4);
	g_assert_cmpint(lb_wrr__getgcd(s3), ==, 8);
	return;
}

void test_lb_wrr__getwrr(void) {
	gint gcd = 1;
	gint maxweight = 0;
	gint i = -1;
	gint cw = 0;

	gcd = lb_wrr__getgcd(s1);
	maxweight = lb_wrr__getmaxweight(s1);
	i = -1;
	cw = 0;
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s1, gcd, maxweight, &i, &cw), ==, 0);

	gcd = lb_wrr__getgcd(s2);
	maxweight = lb_wrr__getmaxweight(s2);
	i = -1;
	cw = 0;
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s2, gcd, maxweight, &i, &cw), ==, 2);

	gcd = lb_wrr__getgcd(s3);
	maxweight = lb_wrr__getmaxweight(s3);
	i = -1;
	cw = 0;
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 0);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 1);
	g_assert_cmpint(lb_wrr__getwrr(s3, gcd, maxweight, &i, &cw), ==, 2);

	return;
}

void test_lb_wrr_init_clear(void) {
	LB_WRR wrr = { .s=NULL };
	GArray *a1 = NULL;
	GArray *a2 = NULL;

	lb_wrr_init_lock(&wrr);
	g_assert(&(wrr.wrr_s_mutex));
	lb_wrr_clear_lock(&wrr);
	g_assert(&(wrr.wrr_s_mutex));

	lb_wrr_init(&wrr, FALSE, FALSE);
	g_assert(wrr.s);
	g_assert_cmpint(wrr.gcd, ==, 1);
	g_assert_cmpint(wrr.maxweight, ==, 0);
	g_assert_cmpint(wrr.sumweight, ==, 0);
	g_assert_cmpint(wrr.index, ==, -1);
	g_assert_cmpint(wrr.curweight, ==, 0);
	g_assert(wrr.wrr_s);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert(&(wrr.wrr_s_mutex));
	a1 = wrr.s;
	a2 = wrr.wrr_s;

	lb_wrr_init_lock(&wrr);
	g_assert(&(wrr.wrr_s_mutex));

	lb_wrr_init(&wrr, TRUE, FALSE);
	g_assert(wrr.s);
	g_assert_cmpint(wrr.gcd, ==, 1);
	g_assert_cmpint(wrr.maxweight, ==, 0);
	g_assert_cmpint(wrr.sumweight, ==, 0);
	g_assert_cmpint(wrr.index, ==, -1);
	g_assert_cmpint(wrr.curweight, ==, 0);
	g_assert(wrr.wrr_s);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert(&(wrr.wrr_s_mutex));
	//g_assert(a1 != wrr.s); //it depends
	//g_assert(a2 != wrr.wrr_s);

	lb_wrr_clear(&wrr, TRUE, FALSE);
	g_assert(wrr.s == NULL);
	g_assert_cmpint(wrr.gcd, ==, 1);
	g_assert_cmpint(wrr.maxweight, ==, 0);
	g_assert_cmpint(wrr.sumweight, ==, 0);
	g_assert_cmpint(wrr.index, ==, -1);
	g_assert_cmpint(wrr.curweight, ==, 0);
	g_assert(wrr.wrr_s == NULL);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert(&(wrr.wrr_s_mutex));

	lb_wrr_clear_lock(&wrr);
	g_assert(&(wrr.wrr_s_mutex));

	return;
}

void test_lb_wrr_append(void) {
	LB_WRR wrr = { .s=NULL };
	lb_wrr_init(&wrr, TRUE, TRUE);

	lb_wrr_append(&wrr, 5);
	g_assert_cmpint((wrr.s)->len, ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.s, 0), ==, 5);
	lb_wrr_append(&wrr, 2);
	g_assert_cmpint((wrr.s)->len, ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.s, 1), ==, 2);
	lb_wrr_append(&wrr, 3);
	g_assert_cmpint((wrr.s)->len, ==, 3);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.s, 2), ==, 3);

	lb_wrr_clear(&wrr, TRUE, TRUE);
	return;
}

void test_lb_wrr_calc(void) {
	LB_WRR wrr = { .s=NULL };
	lb_wrr_init(&wrr, TRUE, TRUE);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 5);
	lb_wrr_append(&wrr, 2);
	lb_wrr_append(&wrr, 3);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 0), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 1), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 2), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 3), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 4), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 5), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 6), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 7), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 8), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 9), ==, 2);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 4);
	lb_wrr_append(&wrr, 4);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 0), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 1), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 2), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 3), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 4), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 5), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 6), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 7), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 8), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 9), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 10), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 11), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 12), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 13), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 14), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 15), ==, 2);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 8);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(wrr.wrr_index, ==, -1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 0), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 1), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 2), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 3), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 4), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 5), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 6), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 7), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 8), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 9), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 10), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 11), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 12), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 13), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 14), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 15), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 16), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 17), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 18), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 19), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 20), ==, 2);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 21), ==, 0);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 22), ==, 1);
	g_assert_cmpint(lb_wrr__getwrrindex(wrr.wrr_s, 23), ==, 2);

	lb_wrr_clear(&wrr, TRUE, TRUE);
	return;
}

void test_lb_wrr_get(void) {
	LB_WRR wrr = { .s=NULL };
	lb_wrr_init(&wrr, TRUE, TRUE);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 5);
	lb_wrr_append(&wrr, 2);
	lb_wrr_append(&wrr, 3);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 4);
	lb_wrr_append(&wrr, 4);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);

	lb_wrr_init(&wrr, TRUE, FALSE);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 8);
	lb_wrr_append(&wrr, 8);
	lb_wrr_calc(&wrr, TRUE);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 0);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 1);
	g_assert_cmpint(lb_wrr_get(&wrr), ==, 2);

	lb_wrr_clear(&wrr, TRUE, TRUE);
	return;
}

gpointer test_lb_wrr_get_multithreads_sub(gpointer data) {
	gint i = -1;
	(void)(data);
	while (counter <= 100) {
		i = lb_wrr_get_locked(&wrr1);
		g_mutex_lock(&m1);
		if (counter <= 100) {
			counter++;
			g_array_append_val(wrr_a1, i);
		}
		g_mutex_unlock(&m1);
		g_usleep(10000); /**< 1/100second */
	}
	return NULL;
}

void test_lb_wrr_get_multithreads(void) {
	GThread *thread1 = NULL;
	GThread *thread2 = NULL;
	GThread *thread3 = NULL;

	lb_wrr_init(&wrr1, TRUE, TRUE);
	lb_wrr_append(&wrr1, 5);
	lb_wrr_append(&wrr1, 2);
	lb_wrr_append(&wrr1, 3);
	lb_wrr_calc(&wrr1, TRUE);

	g_mutex_init(&m1);
	wrr_a1 = g_array_new(FALSE, FALSE, sizeof(gint));

	counter = 0;
	thread1 = g_thread_new("thread1", test_lb_wrr_get_multithreads_sub, NULL);
	thread2 = g_thread_new("thread2", test_lb_wrr_get_multithreads_sub, NULL);
	thread3 = g_thread_new("thread3", test_lb_wrr_get_multithreads_sub, NULL);
	g_thread_join(thread1);
	g_thread_join(thread2);
	g_thread_join(thread3);

	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 0), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 1), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 2), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 3), ==, 2);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 4), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 5), ==, 1);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 6), ==, 2);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 7), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 8), ==, 1);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 9), ==, 2);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 10), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 11), ==, 0);
	g_assert_cmpint(lb_wrr__getelement(wrr_a1, 12), ==, 0);

	g_mutex_clear(&m1);
	g_array_free(wrr_a1, TRUE);
	lb_wrr_clear(&wrr1, TRUE, TRUE);

	return;
}


void testinit(void) {
	gint i = 0;
	s1 = g_array_new(FALSE, FALSE, sizeof(gint));
	i = 5; g_array_append_val(s1, i);
	i = 2; g_array_append_val(s1, i);
	i = 3; g_array_append_val(s1, i);
	s2 = g_array_new(FALSE, FALSE, sizeof(gint));
	i = 8; g_array_append_val(s2, i);
	i = 4; g_array_append_val(s2, i);
	i = 4; g_array_append_val(s2, i);
	s3 = g_array_new(FALSE, FALSE, sizeof(gint));
	i = 8; g_array_append_val(s3, i);
	i = 8; g_array_append_val(s3, i);
	i = 8; g_array_append_val(s3, i);
	g_assert(s1);
	g_assert(s2);
	g_assert(s3);
	return;
}

int main(int argc, char **argv) {
	/*g_thread_init(NULL);*/

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	testinit();

	g_test_add_func("/core/lb_wrr__getelement", test_lb_wrr__getelement);
	g_test_add_func("/core/lb_wrr__getmaxweight", test_lb_wrr__getmaxweight);
	g_test_add_func("/core/lb_wrr__getsumweight", test_lb_wrr__getsumweight);
	g_test_add_func("/core/lb_wrr__gcd", test_lb_wrr__gcd);
	g_test_add_func("/core/lb_wrr__getgcd", test_lb_wrr__getgcd);
	g_test_add_func("/core/lb_wrr_init_clear", test_lb_wrr_init_clear);
	g_test_add_func("/core/lb_wrr_append", test_lb_wrr_append);
	g_test_add_func("/core/lb_wrr_calc", test_lb_wrr_calc);
	g_test_add_func("/core/lb_wrr_get", test_lb_wrr_get);
	g_test_add_func("/core/lb_wrr_get_multithreads", test_lb_wrr_get_multithreads);

	return g_test_run();
}

#else
int main() {
	return 77;
}

#endif



/*eof*/
