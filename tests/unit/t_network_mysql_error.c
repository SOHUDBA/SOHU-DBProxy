#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <signal.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#endif /* WIN32 */

#include <glib.h>
#include "network-mysql-error.h"

/**
 * 不带可变参数的
 */
void test_mpe_error_new_MPE_PRX_SQL_UNSAFE_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert_cmpint(m->errcode, ==, MPE_PRX_PRCRQ_SQL_UNSAFE);
	g_assert_cmpstr(m->sqlstate, ==, "HY000");
	g_assert_cmpstr(m->errmsg->str, ==, "SQL not allowed: May be it's not safe to run this sentence");
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_PRX_SQL_UNSAFE(void) {
	test_mpe_error_new_MPE_PRX_SQL_UNSAFE_0(MPE_PRX_PRCRQ_SQL_UNSAFE);
	return;
}

/**
 * 可变参数有一个
 */
void test_mpe_error_new_MPE_PRX_GETCON_NO_AVAIL_CON_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert_cmpint(m->errcode, ==, MPE_PRX_GETCON_NO_CONNECTION_IN_POOL);
	g_assert_cmpstr(m->sqlstate, ==, "08S01");
	g_assert_cmpstr(m->errmsg->str, ==, "Have tried 5 times, no connection available on backend");
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_PRX_GETCON_NO_AVAIL_CON(void) {
	test_mpe_error_new_MPE_PRX_GETCON_NO_AVAIL_CON_0(MPE_PRX_GETCON_NO_CONNECTION_IN_POOL, 5);
	return;
}

/**
 * 可变参数有多个
 */
void test_mpe_error_new_MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert_cmpint(m->errcode, ==, MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS);
	g_assert_cmpstr(m->sqlstate, ==, "08004");
	g_assert_cmpstr(m->errmsg->str, ==, "too many logins for this user. root@localhost, 10/10");
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS(void) {
	test_mpe_error_new_MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS_0(MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS, "root", "localhost", 10, 10);
	return;
}

/**
 * 错误号等于3000
 */
void test_mpe_error_new_MPE_ERRCODE_START_FROM_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert(m == NULL);
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_ERRCODE_START_FROM(void) {
	test_mpe_error_new_MPE_ERRCODE_START_FROM_0(MPE_ERRCODE_START_FROM);
	return;
}

/**
 * 错误号比3000小，等于2999
 */
void test_mpe_error_new_MPE_ERRCODE_START_FROM_less_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert(m == NULL);
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_ERRCODE_START_FROM_less(void) {
	test_mpe_error_new_MPE_ERRCODE_START_FROM_less_0(MPE_ERRCODE_START_FROM-1);
	return;
}

/**
 * 错误号比3000大很多，等于4000
 */
void test_mpe_error_new_MPE_ERRCODE_too_large_0(mpe_errcode_t errcode, ...) {
	va_list ap;
	va_start( ap, errcode );

	mpe_error_t *m = NULL;
	m = mpe_error_new(errcode, ap);
	g_assert(m == NULL);
	mpe_error_free(m);

	va_end( ap );
	return;
}
void test_mpe_error_new_MPE_ERRCODE_too_large(void) {
	test_mpe_error_new_MPE_ERRCODE_too_large_0(4000);
	return;
}

int main(int argc, char **argv) {
	gint ret = 0;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal (G_LOG_LEVEL_ERROR);

	g_test_add_func("/core/mpe_error_new_MPE_PRX_SQL_UNSAFE", test_mpe_error_new_MPE_PRX_SQL_UNSAFE);
	g_test_add_func("/core/mpe_error_new_MPE_PRX_GETCON_NO_AVAIL_CON", test_mpe_error_new_MPE_PRX_GETCON_NO_AVAIL_CON);
	g_test_add_func("/core/mpe_error_new_MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS", test_mpe_error_new_MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS);
	g_test_add_func("/core/mpe_error_new_MPE_ERRCODE_START_FROM", test_mpe_error_new_MPE_ERRCODE_START_FROM);
	g_test_add_func("/core/mpe_error_new_MPE_ERRCODE_START_FROM_less", test_mpe_error_new_MPE_ERRCODE_START_FROM_less);
	g_test_add_func("/core/mpe_error_new_MPE_ERRCODE_too_large", test_mpe_error_new_MPE_ERRCODE_too_large);

	ret = g_test_run();
	chassis_log_free(log);

	return ret;
}
