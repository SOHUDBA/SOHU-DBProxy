#include <stdarg.h>
#include <glib.h>

#include "network-mysqld.h"
#include "network-mysql-error.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len
#define ARRAY_LENGTH(x) (sizeof(x)/sizeof(x[0]))

typedef struct {
	mpe_errcode_t errcode;
	gchar *sqlstate;
	gchar *errmsg;
} mpe_error_mapping_t;

/*line number alignment begins*/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**
 * 错误编号对应的SQL状态值、错误消息。顺序要与 mpe_errcode_t 一致。
 */
static mpe_error_mapping_t MPE_ERRORS[] = {
{ MPE_ERRCODE_START_FROM , "HY000", NULL },
{ MPE_PRX_PRCRQ_SQL_UNSAFE , "HY000", "SQL not allowed: May be it's not safe to run this sentence" },
{ MPE_PRX_GETSRV_NO_BACKEND , "08S01", "No backend available" },
{ MPE_PRX_GETCON_TOO_MANY_CONNECTIONS , "08004", "Too many connections." },
{ MPE_PRX_GETCON_NO_CONNECTION_IN_POOL , "08S01", "Have tried %d times, no connection available on backend" },
{ MPE_PRX_RAUTH_UNKNOWN_USER , "28000", "unknown user" },
{ MPE_PRX_RAUTH_IP_NOT_ALLOWED , "HY000", "client ip is not allowed" },
{ MPE_PRX_RAUTH_PWD_SCRAMBLE_FAILED , "28000", "scrambling failed" },
{ MPE_PRX_RAUTH_PWD_NOT_MATCHED , "28000", "password doesn't match" },
{ MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS , "08004", "too many logins for this user. %s@%s, %d/%d" },
{ MPE_ADM_RAUTH_UNKNOWN_USER , "28000", "unknown user" },
{ MPE_ADM_RAUTH_PWD_SCRAMBLE_FAILED , "28000", "scrambling failed" },
{ MPE_ADM_RAUTH_PWD_NOT_MATCHED , "28000", "password doesn't match" },
{ MPE_PRX_GETCON_SPECIAL_QUERY, "42000", "cache server timeout, first query should not be select row_count() or select found_rows()!" },
{ MPE_PRX_RQRESULT_CONTEXT_RESTORE_FAILED, "42000", "DBProxy context recovery error on sql:%s." },
{ MPE_PRX_RQ_TX_TIMEOUT, "HY000" , "connection was killed for none query execution for long time in transaction or prepare. Will drop query of this time!" },
{ MPE_PRX_RQ_PACKET_TOO_LARGE, "08S01", "sql sentence exceeds max_allowded_packet!" },
{ MPE_ADM_HSTMT_UNKNOWN_QUERY , "08S01", "(admin-server) query not known" },
{ MPE_ADM_HSTMT_UNKNOWN_COMMAND , "08S01", "unknown COM_*" },
{ MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "42000", "%s not specified, please see %s for more informations." },
{ MPE_ADM_CMDPRC_ELEMENT_ALREADY_EXISTS, "42000", "%s you specified already exists." },
{ MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "42000", "encounter error when save in xml: %s" },
{ MPE_ADM_CMDPRC_ADD_BACKEND, "42000", "encounter error when adding backend" },
{ MPE_ADM_CMDPRC_ADD_LISTEN_SOCKET, "42000", "encounter error when adding listen socket" },
{ MPE_ADM_CMDPRC_DEL_LISTEN_SOCKET, "42000", "encounter error when deling listen socket" },
{ MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "42000", "%s you specified not exist." },
{ MPE_ADM_CMDPRC_PWD_NOT_MATCH, "42000", "the password of the user you want to add does not identify with password in proxy" },
{ MPE_ADM_CMDPRC_OPT_INVALID, "42000", "%s is invalid, it should be %s, please see %s for more informations." },
{ MPE_ADM_CMDPRC_CMD_SYNTAX_ERROR, "42000", "admin command syntax error" },
{ MPE_ADM_CMDPRC_CMD_OPT_IRRATIONAL, "42000", "admin command option is irrational" },
{ MPE_ADM_CMDPRC_COMMAND_NOT_SUPPORT, "42000", "admin command not supported" },
{ MPE_ADM_CMDPRC_COMMAND_NO_QUERY_SPECIFIED, "42000", "admin command should not be null" },
{ MPE_ADM_RQ_NEED_RESULTSET, "42000", "need a resultset + proxy.PROXY_SEND_RESULT" },
{ MPE_ADM_RQ_NEED_RESULTSET_SOMETHING, "42000", "need a resultset + proxy.PROXY_SEND_RESULT ... got something else" },
{ MPE_PRX_PRCRQ_SQL_TOO_MANY_PARA , "HY000", "sql para running is %d bigger than %s:%s para limit %d..." },
{ MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "42000", "encounter error when processing command:%s in mem..." },
{ MPE_PRX_PRCRQ_SQL_EXECUTE_TOO_LONG , "HY000", "execute too long for sql:%s, actual execute time is %ld us, but the limit is %ld us" },
{ MPE_PRX_PRCRQ_TOO_MANY_QUERY_IN_BYTES , "HY000", "sql run is banned for too many query in bytes, total query in bytes is %ld" },
{ MPE_PRX_PRCRQ_TOO_MANY_QUERY_OUT_BYTES , "HY000", "sql run is banned for too many query out bytes, total query out bytes is %ld" },
{ MPE_PRX_PRCRQ_TOO_MANY_QUERY_IN_NUM , "HY000", "sql run is banned for too many query in num, total query num is %ld" },
{ MPE_PRX_PRCRQ_DB_SIZE_OUT_OF_LIMIT , "HY000", "dml sql run is banned for db size out of limit" },
{ MPE_PRX_PRCRQ_SQL_NOT_SUPPORT , "HY000", "sql is not support" },

{ 0, NULL, NULL }
};
/*line number alignment ends*/


/**
 * 构造mpe_error_t，生成message等信息
 */
mpe_error_t *mpe_error_new(mpe_errcode_t errcode, va_list ap) {
	mpe_error_mapping_t *e = NULL;
	mpe_error_t *m = NULL;

	/**判断errcode范围是否正常*/
	if (errcode <= MPE_ERRCODE_START_FROM
			|| errcode >= MPE_ERRCODE_START_FROM+ARRAY_LENGTH(MPE_ERRORS)-1) {
		g_warning("errcode out of range: %d", errcode);
		return NULL ;
	}

	/**构造mpe_error_t*/
	m = g_new0(mpe_error_t, 1);
	if (m != NULL) {
		m->errmsg = g_string_new(NULL);
	}

	/**填充errmsg*/
	if (m != NULL) {
		e = &(MPE_ERRORS[errcode-MPE_ERRCODE_START_FROM]);
		m->errcode = e->errcode;
		m->sqlstate = e->sqlstate;
		if (e->errmsg != NULL) {
			g_string_append_vprintf(m->errmsg, e->errmsg, ap);
		}
	}

	return m;
}

/**
 * 销毁mpe_error_t
 */
void mpe_error_free(mpe_error_t *m) {
	if (m != NULL) {
		m->errcode = 0;
		m->sqlstate = NULL;
		if (m->errmsg != NULL) {
			g_string_free(m->errmsg, TRUE);
			m->errmsg = NULL;
		}
		g_free(m);
	}
	return;
}

/**
 * 将错误消息输出到日志
 */
void mpe_log_error(mpe_errcode_t errcode, ...) {
    va_list argp;
    mpe_error_t *m = NULL;

	va_start( argp, errcode );

	m = mpe_error_new(errcode, argp);
	if (m != NULL) {
		g_critical("errcode:%d, sqlstate:%s, errmsg:%s", m->errcode, m->sqlstate, m->errmsg->str);
	}

	if (m != NULL) {
		mpe_error_free(m);
		m = NULL;
	}
	va_end( argp );

	return;
}

/**
 * 将错误消息返回给客户端
 */
void mpe_send_error(network_socket *con, mpe_errcode_t errcode, ...) {
    va_list argp;
    mpe_error_t *m = NULL;

	va_start( argp, errcode );

	m = mpe_error_new(errcode, argp);
	if (m != NULL) {
		network_mysqld_con_send_error_full(con, S(m->errmsg), m->errcode, m->sqlstate);
	}

	if (m != NULL) {
		mpe_error_free(m);
		m = NULL;
	}
	va_end( argp );

	return;
}


/*eof*/

