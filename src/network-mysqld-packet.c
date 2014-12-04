/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2012, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
/**
 * codec's for the MySQL client protocol
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "network-mysqld-packet.h"
#include "network_mysqld_type.h"
#include "network_mysqld_proto_binary.h"
//#include "sql-tokenizer.h"
#include "glib-ext.h"
#include "chassis-regex.h"

#ifndef CLIENT_PLUGIN_AUTH
#define CLIENT_PLUGIN_AUTH (1 << 19)
#endif

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

network_mysqld_com_query_result_t *network_mysqld_com_query_result_new() {
	network_mysqld_com_query_result_t *com_query;

	com_query = g_new0(network_mysqld_com_query_result_t, 1);
	com_query->state = PARSE_COM_QUERY_INIT;
	com_query->query_status = MYSQLD_PACKET_NULL; /* can have 3 values: NULL for unknown, OK for a OK packet, ERR for a error-packet */

	return com_query;
}

void network_mysqld_com_query_result_free(network_mysqld_com_query_result_t *udata) {
	if (!udata) return;

	g_free(udata);
}

/**
 * unused
 *
 * @deprecated will be removed in 0.9
 * @see network_mysqld_proto_get_com_query_result
 */
int network_mysqld_com_query_result_track_state(network_packet G_GNUC_UNUSED *packet, network_mysqld_com_query_result_t G_GNUC_UNUSED *udata) {
	g_error("%s: this function is deprecated and network_mysqld_proto_get_com_query_result() should be used instead",
			G_STRLOC);
}
/**
 * @return -1 on error
 *         0  on success and done
 *         1  on success and need more
 */
/**
 * @author ORA-inc &&　sohu-inc.com
 * 我们对函数做了修改，1添加了参数，使得可以设置con->tx_flag字段.
 * 因为我们还需要对连接的autocommit字段进行维护，因而这里还需要更具情况对con->autocommit字段重置。
 * @param packet 从server端读回的结果数据包
 * @param query 记录查询语句信息
 * @param use_binary_row_data
 * @param con 正在处理的连接
 */
int network_mysqld_proto_get_com_query_result(network_packet *packet, network_mysqld_com_query_result_t *query, gboolean use_binary_row_data, network_mysqld_con *con) {
	int is_finished = 0;
	guint8 status;
	int err = 0;
	network_mysqld_eof_packet_t *eof_packet;
	network_mysqld_ok_packet_t *ok_packet;

	/**
	 * if we get a OK in the first packet there will be no result-set
	 */
	switch (query->state) {
	case PARSE_COM_QUERY_INIT:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) break;

		switch (status) {
		case MYSQLD_PACKET_ERR: /* e.g. SELECT * FROM dual -> ERROR 1096 (HY000): No tables used */
			query->query_status = MYSQLD_PACKET_ERR;
			if (con->is_injection) {
				con->inj_execute_correctly = FALSE;
			}
			is_finished = 1;
			break;
		case MYSQLD_PACKET_OK:  /* e.g. DELETE FROM tbl */
			query->query_status = MYSQLD_PACKET_OK;

			ok_packet = network_mysqld_ok_packet_new();

			err = err || network_mysqld_proto_get_ok_packet(packet, ok_packet);

			if (!err) {
				if (ok_packet->server_status & SERVER_MORE_RESULTS_EXISTS) {
			
				} else {
					is_finished = 1;
				}
				if (con->multiplex) {
					// 连接复用才需要对连接的字符集、事务、prepare特性进行判断
					/**
					 * @author sohu-inc.com
					 * 因为com_query的结果集跟踪比较复杂，这里我们将事务性的处理直接写在了判断结果集是否返回结束的函数中进行
					 */
					// added by sohu-inc.com, 遇到eof数据包时需要重新设置事务标志字段
					if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
						con->tx_flag = 1;
					} else {
						con->tx_flag = 0;
					}
					/**
					 * @author sohu-inc.com
					 * 重新设置client及server 的autocommit标志字段
					 */
					if (ok_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
						con->client->autocommit = 1;
						con->server->autocommit = 1;
					} else {
						con->client->autocommit = 0;
						con->server->autocommit = 0;
					}
					/**
					 * 区分了是否是注入的查询语句可以减少上下文恢复的很多工作
					 * @todo autocommit 及database的恢复需要加以区分
					 */

					if (con->is_injection) {
						g_assert(con->sql_running);
						g_message("[%s]:the sql running is-> %s", G_STRLOC, con->sql_running->str);
						if (is_set_client_charset(con->srv->regs, con->sql_running->str)) {
							g_string_truncate(con->server->character_set_client, 0);
							g_string_append(con->server->character_set_client, con->client->character_set_client->str);
						} else if (is_set_connect_charset(con->srv->regs, con->sql_running->str)) {
							g_string_truncate(con->server->character_set_connection, 0);
							g_string_append(con->server->character_set_connection, con->client->character_set_connection->str);
							// 这里需要将 server 的 connection collation 设置为字符集默认的校验
							gint index = get_default_collation_index(con->client->character_set_connection->str);
							const gchar * collation_name = NULL;

							if (index > -1) {
								collation_name = distinct_collations[index];
							} else if (g_ascii_strcasecmp("default", con->client->character_set_connection->str)) {
								collation_name = "default";
							}

							if (NULL != collation_name) {
								g_string_truncate(con->server->collection_connect, 0);
								g_string_append(con->server->collection_connect, collation_name);
							}
						} else if (is_set_results_charset(con->srv->regs, con->sql_running->str)) {
							g_string_truncate(con->server->character_set_results, 0);
							g_string_append(con->server->character_set_results, con->client->character_set_results->str);
						} else if (is_set_connect_collation(con->srv->regs, con->sql_running->str)) {
							g_string_truncate(con->server->collection_connect, 0);
							g_string_append(con->server->collection_connect, con->client->collection_connect->str);
							guint8 index = -1;
							const gchar * charset_name = NULL;
							if (is_correct_collationname(con->client->collection_connect->str, &index)) {
								charset_name = charset_dic[index];
							} else if (g_ascii_strcasecmp("default", con->client->collection_connect->str)) {
								charset_name = "default";
							}

							if (NULL != charset_name) {
								g_string_truncate(con->server->character_set_connection, 0);
								g_string_append(con->server->character_set_connection, con->client->character_set_connection->str);
							}

						}
					} else {
						g_message("[%s]:the sql running is->%s from client", G_STRLOC, con->sql_running->str);
						g_assert(con->sql_running);
						if(con->tokens && con->tokens->len > 0) {
							guint len = con->tokens->len;
							if (0 == g_ascii_strcasecmp(con->first_key->str, "set")) {
								if (is_set_client_charset(con->srv->regs, con->sql_running->str)) {
									g_string_truncate(con->server->character_set_client, 0);
									g_string_truncate(con->client->character_set_client, 0);
									//g_string_append(con->server->character_set_client, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									//g_string_append(con->client->character_set_client, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									g_string_append(con->server->character_set_client, con->last_key->str);
									g_string_append(con->client->character_set_client, con->last_key->str);
								} else if (is_set_connect_charset(con->srv->regs, con->sql_running->str)) {
									g_string_truncate(con->server->character_set_connection, 0);
									g_string_truncate(con->client->character_set_connection, 0);
									//g_string_append(con->server->character_set_connection, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									//g_string_append(con->client->character_set_connection, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									g_string_append(con->server->character_set_connection, con->last_key->str);
									g_string_append(con->client->character_set_connection, con->last_key->str);

									// 这里需要将client 和 server 的 connection collation 设置为字符集默认的校验
									gint index = get_default_collation_index(con->last_key->str);
									const gchar * collation_name = NULL;

									if (index > -1) {
										collation_name = distinct_collations[index];
									} else if (g_ascii_strcasecmp("default", con->last_key->str)) {
										collation_name = "default";
									}

									if (NULL != collation_name) {
										g_string_truncate(con->server->collection_connect, 0);
										g_string_truncate(con->client->collection_connect, 0);
										//g_string_append(con->server->character_set_connection, ((sql_token *)con->tokens->pdata[len-1])->text->str);
										//g_string_append(con->client->character_set_connection, ((sql_token *)con->tokens->pdata[len-1])->text->str);
										g_string_append(con->server->collection_connect, collation_name);
										g_string_append(con->client->collection_connect, collation_name);
									}
								} else if (is_set_results_charset(con->srv->regs, con->sql_running->str)) {
									g_string_truncate(con->server->character_set_results, 0);
									g_string_truncate(con->client->character_set_results, 0);
									//g_string_append(con->server->character_set_results, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									//g_string_append(con->client->character_set_results, ((sql_token *)con->tokens->pdata[len-1])->text->str);
									g_string_append(con->server->character_set_results, con->last_key->str);
									g_string_append(con->client->character_set_results, con->last_key->str);
								} else if (is_set_names(con->srv->regs, con->sql_running->str)) {
									/**
									 * @author sohu-inc.com
									 * 设置character_set_results的值
									 */
									g_string_truncate(con->server->character_set_results, 0);
									g_string_truncate(con->client->character_set_results, 0);
									g_string_append(con->server->character_set_results, con->last_key->str);
									g_string_append(con->client->character_set_results, con->last_key->str);

									/**
									 * @author sohu-inc.com
									 * 设置character_set_connection的值
									 */
									g_string_truncate(con->server->character_set_connection, 0);
									g_string_truncate(con->client->character_set_connection, 0);
									g_string_append(con->server->character_set_connection, con->last_key->str);
									g_string_append(con->client->character_set_connection, con->last_key->str);

									// 这里需要将client 和 server 的 connection collation 设置为字符集默认的校验
									gint index = get_default_collation_index(con->last_key->str);
									const gchar * collation_name = NULL;

									if (index > -1) {
										collation_name = distinct_collations[index];
									} else if (g_ascii_strcasecmp("default", con->last_key->str)) {
										collation_name = "default";
									}

									if (NULL != collation_name) {
										g_string_truncate(con->server->collection_connect, 0);
										g_string_truncate(con->client->collection_connect, 0);
										g_string_append(con->server->collection_connect, collation_name);
										g_string_append(con->client->collection_connect, collation_name);
									}

									/**
									 * @author sohu-inc.com
									 * 设置character_set_client的值
									 */
									g_string_truncate(con->server->character_set_client, 0);
									g_string_truncate(con->client->character_set_client, 0);
									g_string_append(con->server->character_set_client, con->last_key->str);
									g_string_append(con->client->character_set_client, con->last_key->str);
								} else if (is_set_connect_collation(con->srv->regs, con->sql_running->str)) {
									// 需要将collation  修正，并且将对应的character set 设置为对应的字符集
									// 这里的代码太冗余了 ，可以精简一下！！！！
									g_string_truncate(con->client->collection_connect, 0);
									g_string_truncate(con->server->collection_connect, 0);
									g_string_append(con->client->collection_connect, con->last_key->str);
									g_string_append(con->server->collection_connect, con->last_key->str);
									guint8 index = -1;
									const gchar * charset_name = NULL;
									if (is_correct_collationname(con->last_key->str, &index)) {
										charset_name = charset_dic[index];
									} else if (g_ascii_strcasecmp("default", con->last_key->str)) {
										charset_name = "default";
									}

									if (NULL != charset_name) {
										g_string_truncate(con->client->character_set_connection, 0);
										g_string_append(con->server->character_set_connection, con->client->character_set_connection->str);
										g_string_truncate(con->client->character_set_connection, 0);
										g_string_append(con->server->character_set_connection, con->client->character_set_connection->str);

									}
								}
							} else if (0 == g_ascii_strcasecmp(con->first_key->str, "prepare")) {
								// prepare 语句的处理
								g_assert(len >= 2);
								/*g_string_ascii_down直接修改str，所以这里要复制一份*/
								GString *str = g_string_new (con->second_key->str);
								GString *stmtname = g_string_ascii_down (str);
								if (!g_hash_table_lookup(con->stmtnames, stmtname)) {
									gint *value = g_new0(gint, 1);
									*value = 1;
									g_hash_table_insert(con->stmtnames, stmtname, value);
								} else {
									g_string_free(stmtname, TRUE);
								}
							} else if (0 == g_ascii_strcasecmp(con->first_key->str, "deallocate")) {
								// deallocate 语句的处理
								GString *str = g_string_new (con->last_key->str);
								GString *stmtname = g_string_ascii_down (str);
								g_hash_table_remove(con->stmtnames, stmtname);
								g_string_free(stmtname, TRUE);
							} else if (0 == g_ascii_strcasecmp(con->first_key->str, "use")) {
								// use 语句的处理
								GString *str = g_string_new (con->last_key->str);
								GString *dbname = g_string_ascii_down (str);
								g_string_truncate(con->client->default_db, 0);
								g_string_truncate(con->server->default_db, 0);
								g_string_append_len(con->client->default_db, S(dbname));
								g_string_append_len(con->server->default_db, S(dbname));
								g_string_free(dbname, TRUE);
							} else if (0 == g_ascii_strcasecmp(con->first_key->str, "drop")) {
								// drop 语句的处理
								if (len > 2 && ( 0 == g_ascii_strcasecmp(con->second_key->str, "database")
										|| 0 == g_ascii_strcasecmp(con->second_key->str, "schema") )
										) {
									GString *dbname = con->last_key;
									if (con->client->default_db != NULL) {
										if (0 == g_ascii_strcasecmp(con->client->default_db->str, dbname->str)) {
											g_string_truncate(con->client->default_db, 0);
										}
									}
									if (con->server->default_db != NULL) {
										if (0 == g_ascii_strcasecmp(con->server->default_db->str, dbname->str)) {
											g_string_truncate(con->server->default_db, 0);
										}
									}
								}
							}
							// 需要将first 清空避免对下一次执行造成错误；
							// 如 prepare长时间没有执行被kill, 接下来执行一个com_init_db 语句会导致core

							g_string_truncate(con->first_key, 0);
						}
					}
				}
				query->server_status = ok_packet->server_status;
				query->warning_count = ok_packet->warnings;
				query->affected_rows = ok_packet->affected_rows;
				query->insert_id     = ok_packet->insert_id;
				query->was_resultset = 0;
				query->binary_encoded= use_binary_row_data; 
			}

			network_mysqld_ok_packet_free(ok_packet);

			break;
		case MYSQLD_PACKET_NULL:
			/* OH NO, LOAD DATA INFILE :) */
			query->state = PARSE_COM_QUERY_LOCAL_INFILE_DATA;
			is_finished = 1;

			break;
		case MYSQLD_PACKET_EOF:
			g_critical("%s: COM_QUERY packet should not be (EOF), got: 0x%02x",
					G_STRLOC,
					status);

			err = 1;

			break;
		default:
			query->query_status = MYSQLD_PACKET_OK;
			/* looks like a result */
			query->state = PARSE_COM_QUERY_FIELD;
			break;
		}
		break;
	case PARSE_COM_QUERY_FIELD:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) break;

		switch (status) {
		case MYSQLD_PACKET_ERR:
		case MYSQLD_PACKET_OK:
		case MYSQLD_PACKET_NULL:
			g_critical("%s: COM_QUERY should not be (OK|NULL|ERR), got: 0x%02x",
					G_STRLOC,
					status);

			err = 1;

			break;
		case MYSQLD_PACKET_EOF:
			/**
			 * in 5.0 we have CURSORs which have no rows, just a field definition
			 *
			 * TODO: find a test-case for it, is it COM_STMT_EXECUTE only?
			 */
			if (packet->data->len == 9) {
				eof_packet = network_mysqld_eof_packet_new();

				err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);

				if (!err) {
#if MYSQL_VERSION_ID >= 50000
					/* 5.5 may send a SERVER_MORE_RESULTS_EXISTS as part of the first 
					 * EOF together with SERVER_STATUS_CURSOR_EXISTS. In that case,
					 * we aren't finished. (#61998)
					 *
					 * Only if _CURSOR_EXISTS is set alone, we have a field-definition-only
					 * resultset
					 */
					if (eof_packet->server_status & SERVER_STATUS_CURSOR_EXISTS &&
					    !(eof_packet->server_status & SERVER_MORE_RESULTS_EXISTS)) {
						is_finished = 1;
					} else {
						query->state = PARSE_COM_QUERY_RESULT;
					}
#else
					query->state = PARSE_COM_QUERY_RESULT;
#endif
					
					// added by sohu-inc.com, 遇到eof数据包时需要重新设置事务标志字段
					if (con->multiplex) {
						if (eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
							con->tx_flag = 1;
						} else {
							con->tx_flag = 0;
						}
						/**
						 * @author sohu-inc.com
						 * 重新设置client及server 的autocommit标志字段
						 */
						if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
							con->client->autocommit = 1;
							con->server->autocommit = 1;
						} else {
							con->client->autocommit = 0;
							con->server->autocommit = 0;
						}
					}
                    /* track the server_status of the 1st EOF packet */
					query->server_status = eof_packet->server_status;
				}

				network_mysqld_eof_packet_free(eof_packet);
			} else {
				query->state = PARSE_COM_QUERY_RESULT;
			}
			break;
		default:
			break;
		}
		break;
	case PARSE_COM_QUERY_RESULT:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) break;

		switch (status) {
		case MYSQLD_PACKET_EOF:
			if (packet->data->len == 9) {
				eof_packet = network_mysqld_eof_packet_new();

				err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);

				if (!err) {
					query->was_resultset = 1;

#ifndef SERVER_PS_OUT_PARAMS
#define SERVER_PS_OUT_PARAMS 4096
#endif
					/**
					 * a PS_OUT_PARAMS is set if a COM_STMT_EXECUTE executes a CALL sp(?) where sp is a PROCEDURE with OUT params 
					 *
					 * ...
					 * 05 00 00 12 fe 00 00 0a 10 -- end column-def (auto-commit, more-results, ps-out-params)
					 * ...
					 * 05 00 00 14 fe 00 00 02 00 -- end of rows (auto-commit), see the missing (more-results, ps-out-params)
					 * 07 00 00 15 00 00 00 02 00 00 00 -- OK for the CALL
					 *
					 * for all other resultsets we trust the status-flags of the 2nd EOF packet
					 */
					if (!(query->server_status & SERVER_PS_OUT_PARAMS)) {
						query->server_status = eof_packet->server_status;
					}
					query->warning_count = eof_packet->warnings;

					if (query->server_status & SERVER_MORE_RESULTS_EXISTS) {
						query->state = PARSE_COM_QUERY_INIT;
					} else {
						is_finished = 1;
					}
					// added by sohu-inc.com, 遇到eof数据包时需要重新设置事务标志字段
					if (con->multiplex) {
						if(eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
							con->tx_flag = 1;
						} else {
							con->tx_flag = 0;
						}
						/**
						 * @author sohu-inc.com
						 * 重新设置client及server 的autocommit标志字段
						 */
						 if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
							 con->client->autocommit = 1;
							 con->server->autocommit = 1;
						 } else {
							 con->client->autocommit = 0;
							 con->server->autocommit = 0;
						 }
					}
				}

				network_mysqld_eof_packet_free(eof_packet);
			}

			break;
		case MYSQLD_PACKET_ERR:
			/* like 
			 * 
			 * EXPLAIN SELECT * FROM dual; returns an error
			 * 
			 * EXPLAIN SELECT 1 FROM dual; returns a result-set
			 * */
			is_finished = 1;
			break;
		case MYSQLD_PACKET_OK:
		case MYSQLD_PACKET_NULL:
			if (use_binary_row_data) {
				/* fallthrough to default:
				   0x00 is part of the protocol for binary row packets
				 */
			} else {
				/* the first field might be a NULL for a text row packet */
				break;
			}
		default:
			query->rows++;
			query->bytes += packet->data->len;
			break;
		}
		break;
	case PARSE_COM_QUERY_LOCAL_INFILE_DATA: 
		/* we will receive a empty packet if we are done */
		if (packet->data->len == packet->offset) {
			query->state = PARSE_COM_QUERY_LOCAL_INFILE_RESULT;
			is_finished = 1;
		}
		break;
	case PARSE_COM_QUERY_LOCAL_INFILE_RESULT:
		err = err || network_mysqld_proto_get_int8(packet, &status);
		if (err) break;

		switch (status) {
		case MYSQLD_PACKET_OK:
			/**
			 * 
			 * 这是一个普通的数据包吗？就当做普通的ok数据包来处理？
			 */
			if (con->multiplex) {
				ok_packet = network_mysqld_ok_packet_new();

				err = err || network_mysqld_proto_get_ok_packet(packet, ok_packet);

				if (!err) {
					/**
					 * @author sohu-inc.com
					 * 因为com_query的结果集跟踪比较复杂，这里我们将事务性的处理直接卸载了判断结果集是否返回结束的函数中进行
					 */
					// added by sohu-inc.com, 遇到eof数据包时需要重新设置事务标志字段
					if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
						con->tx_flag = 1;
					} else {
						con->tx_flag = 0;
					}
					/**
					 * @author sohu-inc.com
					 * 重新设置client及server 的autocommit标志字段
					 */
					if (ok_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
						con->client->autocommit = 1;
						con->server->autocommit = 1;
					} else {
						con->client->autocommit = 0;
						con->server->autocommit = 0;
					}
				}

				network_mysqld_ok_packet_free(ok_packet);
			}
			is_finished = 1;
			break;
		case MYSQLD_PACKET_NULL:
		case MYSQLD_PACKET_ERR:
		case MYSQLD_PACKET_EOF:
		default:
			g_critical("%s: COM_QUERY,should be (OK), got: 0x%02x",
					G_STRLOC,
					status);

			err = 1;

			break;
		}

		break;
	}

	if (err) return -1;

	return is_finished;
}

/**
 * check if the we are in the LOCAL INFILE 'send data from client' state
 *
 * is deprecated as the name doesn't reflect its purpose:
 * - it isn't triggered for LOAD DATA INFILE (w/o LOCAL)
 * - it also covers LOAD XML LOCAL INFILE
 *
 * @deprecated use network_mysqld_com_query_result_is_local_infile() instead
 */
gboolean network_mysqld_com_query_result_is_load_data(network_mysqld_com_query_result_t *udata) {
	return network_mysqld_com_query_result_is_local_infile(udata);
}

/**
 * check if the we are in the LOCAL INFILE 'send data from client' state
 */
gboolean network_mysqld_com_query_result_is_local_infile(network_mysqld_com_query_result_t *udata) {
	return (udata->state == PARSE_COM_QUERY_LOCAL_INFILE_DATA) ? TRUE : FALSE;
}

network_mysqld_com_stmt_prepare_result_t *network_mysqld_com_stmt_prepare_result_new() {
	network_mysqld_com_stmt_prepare_result_t *udata;

	udata = g_new0(network_mysqld_com_stmt_prepare_result_t, 1);
	udata->first_packet = TRUE;

	return udata;
}

void network_mysqld_com_stmt_prepare_result_free(network_mysqld_com_stmt_prepare_result_t *udata) {
	if (!udata) return;

	g_free(udata);
}

int network_mysqld_proto_get_com_stmt_prepare_result(
		network_packet *packet, 
		network_mysqld_com_stmt_prepare_result_t *udata,
		network_mysqld_con *con) {
	guint8 status;
	int is_finished = 0;
	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &status);

	if (udata->first_packet == 1) {
		if (!con->multiplex) {
			udata->first_packet = 0;
		}

		switch (status) {
		case MYSQLD_PACKET_OK:
			/**
			 * @author sohu-inc.com
			 * 对于协议级别的prepare语句，需要保存prepare statement的id
			 * prepare statement的id的获取在这里进行。
			 */
			g_assert(packet->data->len == 12 + NET_HEADER_SIZE); 

			/* the header contains the number of EOFs we expect to see
			 * - no params -> 0
			 * - params | fields -> 1
			 * - params + fields -> 2 
			 */
			// 将新的prepare的id，放到con的id列表中
			// 注意要确保，将缓存的数据释放到共享连接池时这个列表是被清空的
			if (con->multiplex) {
				guint id_tmp = 0;
				packet->offset = 5; // stmt id 是从地六个字节开始的，长度是4字节32位
				network_mysqld_proto_get_int32(packet, &id_tmp);

				g_message("[%s]:get prepare statement sql of which id is %d", G_STRLOC, id_tmp);

				gint *key = g_new0(gint, 1);
				*key = id_tmp;
				gint *value = g_new0(gint, 1);
				*value = id_tmp;
				g_hash_table_insert(con->stmtids, key, value);
			}
			udata->want_eofs = 0;
			
			if (packet->data->str[NET_HEADER_SIZE + 5] != 0 || packet->data->str[NET_HEADER_SIZE + 6] != 0) {
				udata->want_eofs++;
			}
			if (packet->data->str[NET_HEADER_SIZE + 7] != 0 || packet->data->str[NET_HEADER_SIZE + 8] != 0) {
				udata->want_eofs++;
			}

			if (udata->want_eofs == 0) {
				is_finished = 1;
			}

			break;
		case MYSQLD_PACKET_ERR:
			is_finished = 1;
			break;
		default:
			g_error("%s.%d: COM_STMT_PREPARE should either get a (OK|ERR), got %02x",
					__FILE__, __LINE__,
					status);
			break;
		}
	} else {
		switch (status) {
		case MYSQLD_PACKET_OK:
		case MYSQLD_PACKET_NULL:
		case MYSQLD_PACKET_ERR:
			g_error("%s.%d: COM_STMT_PREPARE should not be (OK|ERR|NULL), got: %02x",
					__FILE__, __LINE__,
					status);
			break;
		case MYSQLD_PACKET_EOF:
			if (--udata->want_eofs == 0) {
				is_finished = 1;
			}
			break;
		default:
			break;
		}
	}

	if (err) return -1;

	return is_finished;
}

network_mysqld_com_init_db_result_t *network_mysqld_com_init_db_result_new() {
	network_mysqld_com_init_db_result_t *udata;

	udata = g_new0(network_mysqld_com_init_db_result_t, 1);
	udata->db_name = NULL;

	return udata;
}


void network_mysqld_com_init_db_result_free(network_mysqld_com_init_db_result_t *udata) {
	if (udata->db_name) g_string_free(udata->db_name, TRUE);

	g_free(udata);
}

int network_mysqld_com_init_db_result_track_state(network_packet *packet, network_mysqld_com_init_db_result_t *udata) {
	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_skip(packet, 1); /* the command */

	if (packet->offset != packet->data->len) {
		udata->db_name = g_string_new(NULL);

		network_mysqld_proto_get_gstring_len(packet, packet->data->len - packet->offset, udata->db_name);
	} else {
		if (udata->db_name) g_string_free(udata->db_name, TRUE);
		udata->db_name = NULL;
	}

	return 0;
}

int network_mysqld_proto_get_com_init_db(
		network_packet *packet, 
		network_mysqld_com_init_db_result_t *udata,
		network_mysqld_con *con) {
	guint8 status;
	int is_finished;
	int err = 0;

	/**
	 * in case we have a init-db statement we track the db-change on the server-side
	 * connection
	 */
	err = err || network_mysqld_proto_get_int8(packet, &status);

	switch (status) {
	case MYSQLD_PACKET_ERR:
		if (con->is_injection) {
			con->inj_execute_correctly = FALSE;
		}
		is_finished = 1;
		break;
	case MYSQLD_PACKET_OK:
		/**
		 * track the change of the init_db */
		if (con->server) g_string_truncate(con->server->default_db, 0);
		g_string_truncate(con->client->default_db, 0);

		if (udata->db_name && udata->db_name->len) {
			if (con->server) {
				g_string_append_len(con->server->default_db, 
						S(udata->db_name));
			}
			
			g_string_append_len(con->client->default_db, 
					S(udata->db_name));
		}
		 
		is_finished = 1;
		break;
	default:
		g_critical("%s.%d: COM_INIT_DB should be (ERR|OK), got %02x",
				__FILE__, __LINE__,
				status);

		return -1;
	}

	if (err) return -1;

	return is_finished;
}

/**
 * init the tracking of the sub-states of the protocol
 */
int network_mysqld_con_command_states_init(network_mysqld_con *con, network_packet *packet) {
	guint8 cmd;
	int err = 0;

	err = err || network_mysqld_proto_skip_network_header(packet);
	err = err || network_mysqld_proto_get_int8(packet, &cmd);

	if (err) {
		con->state = CON_STATE_ERROR;
		return -1;
	}

	con->parse.command = cmd;

	packet->offset = 0; /* reset the offset again for the next functions */

	/* init the parser for the commands */
	switch (con->parse.command) {
	case COM_QUERY:
	case COM_PROCESS_INFO:
	case COM_STMT_EXECUTE:
		con->parse.data = network_mysqld_com_query_result_new();
		con->parse.data_free = (GDestroyNotify)network_mysqld_com_query_result_free;
		break;
	case COM_STMT_PREPARE:
		con->parse.data = network_mysqld_com_stmt_prepare_result_new();
		con->parse.data_free = (GDestroyNotify)network_mysqld_com_stmt_prepare_result_free;
		break;
	case COM_STMT_CLOSE:
		/**
		 * @author sohu-inc.com
		 */
		if (con->multiplex) {
			network_mysqld_proto_skip_network_header(packet);
			network_mysqld_proto_skip(packet, 1); /* the command */

			g_assert(packet->offset < packet->data->len);

			network_mysqld_proto_get_int32(packet, &con->last_id);
		}
		break;
	case COM_INIT_DB:
		con->parse.data = network_mysqld_com_init_db_result_new();
		con->parse.data_free = (GDestroyNotify)network_mysqld_com_init_db_result_free;

		network_mysqld_com_init_db_result_track_state(packet, con->parse.data);

		break;
	case COM_QUIT:
		/* track COM_QUIT going to the server, to be able to tell if the server
		 * a) simply went away or
		 * b) closed the connection because the client asked it to
		 * If b) we should not print a message at the next EV_READ event from the server fd
		 */
		con->com_quit_seen = TRUE;
		break;
	case COM_CHANGE_USER:
		/**对change user包进行特殊处理*/
		con->parse.data = network_mysqld_change_user_new();
		con->parse.data_free = (GDestroyNotify)network_mysqld_change_user_free;
		
		if (network_mysqld_proto_get_change_user(packet, con->parse.data)) {
			g_critical("[%s]: change user failed, the packet is invalid", G_STRLOC);
			return -1;
		}
		// 找到与username对应的user info

//		struct user_info * config_user = get_user_info_for_user(con->srv,
//				((network_mysqld_change_user *)con->parse.data)->username->str);
//		// 没有找到相应的用户注册信息，返回错误，向用户端返回错误包，记录日志，关闭相应连接。
//		if (!config_user) {
//			g_critical("[%s]: change user failed, username unknown, %s", G_STRLOC, ((network_mysqld_change_user *)con->parse.data)->username->str);
//			return -2;
//		}
//		GString *passwd = config_user->passwd;
		GString *username =
				((network_mysqld_change_user *) con->parse.data)->username;
		GString *passwd = get_passwd_for_user(username, con->srv);
		if (!passwd) {
			g_warning(
					"[%s]: username unknown or get NULL for password of user: %s",
					G_STRLOC, username->str);
			return -2;
		}

		char scrambled[256];
		// N bytes scrambled password
		memset((void*) scrambled, 0, sizeof(scrambled));
		if (passwd) {
			g_string_append_c(passwd, '\0');
			mysql_scramble(scrambled, con->server->challenge->auth_plugin_data->str,
					passwd->str);
			/**
			 * @author sohu-inc.com
			 * 这里对passwd做了操作，现在改成各自复制一份，记得释放内存
			 */
			g_string_free(passwd, TRUE);
			passwd = NULL;
		} else {
			mysql_scramble(scrambled, con->server->challenge->auth_plugin_data->str,
					"");
		}
		/* 替换成新密码*/
		int start_offset = NET_HEADER_SIZE + 1/*0x11*/ + username->len + 2/*0x00 0x14*/;
		int i;
		for (i = 0; i < 20; i++) {
			packet->data->str[start_offset + i] = scrambled[i];
		}
		
		break;
		
	default:
		break;
	}
	
	return 0;
}

/**
 * @param packet the current packet that is passing by
 *
 *
 * @return -1 on invalid packet, 
 *          0 need more packets, 
 *          1 for the last packet 
 */
int network_mysqld_proto_get_query_result(network_packet *packet, network_mysqld_con *con) {
	guint8 status;
	int is_finished = 0;
	int err = 0;
	network_mysqld_eof_packet_t *eof_packet;
	
	err = err || network_mysqld_proto_skip_network_header(packet);
	if (err) return -1;

	/* forward the response to the client */
	switch (con->parse.command) {
	case COM_CHANGE_USER: 
		/**
		 * - OK
		 * - ERR
		 * - EOF for auth switch TODO
		 */
		err = err || network_mysqld_proto_get_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_ERR:
		case MYSQLD_PACKET_OK:
			g_string_truncate(con->client->response->username, 0);
			g_string_append(con->client->response->username, ((network_mysqld_change_user *)con->parse.data)->username->str);
			g_string_truncate(con->client->response->database, 0);
			g_string_append(con->client->response->database, ((network_mysqld_change_user *)con->parse.data)->schema->str);
			g_string_truncate(con->server->response->username, 0);
			g_string_append(con->server->response->username, ((network_mysqld_change_user *)con->parse.data)->username->str);
			g_string_truncate(con->server->response->database, 0);
			g_string_append(con->server->response->database, ((network_mysqld_change_user *)con->parse.data)->schema->str);
			if (con->stmtids)
				g_hash_table_remove_all(con->stmtids);
			if (con->stmtnames)
				g_hash_table_remove_all(con->stmtnames);
			is_finished = 1;
			break;
		case MYSQLD_PACKET_EOF:
			/* TODO:
			 * - added extra states to the state-engine in network-mysqld.c to track the packets that are sent back and forth
			 *   to switch the auth-method in COM_CHANGE_USER
			 */
			g_message("%s: COM_CHANGE_USER's auth-method-switch detected, but is currently not supported. Closing connection.",
					G_STRLOC);
			return -1;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|OK)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		}
		break;
	case COM_INIT_DB:
		//g_debug("there is a init_db command");
		is_finished = network_mysqld_proto_get_com_init_db(packet, con->parse.data, con);

		break;
	case COM_REFRESH:
	case COM_STMT_RESET:
	case COM_PING:
	case COM_TIME:
	case COM_REGISTER_SLAVE:
	case COM_PROCESS_KILL:
		err = err || network_mysqld_proto_get_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_ERR:
		case MYSQLD_PACKET_OK:
			is_finished = 1;
			break;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|OK)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		}
		break;
	case COM_DEBUG:
	case COM_SET_OPTION:
	case COM_SHUTDOWN:
		err = err || network_mysqld_proto_get_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_ERR: /* COM_DEBUG may not have the right permissions */
		case MYSQLD_PACKET_EOF:
			is_finished = 1;
			break;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|EOF)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		}
		break;

	case COM_FIELD_LIST:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;

		/* we transfer some data and wait for the EOF */
		switch (status) {
		case MYSQLD_PACKET_ERR:
		case MYSQLD_PACKET_EOF: {
			is_finished = 1;
			network_mysqld_eof_packet_t *eof_packet = network_mysqld_eof_packet_new();
			err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
			if(!err) {
				if(eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
					con->tx_flag = 1;
				} else {
					con->tx_flag = 0;
				}
				/**
				 * @author sohu-inc.com
				 * 重新设置client及server 的autocommit标志字段
				 */
				 if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
					 con->client->autocommit = 1;
					 con->server->autocommit = 1;
				 } else {
					 con->client->autocommit = 0;
					 con->server->autocommit = 0;
				 }
			}
			network_mysqld_eof_packet_free(eof_packet);
			break;
		}
		case MYSQLD_PACKET_NULL:
		case MYSQLD_PACKET_OK:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR, EOF or field data)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		default:
			break;
		}
		break;
#if MYSQL_VERSION_ID >= 50000
	case COM_STMT_FETCH:
		/*  */
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_EOF: 
			eof_packet = network_mysqld_eof_packet_new();

			err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
			if (!err) {
				if ((eof_packet->server_status & SERVER_STATUS_LAST_ROW_SENT) ||
				    (eof_packet->server_status & SERVER_STATUS_CURSOR_EXISTS)) {
					is_finished = 1;
				}
			}

			network_mysqld_eof_packet_free(eof_packet);

			break; 
		case MYSQLD_PACKET_ERR:
			is_finished = 1;
			break;
		default:
			break;
		}
		break;
#endif
	case COM_QUIT: /* sometimes we get a packet before the connection closes */
	case COM_STATISTICS:
		/* just one packet, no EOF */
		is_finished = 1;

		break;
	case COM_STMT_PREPARE:
		is_finished = network_mysqld_proto_get_com_stmt_prepare_result(packet, con->parse.data, con);
		break;
	case COM_STMT_EXECUTE:
		/* COM_STMT_EXECUTE result packets are basically the same as COM_QUERY ones,
		 * the only difference is the encoding of the actual data - fields are in there, too.
		 */
		is_finished = network_mysqld_proto_get_com_query_result(packet, con->parse.data, TRUE, con);
		break;
	case COM_PROCESS_INFO:
	case COM_QUERY:
		is_finished = network_mysqld_proto_get_com_query_result(packet, con->parse.data, FALSE, con);
		break;
	case COM_BINLOG_DUMP:
		/**
		 * the binlog-dump event stops, forward all packets as we see them
		 * and keep the command active
		 */
		is_finished = 1;
		break;
	default:
		g_debug_hexdump(G_STRLOC, S(packet->data));
		g_message("%s: COM_(0x%02x) is not handled", 
				G_STRLOC,
				con->parse.command);
		err = 1;
		break;
	}

	if (err) return -1;

	return is_finished;
}

/**
 * @author sohu-inc.com
 * 查看init_db 的结果数据包，判定是否在事务中
 * @return 1 在事务中
 * @return 0 不在事务中
 * @return -1 非法返回数据包
 * @return 2 保持原来的事务状态(对应中间的结果数据包或error 数据包)
 */
int network_mysqld_proto_get_com_init_db_in_trans(
		network_packet *packet, 
		network_mysqld_com_init_db_result_t *UNUSED_PARAM(udata),
		network_mysqld_con *UNUSED_PARAM(con)) {
	guint8 status;
	int is_intrans = 2;
	int err = 0;

	network_mysqld_ok_packet_t *ok_packet;
	/**
	 * in case we have a init-db statement we track the db-change on the server-side
	 * connection
	 */
	err = err || network_mysqld_proto_peek_int8(packet, &status);

	switch (status) {
	case MYSQLD_PACKET_ERR:
		is_intrans = 2;
		break;
	case MYSQLD_PACKET_OK:
		// 更新client端及server端的数据库
		// 这个在判断结果是否结束里面做就可以了，不需要在这里再做一次了
		/**
		 * track the change of the init_db */
/*
		if (con->server) g_string_truncate(con->server->default_db, 0);
		g_string_truncate(con->client->default_db, 0);

		if (udata->db_name && udata->db_name->len) {
			if (con->server) {
				g_string_append_len(con->server->default_db, 
						S(udata->db_name));
			}
			
			g_string_append_len(con->client->default_db, 
					S(udata->db_name));
		}
		 
*/
		ok_packet = network_mysqld_ok_packet_new();
		err = err || network_mysqld_proto_get_ok_packet(packet, ok_packet);
		if (!err) {
			if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
				is_intrans = 1;
			} else {
				is_intrans = 0;
			}
		}
		network_mysqld_ok_packet_free(ok_packet);
		break;
	default:
		g_critical("%s.%d: COM_INIT_DB should be (ERR|OK), got %02x",
				__FILE__, __LINE__,
				status);

		return -1;
	}

	if (err) return -1;
	return is_intrans;
}

/**
 * @author sohu-inc.com
 * 通过prepare的结果查看连接是否在事务中
 * 同时，这里需要更新statement_id列表，若是ok数据包，将对应的id添加到con中的id列表
 *
 * @fixme 这里还有不少问题！！
 */
int network_mysqld_proto_get_com_stmt_prepare_result_in_trans(
		network_packet *packet, 
		network_mysqld_com_stmt_prepare_result_t *udata) {
	guint8 status;
	int is_intrans = 2;
	int err = 0;
	network_mysqld_eof_packet_t *eof_packet;
	err = err || network_mysqld_proto_peek_int8(packet, &status);

	if (udata->first_packet == 1) {
		udata->first_packet = 0;

		switch (status) {
		case MYSQLD_PACKET_OK:
			g_assert(packet->data->len == 12 + NET_HEADER_SIZE); 

			/* the header contains the number of EOFs we expect to see
			 * - no params -> 0
			 * - params | fields -> 1
			 * - params + fields -> 2 
			 */
			network_mysqld_stmt_prepare_ok_packet_t * prepare_ok_packet;
			
			udata->want_eofs = 0;

			if (packet->data->str[NET_HEADER_SIZE + 5] != 0 || packet->data->str[NET_HEADER_SIZE + 6] != 0) {
				udata->want_eofs++;
			}
			if (packet->data->str[NET_HEADER_SIZE + 7] != 0 || packet->data->str[NET_HEADER_SIZE + 8] != 0) {
				udata->want_eofs++;
			}

			// 这里只是在一个结果的中间的状态，并且PREPARE_OK_PACKET数据包不会包含server_status字段
			// 因而我们只是返回事务保持，但是我们会在这里更新con->stmtids
			//if (udata->want_eofs == 0) {
			//	 = 1;
			//}
			
			// 这里需要将新增的id的列表push到con->stmtids，为了功能的划分明确是不是单独通过一个函数来做这个工作？
			// 这里先做了？
			prepare_ok_packet = network_mysqld_stmt_prepare_ok_packet_new();
			err = err || network_mysqld_proto_get_stmt_prepare_ok_packet(packet, prepare_ok_packet);
			if (!err) {
				guint32 new_stmt_id = prepare_ok_packet->stmt_id;
				g_debug("[%s]: get new prepare id %u", G_STRLOC, new_stmt_id);
			}
			network_mysqld_stmt_prepare_ok_packet_free(prepare_ok_packet);

			is_intrans = 2;
			break;
		case MYSQLD_PACKET_ERR:
			is_intrans = 2;
			break;
		default:
			g_error("%s.%d: COM_STMT_PREPARE should either get a (OK|ERR), got %02x",
					__FILE__, __LINE__,
					status);
			break;
		}
	} else {
		switch (status) {
		case MYSQLD_PACKET_OK:
		case MYSQLD_PACKET_NULL:
		case MYSQLD_PACKET_ERR:
			g_error("%s.%d: COM_STMT_PREPARE should not be (OK|ERR|NULL), got: %02x",
					__FILE__, __LINE__,
					status);
			break;
		case MYSQLD_PACKET_EOF:
			eof_packet = network_mysqld_eof_packet_new();

			err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
			if (!err) {
				if (eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
					is_intrans = 1;
				} else {
					is_intrans = 0;
				}
			}

			network_mysqld_eof_packet_free(eof_packet);
			
			break;
		default:
			break;
		}
	}

	if (err) return -1;

	return is_intrans;
}

/**
 * @author sohu-inc.com
 * 通过返回结果包中server status字段，判断连接是否在事务中。
 * 这里会有个简单的状态机，不能确定状态是否可以重新获取。应该是不可能的，所以对于普通的com_query的返回结果，
 * 所以其事务性的判断应该和is_finished的判断在一块进行。
 * @note will be removed
 */
int network_mysqld_proto_get_com_query_result_in_trans(network_packet *UNUSED_PARAM(packet), network_mysqld_com_query_result_t *UNUSED_PARAM(query), gboolean UNUSED_PARAM(use_binary_row_data)) {
	// 故这里不能单独实现？
	return 2;
}

/**
 * @author sohu-inc.com
 * 通过返回结果的查看连接是否在事务中,仿照现有的is_finished的实现方式
 * 中间结果flag 保持不变，
 * EOF 及 OK 数据包才查看server status变量
 */
/**
 * @param packet the current packet that is passing by
 *
 *
 * @return -1 on invalid packet, 
 *          0 not in transaction, 
 *          1 in transaction,
 *	    2 keep flag 
 */
int network_mysqld_proto_get_trans_flag(network_packet *packet, network_mysqld_con *con) {
	guint8 status;
	int is_intrans = 2;
	int err = 0;
	network_mysqld_eof_packet_t *eof_packet;
	network_mysqld_ok_packet_t *ok_packet;
	
	err = err || network_mysqld_proto_skip_network_header(packet);
	if (err) return -1;

	/* forward the response to the client */
	switch (con->parse.command) {
	case COM_CHANGE_USER: 
		/**
		 * - OK
		 * - ERR
		 * - EOF for auth switch TODO
		 */
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;
		switch (status) {
		case MYSQLD_PACKET_ERR:
			is_intrans = 2;
			break;
		case MYSQLD_PACKET_OK:
			//is_finished = 1;
			ok_packet = network_mysqld_ok_packet_new();
			err = err || network_mysqld_proto_get_ok_packet(packet, ok_packet);
			if(!err) {
				if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
					is_intrans = 1;
				} else {
					is_intrans = 0;
				}
				/**
                                 * @author sohu-inc.com
                                 * 重新设置client及server 的autocommit标志字段
                                 */
                                if (ok_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
                                        con->client->autocommit = 1;
                                        con->server->autocommit = 1;
                                } else {
                                        con->client->autocommit = 0;
                                        con->server->autocommit = 0;
                                }
			}
			//if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
			//	return 1;
			//}
			network_mysqld_ok_packet_free(ok_packet);
			break;
		case MYSQLD_PACKET_EOF:
			/* TODO:
			 * - added extra states to the state-engine in network-mysqld.c to track the packets that are sent back and forth
			 *   to switch the auth-method in COM_CHANGE_USER
			 */
			g_message("[%s]: COM_CHANGE_USER's auth-method-switch detected, but is currently not supported. Closing connection.", G_STRLOC);
			return -1;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("[%s]: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|OK)", G_STRLOC, con->parse.command, (guint8)status);
			return -1;
		}
		break;
	case COM_INIT_DB:
		//is_finished = network_mysqld_proto_get_com_init_db(packet, con->parse.data, con);
		is_intrans = network_mysqld_proto_get_com_init_db_in_trans(packet, con->parse.data, con);
		break;
	case COM_REFRESH:
	case COM_STMT_RESET:
	case COM_PING:
	case COM_TIME:
	case COM_REGISTER_SLAVE:
	case COM_PROCESS_KILL:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_ERR:
			is_intrans = 2;
			break;
		case MYSQLD_PACKET_OK:
			ok_packet = network_mysqld_ok_packet_new();
                        err = err || network_mysqld_proto_get_ok_packet(packet, ok_packet);
                        if(!err) {
                                if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
                                        is_intrans = 1;
                                } else {
                                        is_intrans = 0;
                                }
				/**
                                 * @author sohu-inc.com
                                 * 重新设置client及server 的autocommit标志字段
                                 */
                                if (ok_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
                                        con->client->autocommit = 1;
                                        con->server->autocommit = 1;
                                } else {
                                        con->client->autocommit = 0;
                                        con->server->autocommit = 0;
                                }
                        }
                        //if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
                        //      return 1;
                        //}
                        network_mysqld_ok_packet_free(ok_packet);
                        break;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|OK)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		}
		break;
	case COM_DEBUG:
	case COM_SET_OPTION:
	case COM_SHUTDOWN:
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_ERR: /* COM_DEBUG may not have the right permissions */
			is_intrans = 2;
			break;
		case MYSQLD_PACKET_EOF:
			eof_packet = network_mysqld_eof_packet_new();
                        err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
                        if(!err) {
                                if(eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
                                        is_intrans = 1;
                                } else {
                                        is_intrans = 0;
                                }
				/**
                                 * @author sohu-inc.com
                                 * 重新设置client及server 的autocommit标志字段
                                 */
                                if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
                                        con->client->autocommit = 1;
                                        con->server->autocommit = 1;
                                } else {
                                        con->client->autocommit = 0;
                                        con->server->autocommit = 0;
                                }
                        }
                        //if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
                        //      return 1;
                        //}
                        network_mysqld_eof_packet_free(eof_packet);
                        break;
		default:
			g_debug_hexdump(G_STRLOC, S(packet->data));
			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR|EOF)",
					G_STRLOC,
					con->parse.command,
					(guint8)status);
			return -1;
		}
		break;

	case COM_FIELD_LIST:
		is_intrans = 2;
		break;
//		err = err || network_mysqld_proto_get_int8(packet, &status);
//		if (err) return -1;
//
//		/* we transfer some data and wait for the EOF */
//		switch (status) {
//		case MYSQLD_PACKET_ERR:
//		case MYSQLD_PACKET_EOF:
//			eof_packet = network_mysqld_eof_packet_new();
//                        err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
//                        if(!err) {
//                                if(eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
//                                        is_intrans = 1;
//                                } else {
//                                        is_intrans = 0;
//                                }
//				/**
//                                 * @author sohu-inc.com
//                                 * 重新设置client及server 的autocommit标志字段
//                                 */
//                                if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
//                                        con->client->autocommit = 1;
//                                        con->server->autocommit = 1;
//                                } else {
//                                        con->client->autocommit = 0;
//                                        con->server->autocommit = 0;
//                                }
//                        }
//                        //if(ok_packet->server_status & SERVER_STATUS_IN_TRANS) {
//                        //      return 1;
//                        //}
//                        network_mysqld_eof_packet_free(eof_packet);
//			break;
//
//		case MYSQLD_PACKET_NULL:
//		case MYSQLD_PACKET_OK:
//			g_debug_hexdump(G_STRLOC, S(packet->data));
//			g_message("%s: got a 0x%02x packet as respose for COM_[0%02x], but expected only (ERR, EOF or field data)",
//					G_STRLOC,
//					con->parse.command,
//					(guint8)status);
//			return -1;
//		default:
//			break;
//		}
//		break;
#if MYSQL_VERSION_ID >= 50000
	case COM_STMT_FETCH:
		/*  */
		err = err || network_mysqld_proto_peek_int8(packet, &status);
		if (err) return -1;

		switch (status) {
		case MYSQLD_PACKET_EOF: 
			eof_packet = network_mysqld_eof_packet_new();
                        err = err || network_mysqld_proto_get_eof_packet(packet, eof_packet);
                        if(!err) {
                                if(eof_packet->server_status & SERVER_STATUS_IN_TRANS) {
                                        is_intrans = 1;
                                } else {
                                        is_intrans = 0;
                                }
				/**
                                 * @author sohu-inc.com
                                 * 重新设置client及server 的autocommit标志字段
                                 */
                                if (eof_packet->server_status & SERVER_STATUS_AUTOCOMMIT) {
                                        con->client->autocommit = 1;
                                        con->server->autocommit = 1;
                                } else {
                                        con->client->autocommit = 0;
                                        con->server->autocommit = 0;
                                }
                        }
                        network_mysqld_eof_packet_free(eof_packet);
			break; 
		case MYSQLD_PACKET_ERR:
			is_intrans = 2;
			break;
		default:
			break;
		}
		break;
#endif
	case COM_QUIT: /* sometimes we get a packet before the connection closes */
	case COM_STATISTICS:
		/* just one packet, no EOF */
		//is_finished = 1;
		is_intrans = 2;
		break;
	case COM_STMT_PREPARE:
		is_intrans = network_mysqld_proto_get_com_stmt_prepare_result_in_trans(packet, con->parse.data);
		break;
	case COM_STMT_EXECUTE:
		/* COM_STMT_EXECUTE result packets are basically the same as COM_QUERY ones,
		 * the only difference is the encoding of the actual data - fields are in there, too.
		 */
		// 按现在的实现只需要保持，network_mysqld_proto_get_com_query_result中对con->tx_flag的设置
		is_intrans = network_mysqld_proto_get_com_query_result_in_trans(packet, con->parse.data, TRUE);
		break;
	case COM_PROCESS_INFO:
	case COM_QUERY:
		// 按现在的实现只需要保持，network_mysqld_proto_get_com_query_result中对con->tx_flag的设置
		is_intrans = network_mysqld_proto_get_com_query_result_in_trans(packet, con->parse.data, FALSE);
		break;
	case COM_BINLOG_DUMP:
		/**
		 * the binlog-dump event stops, forward all packets as we see them
		 * and keep the command active
		 */
		is_intrans = 2;
		break;
	default:
		g_debug_hexdump(G_STRLOC, S(packet->data));
		g_message("%s: COM_(0x%02x) is not handled", 
				G_STRLOC,
				con->parse.command);
		err = 1;
		break;
	}

	if (err) return -1;

	return is_intrans;
}

int network_mysqld_proto_get_fielddef(network_packet *packet, network_mysqld_proto_fielddef_t *field, guint32 capabilities) {
	int err = 0;

	if (capabilities & CLIENT_PROTOCOL_41) {
		guint16 field_charsetnr;
		guint32 field_length;
		guint8 field_type;
		guint16 field_flags;
		guint8 field_decimals;

		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->catalog, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->db, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->table, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->org_table, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->name, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->org_name, NULL);
        
		err = err || network_mysqld_proto_skip(packet, 1); /* filler */
        
		err = err || network_mysqld_proto_get_int16(packet, &field_charsetnr);
		err = err || network_mysqld_proto_get_int32(packet, &field_length);
		err = err || network_mysqld_proto_get_int8(packet,  &field_type);
		err = err || network_mysqld_proto_get_int16(packet, &field_flags);
		err = err || network_mysqld_proto_get_int8(packet,  &field_decimals);
        
		err = err || network_mysqld_proto_skip(packet, 2); /* filler */
		if (!err) {
			field->charsetnr = field_charsetnr;
			field->length    = field_length;
			field->type      = field_type;
			field->flags     = field_flags;
			field->decimals  = field_decimals;
		}
	} else {
		guint8 len;
		guint32 field_length;
		guint8  field_type;
		guint8  field_decimals;

		/* see protocol.cc Protocol::send_fields */

		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->table, NULL);
		err = err || network_mysqld_proto_get_lenenc_string(packet, &field->name, NULL);
		err = err || network_mysqld_proto_get_int8(packet, &len);
		err = err || (len != 3);
		err = err || network_mysqld_proto_get_int24(packet, &field_length);
		err = err || network_mysqld_proto_get_int8(packet, &len);
		err = err || (len != 1);
		err = err || network_mysqld_proto_get_int8(packet, &field_type);
		err = err || network_mysqld_proto_get_int8(packet, &len);
		if (len == 3) { /* the CLIENT_LONG_FLAG is set */
			guint16 field_flags;

			err = err || network_mysqld_proto_get_int16(packet, &field_flags);

			if (!err) field->flags = field_flags;
		} else if (len == 2) {
			guint8 field_flags;

			err = err || network_mysqld_proto_get_int8(packet, &field_flags);

			if (!err) field->flags = field_flags;
		} else {
			err = -1;
		}
		err = err || network_mysqld_proto_get_int8(packet, &field_decimals);

		if (!err) {
			field->charsetnr = 0x08 /* latin1_swedish_ci */;
			field->length    = field_length;
			field->type      = field_type;
			field->decimals  = field_decimals;
		}
	}

	return err ? -1 : 0;
}

/**
 * parse the result-set packet and extract the fields
 *
 * @param chunk  list of mysql packets 
 * @param fields empty array where the fields shall be stored in
 *
 * @return NULL if there is no resultset
 *         pointer to the chunk after the fields (to the EOF packet)
 */ 
GList *network_mysqld_proto_get_fielddefs(GList *chunk, GPtrArray *fields) {
	network_packet packet;
	guint64 field_count;
	guint i;
	int err = 0;
	guint32 capabilities = CLIENT_PROTOCOL_41;
	network_mysqld_lenenc_type lenenc_type;
    
	packet.data = chunk->data;
	packet.offset = 0;

	err = err || network_mysqld_proto_skip_network_header(&packet);
	
	err = err || network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);

	if (err) return NULL; /* packet too short */

	/* make sure that we have a valid length-encoded integer here */
	switch (lenenc_type) {
	case NETWORK_MYSQLD_LENENC_TYPE_INT:
		break;
	default:
		/* we shouldn't be here, we expected to get a valid length-encoded field count */
		return NULL;
	}
	
	err = err || network_mysqld_proto_get_lenenc_int(&packet, &field_count);
	
	if (err) return NULL; /* packet to short */

	if (field_count == 0) {
		/* shouldn't happen, the upper layer should have checked that this is a OK packet */
		return NULL;
	}
    
	/* the next chunk, the field-def */
	for (i = 0; i < field_count; i++) {
		network_mysqld_proto_fielddef_t *field;
        
		chunk = chunk->next;
		g_assert(chunk);

		packet.data = chunk->data;
		packet.offset = 0;

		field = network_mysqld_proto_fielddef_new();

		err = err || network_mysqld_proto_skip_network_header(&packet);
		err = err || network_mysqld_proto_get_fielddef(&packet, field, capabilities);

		g_ptr_array_add(fields, field); /* even if we had an error, append it so that we can free it later */

		if (err) return NULL;
	}
    
	/* this should be EOF chunk */
	chunk = chunk->next;

	if (!chunk) return NULL;

	packet.data = chunk->data;
	packet.offset = 0;
	
	err = err || network_mysqld_proto_skip_network_header(&packet);

	err = err || network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);
	err = err || (lenenc_type != NETWORK_MYSQLD_LENENC_TYPE_EOF);

	if (err) return NULL;
    
	return chunk;
}

/**
 * @author sohu-inc.com
 * 用于处理上下文恢复数据包的init_db 数据包
 */
network_mysqld_init_db_packet_t* network_mysqld_init_db_packet_new(void) {
	network_mysqld_init_db_packet_t* init_db_packet;
	init_db_packet = g_new0(network_mysqld_init_db_packet_t, 1);
	
	init_db_packet->schema = g_string_new(NULL);

	return init_db_packet;
}

void  network_mysqld_init_db_packet_free(network_mysqld_init_db_packet_t* init_db_packet) {
	if(!init_db_packet)
		return;
	
	if(init_db_packet->schema)
		g_string_free(init_db_packet->schema, TRUE);

	g_free(init_db_packet);
}

/**
 * @author sohu-inc.com
 * 从数据包packet中解析出数据库初始化包
 * @param packet 接收到的数据包，主要是为了保存连接上下文
 * @param init_db_packet 用于保存init_db数据包
 */
int network_mysqld_proto_get_init_db_packet(network_packet *packet, network_mysqld_init_db_packet_t* init_db_packet) {
	int err = 0;
	gchar *schema = NULL;

	if (packet->offset < packet->data->len) {
		err = err || network_mysqld_proto_get_string_len(packet, &schema, packet->data->len - packet->offset);
	}

	if(!err) {
		if(schema) g_string_assign(init_db_packet->schema, schema);
	}
	
	return err ? -1 : 0;
}
/**
 * @author sohu-inc.com
 * 将数据库初始化包附加到要构造的数据包上面
 * @param packet 要构造的数据包
 * @param init_db_packet 要发送的init_db数据包
 */
int network_mysqld_proto_append_init_db_packet(GString *packet,
		network_mysqld_init_db_packet_t *init_db_packet) {
	network_mysqld_proto_append_int8(packet, 0x02); //COM_INIT_DB
	//guint schema_len = init_db_packet->schema->len;
	//if (errmsg_len >= 512) errmsg_len = 512;
	g_string_append_len(packet, init_db_packet->schema->str,
			init_db_packet->schema->len);

	return 0;
}

/**
 * @author sohu-inc.com
 * @param packet 需要添加autocommit 数据包的包
 * @param num 将要设置的autocommit的值
 */
int network_mysqld_proto_append_autocommit_packet(GString *packet, guint num) {
	g_assert(packet);
	
	network_mysqld_proto_append_int8(packet, 0x03); //COM_QUERY
	g_string_append(packet, "set autocommit = ");
	g_string_append_c(packet, (gchar) (num + '0'));
	
	return 0;
}
/**
 * @author sohu-inc.com
 * @param packet 需要添加字符集属性数据包的包
 * @param charset_type 将要设置的属性的名字
 * @param charset_name 字符集的名字
 */
int network_mysqld_proto_append_character_set_packet(GString *packet,
		const gchar *charset_type, const gchar *charset_name) {
	g_assert(packet);
	g_assert(charset_type);
	g_assert(charset_name);
	/** 修复采用dbeaver连接时导致dbproxy异常退出, 主要是character_set_results 为NULL导致的bug*/
	/*
	 g_assert(
	 is_correct_charsetname(charset_name)
	 || (0 == g_strcasecmp(charset_type, "character_set_results")
	 && 0 == g_strcasecmp(charset_name, "NULL")));
	 */
	/*g_assert(
			is_correct_charsetname(charset_name)
					|| (0 == g_ascii_strcasecmp(charset_name, "default"))
					|| (0
							== g_ascii_strcasecmp(charset_type,
									"character_set_results")
							&& 0 == g_ascii_strcasecmp(charset_name, "NULL")));
	*/

	int ret = 0;
	if ( ! (
			 ( is_correct_charsetname(charset_name) == TRUE )
					|| (0 == g_ascii_strcasecmp(charset_name, "default"))
					|| (0
							== g_ascii_strcasecmp(charset_type,
									"character_set_results")
							&& 0 == g_ascii_strcasecmp(charset_name, "NULL"))
						) ) {
		ret = -1;
	}

	network_mysqld_proto_append_int8(packet, 0x03); //COM_QUERY

	g_string_append(packet, "set ");
	g_string_append(packet, charset_type);
	g_string_append(packet, " = ");
	g_string_append(packet, charset_name);

	return ret;
}

int network_mysqld_proto_append_collation_set_packet(GString *packet,
		const gchar *collation_type,
		const gchar *collation_name) {
	g_assert(packet);
	g_assert(collation_type);
	g_assert(collation_name);

	int ret = 0;
	guint8 index = 0;
	if (
			!is_correct_collationname(collation_type, &index)
			&& (0 != g_ascii_strcasecmp(collation_name, "default"))) {

		ret = -1;
	}

	network_mysqld_proto_append_int8(packet, 0x03); //COM_QUERY

	g_string_append(packet, "set ");
	g_string_append(packet, collation_type);
	g_string_append(packet, " = ");
	g_string_append(packet, collation_name);

	return ret;
}


/**
 * 构造 init db 注入包结构
 */
injection *network_mysqld_injection_new_init_db(int inj_index, const GString *default_db) {
	network_mysqld_init_db_packet_t *init_db_packet = NULL;
	GString *init_db_packet_new = NULL;
	GString *init_db_packet_new_str = NULL;
	injection *inj = NULL;

	init_db_packet = network_mysqld_init_db_packet_new();
	g_string_append_len(init_db_packet->schema, S(default_db));

	init_db_packet_new = g_string_new(NULL );
	network_mysqld_proto_append_init_db_packet(init_db_packet_new,
			init_db_packet);

	init_db_packet_new_str = g_string_new(NULL );
	network_mysqld_proto_append_int16(init_db_packet_new_str,
			(guint16) init_db_packet_new->len);
	network_mysqld_proto_append_int8(init_db_packet_new_str, 0);
	network_mysqld_proto_append_int8(init_db_packet_new_str, 0x0);
	g_string_append_len(init_db_packet_new_str, S(init_db_packet_new));

	g_string_free(init_db_packet_new, TRUE);
	network_mysqld_init_db_packet_free(init_db_packet);

	inj = injection_new(inj_index, init_db_packet_new_str);

	return inj;
}

/**
 * 构造 autocommit 注入包结构
 */
injection *network_mysqld_injection_new_autocommit(int inj_index,
		guint8 autocommit) {
	GString *autocommit_packet = NULL;
	GString * autocommit_packet_new = NULL;
	injection *inj = NULL;

	autocommit_packet = g_string_new(NULL );
	network_mysqld_proto_append_autocommit_packet(autocommit_packet,
			autocommit);

	autocommit_packet_new = g_string_new(NULL );
	network_mysqld_proto_append_int16(autocommit_packet_new,
			(guint16) autocommit_packet->len);
	network_mysqld_proto_append_int8(autocommit_packet_new, 0);
	network_mysqld_proto_append_int8(autocommit_packet_new, 0x0);
	g_string_append_len(autocommit_packet_new, S(autocommit_packet));

	g_string_free(autocommit_packet, TRUE);

	inj = injection_new(inj_index, autocommit_packet_new);

	return inj;
}

/**
 * 构造 character set 注入包结构
 */
injection *network_mysqld_injection_new_character_set(int inj_index,
		const gchar *charset_type, const gchar *character_set_client) {
	GString *character_set_packet = NULL;
	GString *character_set_packet_new = NULL;
	injection *inj = NULL;

	character_set_packet = g_string_new(NULL );
	if (-1 == network_mysqld_proto_append_character_set_packet(character_set_packet,
			charset_type, character_set_client)) {
		g_critical("[%s]: %s of client is %s, which is not a correct type",
				G_STRLOC,
				charset_type,
				character_set_client);
	}

	character_set_packet_new = g_string_new(NULL );
	network_mysqld_proto_append_int16(character_set_packet_new,
			character_set_packet->len);
	network_mysqld_proto_append_int8(character_set_packet_new, 0);
	network_mysqld_proto_append_int8(character_set_packet_new, 0x0);
	g_string_append_len(character_set_packet_new, S(character_set_packet));

	g_string_free(character_set_packet, TRUE);

	inj = injection_new(inj_index, character_set_packet_new);

	return inj;
}

/**
 * 构造 collation set 注入包结构
 */
injection *network_mysqld_injection_new_collation_set(int inj_index,
		const gchar *collation_type, const gchar *collation_set_name) {
	GString *collation_set_packet = NULL;
	GString *collation_set_packet_new = NULL;
	injection *inj = NULL;

	collation_set_packet = g_string_new(NULL );
	if (-1 == network_mysqld_proto_append_character_set_packet(collation_set_packet,
			collation_type, collation_set_name)) {
		g_critical("[%s]: %s of client is %s, which is not a correct type",
				G_STRLOC,
				collation_type,
				collation_set_name);
	}

	collation_set_packet_new = g_string_new(NULL );
	network_mysqld_proto_append_int16(collation_set_packet_new,
			collation_set_packet->len);
	network_mysqld_proto_append_int8(collation_set_packet_new, 0);
	network_mysqld_proto_append_int8(collation_set_packet_new, 0x0);
	g_string_append_len(collation_set_packet_new, S(collation_set_packet));

	g_string_free(collation_set_packet, TRUE);

	inj = injection_new(inj_index, collation_set_packet_new);

	return inj;
}


network_mysqld_ok_packet_t *network_mysqld_ok_packet_new() {
	network_mysqld_ok_packet_t *ok_packet;

	ok_packet = g_new0(network_mysqld_ok_packet_t, 1);

	return ok_packet;
}



void network_mysqld_ok_packet_free(network_mysqld_ok_packet_t *ok_packet) {
	if (!ok_packet) return;

	g_free(ok_packet);
}


/**
 * decode a OK packet from the network packet
 */
int network_mysqld_proto_get_ok_packet(network_packet *packet, network_mysqld_ok_packet_t *ok_packet) {
	guint8 field_count;
	guint64 affected, insert_id;
	guint16 server_status, warning_count = 0;
	guint32 capabilities = CLIENT_PROTOCOL_41;

	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &field_count);
	if (err) return -1;

	if (field_count != 0) {
		g_critical("%s: expected the first byte to be 0, got %d",
				G_STRLOC,
				field_count);
		return -1;
	}

	err = err || network_mysqld_proto_get_lenenc_int(packet, &affected);
	err = err || network_mysqld_proto_get_lenenc_int(packet, &insert_id);
	err = err || network_mysqld_proto_get_int16(packet, &server_status);
	if (capabilities & CLIENT_PROTOCOL_41) {
		err = err || network_mysqld_proto_get_int16(packet, &warning_count);
	}

	if (!err) {
		ok_packet->affected_rows = affected;
		ok_packet->insert_id     = insert_id;
		ok_packet->server_status = server_status;
		ok_packet->warnings      = warning_count;
	}

	return err ? -1 : 0;
}

int network_mysqld_proto_append_ok_packet(GString *packet, network_mysqld_ok_packet_t *ok_packet) {
	guint32 capabilities = CLIENT_PROTOCOL_41;

	network_mysqld_proto_append_int8(packet, 0); /* no fields */
	network_mysqld_proto_append_lenenc_int(packet, ok_packet->affected_rows);
	network_mysqld_proto_append_lenenc_int(packet, ok_packet->insert_id);
	network_mysqld_proto_append_int16(packet, ok_packet->server_status); /* autocommit */
	if (capabilities & CLIENT_PROTOCOL_41) {
		network_mysqld_proto_append_int16(packet, ok_packet->warnings); /* no warnings */
	}

	return 0;
}

static network_mysqld_err_packet_t *network_mysqld_err_packet_new_full(network_mysqld_protocol_t version) {
	network_mysqld_err_packet_t *err_packet;

	err_packet = g_new0(network_mysqld_err_packet_t, 1);
	err_packet->sqlstate = g_string_new(NULL);
	err_packet->errmsg = g_string_new(NULL);
	err_packet->version = version;

	return err_packet;
}

network_mysqld_err_packet_t *network_mysqld_err_packet_new() {
	return network_mysqld_err_packet_new_full(NETWORK_MYSQLD_PROTOCOL_VERSION_41);
}

network_mysqld_err_packet_t *network_mysqld_err_packet_new_pre41() {
	return network_mysqld_err_packet_new_full(NETWORK_MYSQLD_PROTOCOL_VERSION_PRE41);
}

void network_mysqld_err_packet_free(network_mysqld_err_packet_t *err_packet) {
	if (!err_packet) return;

	g_string_free(err_packet->sqlstate, TRUE);
	g_string_free(err_packet->errmsg, TRUE);

	g_free(err_packet);
}

/**
 * decode a ERR packet from the network packet
 */
int network_mysqld_proto_get_err_packet(network_packet *packet, network_mysqld_err_packet_t *err_packet) {
	guint8 field_count, marker;
	guint16 errcode;
	gchar *sqlstate = NULL, *errmsg = NULL;
	guint32 capabilities = CLIENT_PROTOCOL_41;

	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &field_count);
	if (err) return -1;

	if (field_count != MYSQLD_PACKET_ERR) {
		g_critical("%s: expected the first byte to be 0xff, got %d",
				G_STRLOC,
				field_count);
		return -1;
	}

	err = err || network_mysqld_proto_get_int16(packet, &errcode);
	if (capabilities & CLIENT_PROTOCOL_41) {
		err = err || network_mysqld_proto_get_int8(packet, &marker);
		err = err || (marker != '#');
		err = err || network_mysqld_proto_get_string_len(packet, &sqlstate, 5);
	}
	if (packet->offset < packet->data->len) {
		err = err || network_mysqld_proto_get_string_len(packet, &errmsg, packet->data->len - packet->offset);
	}

	if (!err) {
		err_packet->errcode = errcode;
		if (errmsg) g_string_assign(err_packet->errmsg, errmsg);
		g_string_assign(err_packet->sqlstate, sqlstate);
	}

	if (sqlstate) g_free(sqlstate);
	if (errmsg) g_free(errmsg);

	return err ? -1 : 0;
}



/**
 * create a ERR packet
 *
 * @note the sqlstate has to match the SQL standard. If no matching SQL state is known, leave it at NULL
 *
 * @param packet      network packet
 * @param err_packet  the error structure
 *
 * @return 0 on success
 */
int network_mysqld_proto_append_err_packet(GString *packet, network_mysqld_err_packet_t *err_packet) {
	int errmsg_len;

	network_mysqld_proto_append_int8(packet, 0xff); /* ERR */
	network_mysqld_proto_append_int16(packet, err_packet->errcode); /* errorcode */
	if (err_packet->version == NETWORK_MYSQLD_PROTOCOL_VERSION_41) {
		g_string_append_c(packet, '#');
		if (err_packet->sqlstate && (err_packet->sqlstate->len > 0)) {
			g_string_append_len(packet, err_packet->sqlstate->str, 5);
		} else {
			g_string_append_len(packet, C("07000"));
		}
	}

	errmsg_len = err_packet->errmsg->len;
	if (errmsg_len >= 512) errmsg_len = 512;
	g_string_append_len(packet, err_packet->errmsg->str, errmsg_len);

	return 0;
}

network_mysqld_eof_packet_t *network_mysqld_eof_packet_new() {
	network_mysqld_eof_packet_t *eof_packet;

	eof_packet = g_new0(network_mysqld_eof_packet_t, 1);

	return eof_packet;
}

void network_mysqld_eof_packet_free(network_mysqld_eof_packet_t *eof_packet) {
	if (!eof_packet) return;

	g_free(eof_packet);
}


/**
 * decode a OK packet from the network packet
 */
int network_mysqld_proto_get_eof_packet(network_packet *packet, network_mysqld_eof_packet_t *eof_packet) {
	guint8 field_count;
	guint16 server_status, warning_count;
	guint32 capabilities = CLIENT_PROTOCOL_41;

	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &field_count);
	if (err) return -1;

	if (field_count != MYSQLD_PACKET_EOF) {
		g_critical("%s: expected the first byte to be 0xfe, got %d",
				G_STRLOC,
				field_count);
		return -1;
	}

	if (capabilities & CLIENT_PROTOCOL_41) {
		err = err || network_mysqld_proto_get_int16(packet, &warning_count);
		err = err || network_mysqld_proto_get_int16(packet, &server_status);
		if (!err) {
			eof_packet->server_status = server_status;
			eof_packet->warnings      = warning_count;
		}
	} else {
		eof_packet->server_status = 0;
		eof_packet->warnings      = 0;
	}

	return err ? -1 : 0;
}

int network_mysqld_proto_append_eof_packet(GString *packet, network_mysqld_eof_packet_t *eof_packet) {
	guint32 capabilities = CLIENT_PROTOCOL_41;

	network_mysqld_proto_append_int8(packet, MYSQLD_PACKET_EOF); /* no fields */
	if (capabilities & CLIENT_PROTOCOL_41) {
		network_mysqld_proto_append_int16(packet, eof_packet->warnings); /* no warnings */
		network_mysqld_proto_append_int16(packet, eof_packet->server_status); /* autocommit */
	}

	return 0;
}


network_mysqld_auth_challenge *network_mysqld_auth_challenge_new() {
	network_mysqld_auth_challenge *shake;

	shake = g_new0(network_mysqld_auth_challenge, 1);
	
	shake->auth_plugin_data = g_string_new("");
	shake->capabilities = 
		CLIENT_PROTOCOL_41 |
		CLIENT_SECURE_CONNECTION |
		0;
	shake->auth_plugin_name = g_string_new(NULL);

	return shake;
}

void network_mysqld_auth_challenge_free(network_mysqld_auth_challenge *shake) {
	if (!shake) return;

	if (shake->server_version_str) g_free(shake->server_version_str);
	if (shake->auth_plugin_data)   g_string_free(shake->auth_plugin_data, TRUE);
	if (shake->auth_plugin_name)   g_string_free(shake->auth_plugin_name, TRUE);

	g_free(shake);
}

network_mysqld_auth_challenge *network_mysqld_auth_challenge_copy(network_mysqld_auth_challenge *src) {
	network_mysqld_auth_challenge *dst;

	if (!src) return NULL;

	dst = network_mysqld_auth_challenge_new();
	dst->protocol_version = src->protocol_version;
	dst->server_version  = src->server_version;
	dst->thread_id       = src->thread_id;
	dst->capabilities    = src->capabilities;
	dst->charset         = src->charset;
	dst->server_status   = src->server_status;
	dst->server_version_str = g_strdup(src->server_version_str);
	g_string_assign_len(dst->auth_plugin_data, S(src->auth_plugin_data));
	g_string_assign_len(dst->auth_plugin_name, S(src->auth_plugin_name));

	return dst;
}


void network_mysqld_auth_challenge_set_challenge(network_mysqld_auth_challenge *shake) {
	guint i;

	/* 20 chars */

	g_string_set_size(shake->auth_plugin_data, 21);

	for (i = 0; i < 20; i++) {
		shake->auth_plugin_data->str[i] = (94.0 * (rand() / (RAND_MAX + 1.0))) + 33; /* 33 - 127 are printable characters */
	}

	shake->auth_plugin_data->len = 20;
	shake->auth_plugin_data->str[shake->auth_plugin_data->len] = '\0';
}

int network_mysqld_proto_get_auth_challenge(network_packet *packet, network_mysqld_auth_challenge *shake) {
	int maj, min, patch;
	gchar *auth_plugin_data_1 = NULL, *auth_plugin_data_2 = NULL;
	guint16 capabilities1, capabilities2;
	guint8 status;
	int err = 0;
	guint8 auth_plugin_data_len;

	err = err || network_mysqld_proto_get_int8(packet, &status);

	if (err) return -1;

	switch (status) {
	case 0xff:
		return -1;
	case 0x0a:
		break;
	default:
		g_debug("%s: unknown protocol %d", 
				G_STRLOC,
				status
				);
		return -1;
	}

	err = err || network_mysqld_proto_get_string(packet, &shake->server_version_str);
	err = err || (NULL == shake->server_version_str); /* the server-version has to be set */

	err = err || network_mysqld_proto_get_int32(packet, &shake->thread_id);

	/**
	 * get the scramble buf
	 *
	 * 8 byte here and some the other 12 sometime later
	 */	
	err = err || network_mysqld_proto_get_string_len(packet, &auth_plugin_data_1, 8);

	err = err || network_mysqld_proto_skip(packet, 1);

	err = err || network_mysqld_proto_get_int16(packet, &capabilities1);
	err = err || network_mysqld_proto_get_int8(packet, &shake->charset);
	err = err || network_mysqld_proto_get_int16(packet, &shake->server_status);

	/* capabilities is extended in 5.5.x to carry 32bits to announce CLIENT_PLUGIN_AUTH */	
	err = err || network_mysqld_proto_get_int16(packet, &capabilities2);
	err = err || network_mysqld_proto_get_int8(packet, &auth_plugin_data_len);

	err = err || network_mysqld_proto_skip(packet, 10);

	if (!err) {
		shake->capabilities = capabilities1 | (capabilities2 << 16);
	
		if (shake->capabilities & CLIENT_PLUGIN_AUTH) {
			guint8 auth_plugin_data2_len = 0;

			/* CLIENT_PLUGIN_AUTH enforces auth_plugin_data_len
			 *
			 * we have at least 12 bytes */

			if (auth_plugin_data_len > 8) {
				auth_plugin_data2_len = auth_plugin_data_len - 8;
			}

			err = err || network_mysqld_proto_get_string_len(packet, &auth_plugin_data_2, auth_plugin_data2_len);
			err = err || network_mysqld_proto_skip(packet, 12 - MIN(12, auth_plugin_data2_len));
			if (!err) {
				/* Bug#59453 ... MySQL 5.5.7-9 and 5.6.0-1 don't send a trailing \0
				 *
				 * if there is no trailing \0, get the rest of the packet
				 */
				if (0 != network_mysqld_proto_get_gstring(packet, shake->auth_plugin_name)) {
					err = err || network_mysqld_proto_get_gstring_len(packet,
							packet->data->len - packet->offset,
							shake->auth_plugin_name);
				}
			}
		} else if (shake->capabilities & CLIENT_SECURE_CONNECTION) {
			err = err || network_mysqld_proto_get_string_len(packet, &auth_plugin_data_2, 12);
			err = err || network_mysqld_proto_skip(packet, 1);
		}
	}

	if (!err) {
		/* process the data */
	
		if (3 != sscanf(shake->server_version_str, "%d.%d.%d%*s", &maj, &min, &patch)) {
			/* can't parse the protocol */
	
			g_critical("%s: protocol 10, but version number not parsable", G_STRLOC);
	
			return -1;
		}
	
		/**
		 * out of range 
		 */
		if (min   < 0 || min   > 100 ||
		    patch < 0 || patch > 100 ||
		    maj   < 0 || maj   > 10) {
			g_critical("%s: protocol 10, but version number out of range", G_STRLOC);
	
			return -1;
		}
	
		shake->server_version = 
			maj * 10000 +
			min *   100 +
			patch;
	
	
		/**
		 * build auth_plugin_data
		 *
		 * auth_plugin_data_1 + auth_plugin_data_2 == auth_plugin_data
		 */
		g_string_truncate(shake->auth_plugin_data, 0);

		if (shake->capabilities & CLIENT_PLUGIN_AUTH) {
			g_string_assign_len(shake->auth_plugin_data, auth_plugin_data_1, MIN(8, auth_plugin_data_len));
			if (auth_plugin_data_len > 8) {
				g_string_append_len(shake->auth_plugin_data, auth_plugin_data_2, auth_plugin_data_len - 8);
			}
		} else if (shake->capabilities & CLIENT_SECURE_CONNECTION) {
			g_string_assign_len(shake->auth_plugin_data, auth_plugin_data_1, 8);
			g_string_append_len(shake->auth_plugin_data, auth_plugin_data_2, 12);
		} else {
			/* we have at least the old password scramble */
			g_string_assign_len(shake->auth_plugin_data, auth_plugin_data_1, 8);
		}

		/* some final assertions */
		if (shake->capabilities & CLIENT_PLUGIN_AUTH) {
			if (shake->auth_plugin_data->len != auth_plugin_data_len) {
				err = 1;
			}
		} else if (shake->capabilities & CLIENT_SECURE_CONNECTION) {
			if (shake->auth_plugin_data->len != 20) {
				err = 1;
			}
		} else {
			/* old auth */
			if (shake->auth_plugin_data->len != 8) {
				err = 1;
			}
		}
	}

	if (auth_plugin_data_1) g_free(auth_plugin_data_1);
	if (auth_plugin_data_2) g_free(auth_plugin_data_2);

	return err ? -1 : 0;
}

int network_mysqld_proto_append_auth_challenge(GString *packet, network_mysqld_auth_challenge *shake) {
	guint i;

	network_mysqld_proto_append_int8(packet, 0x0a);
	if (shake->server_version_str) {
		g_string_append(packet, shake->server_version_str);
	} else if (shake->server_version > 30000 && shake->server_version < 100000) {
		g_string_append_printf(packet, "%d.%02d.%02d", 
				shake->server_version / 10000,
				(shake->server_version % 10000) / 100,
				shake->server_version %   100
				);
	} else {
		g_string_append_len(packet, C("5.0.99"));
	}
	network_mysqld_proto_append_int8(packet, 0x00);
	network_mysqld_proto_append_int32(packet, shake->thread_id);
	if (shake->auth_plugin_data->len) {
		g_assert_cmpint(shake->auth_plugin_data->len, >=, 8);
		g_string_append_len(packet, shake->auth_plugin_data->str, 8);
	} else {
		g_string_append_len(packet, C("01234567"));
	}
	network_mysqld_proto_append_int8(packet, 0x00); /* filler */
	network_mysqld_proto_append_int16(packet, shake->capabilities & 0xffff);
	network_mysqld_proto_append_int8(packet, shake->charset);
	network_mysqld_proto_append_int16(packet, shake->server_status);
	network_mysqld_proto_append_int16(packet, (shake->capabilities >> 16) & 0xffff);

	if (shake->capabilities & CLIENT_PLUGIN_AUTH) {
		g_assert_cmpint(shake->auth_plugin_data->len, <, 255);
		network_mysqld_proto_append_int8(packet, shake->auth_plugin_data->len);
	} else {
		network_mysqld_proto_append_int8(packet, 0);
	}

	/* add the fillers */
	for (i = 0; i < 10; i++) {
		network_mysqld_proto_append_int8(packet, 0x00);
	}

	if (shake->capabilities & CLIENT_PLUGIN_AUTH) {
		g_assert_cmpint(shake->auth_plugin_data->len, >=, 8);
		g_string_append_len(packet, shake->auth_plugin_data->str + 8, shake->auth_plugin_data->len - 8);

		g_string_append_len(packet, S(shake->auth_plugin_name));
		if ((shake->server_version >= 50510 && shake->server_version < 50600) ||
		    (shake->server_version >= 50602)) {
			g_string_append_c(packet, 0x00);
		}
	} else if (shake->capabilities & CLIENT_SECURE_CONNECTION) {
		/* if we only have SECURE_CONNECTION it is 0-terminated */
		if (shake->auth_plugin_data->len) {
			g_assert_cmpint(shake->auth_plugin_data->len, >=, 8);
			g_string_append_len(packet, shake->auth_plugin_data->str + 8, shake->auth_plugin_data->len - 8);
		} else {
			g_string_append_len(packet, C("890123456789"));
		}
		network_mysqld_proto_append_int8(packet, 0x00);
	}
	
	return 0;
}

network_mysqld_auth_response *network_mysqld_auth_response_new(guint32 server_capabilities) {
	network_mysqld_auth_response *auth;

	auth = g_new0(network_mysqld_auth_response, 1);

	/* we have to make sure scramble->buf is not-NULL to get
	 * the "empty string" and not a "NULL-string"
	 */
	auth->auth_plugin_data = g_string_new("");
	auth->auth_plugin_name = g_string_new(NULL);
	auth->username = g_string_new("");
	auth->database = g_string_new("");
	auth->client_capabilities = CLIENT_SECURE_CONNECTION | CLIENT_PROTOCOL_41;
	auth->server_capabilities = server_capabilities;

	return auth;
}

void network_mysqld_auth_response_free(network_mysqld_auth_response *auth) {
	if (!auth) return;

	if (auth->auth_plugin_data)  g_string_free(auth->auth_plugin_data, TRUE);
	if (auth->auth_plugin_name)  g_string_free(auth->auth_plugin_name, TRUE);
	if (auth->username)          g_string_free(auth->username, TRUE);
	if (auth->database)          g_string_free(auth->database, TRUE);

	g_free(auth);
}

int network_mysqld_proto_get_auth_response(network_packet *packet, network_mysqld_auth_response *auth) {
	int err = 0;
	guint16 l_cap;
	/* extract the default db from it */

	/*
	 * @\0\0\1
	 *  \215\246\3\0 - client-flags
	 *  \0\0\0\1     - max-packet-len
	 *  \10          - charset-num
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0       - fillers
	 *  root\0       - username
	 *  \24          - len of the scrambled buf
	 *    ~    \272 \361 \346
	 *    \211 \353 D    \351
	 *    \24  \243 \223 \257
	 *    \0   ^    \n   \254
	 *    t    \347 \365 \244
	 *  
	 *  world\0
	 */


	/* 4.0 uses 2 byte, 4.1+ uses 4 bytes, but the proto-flag is in the lower 2 bytes */
	err = err || network_mysqld_proto_peek_int16(packet, &l_cap);
	if (err) return -1;

	if (l_cap & CLIENT_PROTOCOL_41) {
		err = err || network_mysqld_proto_get_int32(packet, &auth->client_capabilities);
		err = err || network_mysqld_proto_get_int32(packet, &auth->max_packet_size);
		err = err || network_mysqld_proto_get_int8(packet, &auth->charset);

		err = err || network_mysqld_proto_skip(packet, 23);
	
		err = err || network_mysqld_proto_get_gstring(packet, auth->username);
		if ((auth->server_capabilities & CLIENT_SECURE_CONNECTION) &&
		    (auth->server_capabilities & CLIENT_SECURE_CONNECTION)) {
			guint8 len;
			/* new auth is 1-byte-len + data */
			err = err || network_mysqld_proto_get_int8(packet, &len);
			err = err || network_mysqld_proto_get_gstring_len(packet, len, auth->auth_plugin_data);
		} else {
			/* old auth stores it as NUL-term-string */
			err = err || network_mysqld_proto_get_gstring(packet, auth->auth_plugin_data);
		}

		if ((auth->server_capabilities & CLIENT_CONNECT_WITH_DB) &&
		    (auth->client_capabilities & CLIENT_CONNECT_WITH_DB)) {
			err = err || network_mysqld_proto_get_gstring(packet, auth->database);
		}

		if ((auth->server_capabilities & CLIENT_PLUGIN_AUTH) &&
		    (auth->client_capabilities & CLIENT_PLUGIN_AUTH)) {
			/* parse out the plugin name */
			err = err || network_mysqld_proto_get_gstring(packet, auth->auth_plugin_name);
		}
	} else {
		err = err || network_mysqld_proto_get_int16(packet, &l_cap);
		err = err || network_mysqld_proto_get_int24(packet, &auth->max_packet_size);
		err = err || network_mysqld_proto_get_gstring(packet, auth->username);
		if (packet->data->len != packet->offset) {
			/* if there is more, it is the password without a terminating \0 */
			err = err || network_mysqld_proto_get_gstring_len(packet, packet->data->len - packet->offset, auth->auth_plugin_data);
		}

		if (!err) {
			auth->client_capabilities = l_cap;
		}
	}

	return err ? -1 : 0;
}

/**
 * append the auth struct to the mysqld packet
 */
int network_mysqld_proto_append_auth_response(GString *packet, network_mysqld_auth_response *auth) {
	int i;

	if (!(auth->client_capabilities & CLIENT_PROTOCOL_41)) {
		network_mysqld_proto_append_int16(packet, auth->client_capabilities);
		network_mysqld_proto_append_int24(packet, auth->max_packet_size); /* max-allowed-packet */

		if (auth->username->len) g_string_append_len(packet, S(auth->username));
		network_mysqld_proto_append_int8(packet, 0x00); /* trailing \0 */

		if (auth->auth_plugin_data->len) {
			g_string_append_len(packet, S(auth->auth_plugin_data)); /* no trailing \0 */
		}
	} else {
		network_mysqld_proto_append_int32(packet, auth->client_capabilities);
		network_mysqld_proto_append_int32(packet, auth->max_packet_size); /* max-allowed-packet */
		
		network_mysqld_proto_append_int8(packet, auth->charset); /* charset */

		for (i = 0; i < 23; i++) { /* filler */
			network_mysqld_proto_append_int8(packet, 0x00);
		}

		if (auth->username->len) g_string_append_len(packet, S(auth->username));
		network_mysqld_proto_append_int8(packet, 0x00); /* trailing \0 */

		/* scrambled password */
		if (auth->server_capabilities & CLIENT_SECURE_CONNECTION) {
			/* server supports the secure-auth (4.1+) which is 255 bytes max
			 *
			 * if ->len is longer than 255, wrap around ... should be reported back
			 * to the upper layers
			 */
			network_mysqld_proto_append_int8(packet, auth->auth_plugin_data->len);
			g_string_append_len(packet, auth->auth_plugin_data->str, auth->auth_plugin_data->len & 0xff);
		} else {
			/* server only supports the old protocol which allows any length, but no \0 in the auth-plugin-data */
			g_string_append_len(packet, auth->auth_plugin_data->str, auth->auth_plugin_data->len);
			network_mysqld_proto_append_int8(packet, 0x00); /* trailing \0 */
		}

		if ((auth->server_capabilities & CLIENT_CONNECT_WITH_DB) &&
		    (auth->database->len > 0)) {
			g_string_append_len(packet, S(auth->database));
			network_mysqld_proto_append_int8(packet, 0x00); /* trailing \0 */
		}

		if ((auth->client_capabilities & CLIENT_PLUGIN_AUTH) &&
		    (auth->server_capabilities & CLIENT_PLUGIN_AUTH)) {
			g_string_append_len(packet, S(auth->auth_plugin_name));
			network_mysqld_proto_append_int8(packet, 0x00); /* trailing \0 */
		}
	}

	return 0;
}


network_mysqld_auth_response *network_mysqld_auth_response_copy(network_mysqld_auth_response *src) {
	network_mysqld_auth_response *dst;

	if (!src) return NULL;

	dst = network_mysqld_auth_response_new(src->server_capabilities);
	dst->client_capabilities    = src->client_capabilities;
	dst->max_packet_size = src->max_packet_size;
	dst->charset         = src->charset;
	g_string_assign_len(dst->username, S(src->username));
	g_string_assign_len(dst->auth_plugin_data, S(src->auth_plugin_data));
	g_string_assign_len(dst->auth_plugin_name, S(src->auth_plugin_name));
	g_string_assign_len(dst->database, S(src->database));

	return dst;
}

/*
 * change user statements
 */
network_mysqld_change_user *network_mysqld_change_user_new() {
	network_mysqld_change_user *change_user;

	change_user = g_new0(network_mysqld_change_user, 1);

	change_user->username = g_string_new("");
	change_user->password = g_string_new("");
	change_user->schema = g_string_new("");

	return change_user;
}

void network_mysqld_change_user_free(network_mysqld_change_user* change_user) {
	if (!change_user) return;

	if (change_user->username)  g_string_free(change_user->username, TRUE);
	if (change_user->password)  g_string_free(change_user->password, TRUE);
	if (change_user->schema)    g_string_free(change_user->schema, TRUE);

	g_free(change_user);
}

int network_mysqld_proto_get_change_user(network_packet *packet, network_mysqld_change_user* change_user) {
	int err = 0;
	
	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_skip(packet, 1); 
	
	err = err || network_mysqld_proto_get_gstring(packet, change_user->username);
	network_mysqld_proto_skip(packet, 1);
	
	err = err || network_mysqld_proto_get_gstring_len(packet, 20, change_user->password);
	err = err || network_mysqld_proto_get_gstring(packet, change_user->schema);

	return err ? -1 : 0;
}

/*
 * prepared statements
 */

/**
 * 
 */
network_mysqld_stmt_prepare_packet_t *network_mysqld_stmt_prepare_packet_new() {
	network_mysqld_stmt_prepare_packet_t *stmt_prepare_packet;

	stmt_prepare_packet = g_slice_new0(network_mysqld_stmt_prepare_packet_t);
	stmt_prepare_packet->stmt_text = g_string_new(NULL);

	return stmt_prepare_packet;
}

/**
 * 
 */
void network_mysqld_stmt_prepare_packet_free(network_mysqld_stmt_prepare_packet_t *stmt_prepare_packet) {
	if (NULL == stmt_prepare_packet) return;

	if (NULL != stmt_prepare_packet->stmt_text) g_string_free(stmt_prepare_packet->stmt_text, TRUE);

	g_slice_free(network_mysqld_stmt_prepare_packet_t, stmt_prepare_packet);
}

/**
 * 
 */
int network_mysqld_proto_get_stmt_prepare_packet(network_packet *packet, network_mysqld_stmt_prepare_packet_t *stmt_prepare_packet) {
	guint8 packet_type;

	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &packet_type);
	if (err) return -1;

	if (COM_STMT_PREPARE != packet_type) {
		g_critical("%s: expected the first byte to be %02x, got %02x",
				G_STRLOC,
				COM_STMT_PREPARE,
				packet_type);
		return -1;
	}

	g_string_assign_len(stmt_prepare_packet->stmt_text, packet->data->str + packet->offset, packet->data->len - packet->offset);

	return err ? -1 : 0;
}

int network_mysqld_proto_append_stmt_prepare_packet(GString *packet, network_mysqld_stmt_prepare_packet_t *stmt_prepare_packet) {
	network_mysqld_proto_append_int8(packet, COM_STMT_PREPARE);
	g_string_append_len(packet, S(stmt_prepare_packet->stmt_text));

	return 0;
}

/**
 * 
 */
network_mysqld_stmt_prepare_ok_packet_t *network_mysqld_stmt_prepare_ok_packet_new() {
	network_mysqld_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet;

	stmt_prepare_ok_packet = g_slice_new0(network_mysqld_stmt_prepare_ok_packet_t);

	return stmt_prepare_ok_packet;
}

/**
 * 
 */
void network_mysqld_stmt_prepare_ok_packet_free(network_mysqld_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet) {
	if (NULL == stmt_prepare_ok_packet) return;

	g_slice_free(network_mysqld_stmt_prepare_ok_packet_t, stmt_prepare_ok_packet);
}

/**
 * parse the first packet of the OK response for a COM_STMT_PREPARE
 *
 * it is followed by the field defs for the params and the columns and their EOF packets which is handled elsewhere
 */
int network_mysqld_proto_get_stmt_prepare_ok_packet(network_packet *packet, network_mysqld_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet) {
	guint8 packet_type;
	guint16 num_columns;
	guint16 num_params;
	guint16 warnings;
	guint32 stmt_id;

	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &packet_type);
	if (err) return -1;

	if (0x00 != packet_type) {
		g_critical("%s: expected the first byte to be %02x, got %02x",
				G_STRLOC,
				0x00,
				packet_type);
		return -1;
	}
	err = err || network_mysqld_proto_get_int32(packet, &stmt_id);
	err = err || network_mysqld_proto_get_int16(packet, &num_columns);
	err = err || network_mysqld_proto_get_int16(packet, &num_params);
	err = err || network_mysqld_proto_skip(packet, 1); /* the filler */
	err = err || network_mysqld_proto_get_int16(packet, &warnings);

	if (!err) {
		stmt_prepare_ok_packet->stmt_id = stmt_id;
		stmt_prepare_ok_packet->num_columns = num_columns;
		stmt_prepare_ok_packet->num_params = num_params;
		stmt_prepare_ok_packet->warnings = warnings;
	}

	return err ? -1 : 0;
}

int network_mysqld_proto_append_stmt_prepare_ok_packet(GString *packet, network_mysqld_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet) {
	int err = 0;

	err = err || network_mysqld_proto_append_int8(packet, MYSQLD_PACKET_OK);
	err = err || network_mysqld_proto_append_int32(packet, stmt_prepare_ok_packet->stmt_id);
	err = err || network_mysqld_proto_append_int16(packet, stmt_prepare_ok_packet->num_columns);
	err = err || network_mysqld_proto_append_int16(packet, stmt_prepare_ok_packet->num_params);
	err = err || network_mysqld_proto_append_int8(packet, 0x00);
	err = err || network_mysqld_proto_append_int16(packet, stmt_prepare_ok_packet->warnings);

	return err ? -1 : 0;
}

/**
 * create a struct for a COM_STMT_EXECUTE packet
 */
network_mysqld_stmt_execute_packet_t *network_mysqld_stmt_execute_packet_new() {
	network_mysqld_stmt_execute_packet_t *stmt_execute_packet;

	stmt_execute_packet = g_slice_new0(network_mysqld_stmt_execute_packet_t);
	stmt_execute_packet->params = g_ptr_array_new();

	return stmt_execute_packet;
}

/**
 * free a struct for a COM_STMT_EXECUTE packet
 */
void network_mysqld_stmt_execute_packet_free(network_mysqld_stmt_execute_packet_t *stmt_execute_packet) {
	guint i;

	if (NULL == stmt_execute_packet) return;

	for (i = 0; i < stmt_execute_packet->params->len; i++) {
		network_mysqld_type_t *param = g_ptr_array_index(stmt_execute_packet->params, i);

		network_mysqld_type_free(param);
	}

	g_ptr_array_free(stmt_execute_packet->params, TRUE);

	g_slice_free(network_mysqld_stmt_execute_packet_t, stmt_execute_packet);
}

/**
 * get the statement-id from the COM_STMT_EXECUTE packet
 *
 * as network_mysqld_proto_get_stmt_execute_packet() needs the parameter count
 * to calculate the number of null-bits, we need a way to look it up in a 
 * external store which is very likely indexed by the stmt-id
 *
 * @see network_mysqld_proto_get_stmt_execute_packet()
 */
int network_mysqld_proto_get_stmt_execute_packet_stmt_id(network_packet *packet,
		guint32 *stmt_id) {
	guint8 packet_type;
	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &packet_type);
	if (err) return -1;

	if (COM_STMT_EXECUTE != packet_type) {
		g_critical("%s: expected the first byte to be %02x, got %02x",
				G_STRLOC,
				COM_STMT_EXECUTE,
				packet_type);
		return -1;
	}

	err = err || network_mysqld_proto_get_int32(packet, stmt_id);

	return err ? -1 : 0;
}

/**
 *
 * param_count has to be taken from the response of the prepare-stmt-ok packet
 *
 * @param param_count number of parameters that we expect to see here
 */
int network_mysqld_proto_get_stmt_execute_packet(network_packet *packet,
		network_mysqld_stmt_execute_packet_t *stmt_execute_packet,
		guint param_count) {
	int err = 0;
	GString *nul_bits;
	gsize nul_bits_len;

	err = err || network_mysqld_proto_get_stmt_execute_packet_stmt_id(packet, &stmt_execute_packet->stmt_id);
	err = err || network_mysqld_proto_get_int8(packet, &stmt_execute_packet->flags);
	err = err || network_mysqld_proto_get_int32(packet, &stmt_execute_packet->iteration_count);

	if (0 == param_count) {
		return err ? -1 : 0;
	}

	nul_bits_len = (param_count + 7) / 8;
	nul_bits = g_string_sized_new(nul_bits_len);
	err = err || network_mysqld_proto_get_gstring_len(packet, nul_bits_len, nul_bits);
	err = err || network_mysqld_proto_get_int8(packet, &stmt_execute_packet->new_params_bound);

	if (0 != err) {
		g_string_free(nul_bits, TRUE);

		return -1; /* exit early if something failed up to now */
	}

	if (stmt_execute_packet->new_params_bound) {
		guint i;

		for (i = 0; 0 == err && i < param_count; i++) {
			guint16 param_type;

			err = err || network_mysqld_proto_get_int16(packet, &param_type);

			if (0 == err) {
				network_mysqld_type_t *param;

				param = network_mysqld_type_new(param_type & 0xff);
				if (NULL == param) {
					g_critical("%s: couldn't create type = %d", G_STRLOC, param_type & 0xff);

					err = -1;
					break;
				}
				param->is_null = (nul_bits->str[i / 8] & (1 << (i % 8))) != 0;
				param->is_unsigned = (param_type & 0x8000) != 0;

				g_ptr_array_add(stmt_execute_packet->params, param);
			}
		}

		for (i = 0; 0 == err && i < param_count; i++) {
			network_mysqld_type_t *param = g_ptr_array_index(stmt_execute_packet->params, i);

			if (!param->is_null) {
				err = err || network_mysqld_proto_binary_get_type(packet, param);
			}
		}
	}

	g_string_free(nul_bits, TRUE);

	return err ? -1 : 0;
}

int network_mysqld_proto_append_stmt_execute_packet(GString *packet,
		network_mysqld_stmt_execute_packet_t *stmt_execute_packet,
		guint param_count) {
	gsize nul_bits_len;
	GString *nul_bits;
	guint i;
	int err = 0;

	nul_bits_len = (param_count + 7) / 8;
	nul_bits = g_string_sized_new(nul_bits_len);
	memset(nul_bits->str, 0, nul_bits->len); /* set it all to zero */

	for (i = 0; i < param_count; i++) {
		network_mysqld_type_t *param = g_ptr_array_index(stmt_execute_packet->params, i);

		if (param->is_null) {
			nul_bits->str[i / 8] |= 1 << (i % 8);
		}
	}

	network_mysqld_proto_append_int8(packet, COM_STMT_EXECUTE);
	network_mysqld_proto_append_int32(packet, stmt_execute_packet->stmt_id);
	network_mysqld_proto_append_int8(packet, stmt_execute_packet->flags);
	network_mysqld_proto_append_int32(packet, stmt_execute_packet->iteration_count);
	g_string_append_len(packet, S(nul_bits));
	network_mysqld_proto_append_int8(packet, stmt_execute_packet->new_params_bound);

	if (stmt_execute_packet->new_params_bound) {
		for (i = 0; i < stmt_execute_packet->params->len; i++) {
			network_mysqld_type_t *param = g_ptr_array_index(stmt_execute_packet->params, i);

			network_mysqld_proto_append_int16(packet, (guint16)param->type);
		}
		for (i = 0; 0 == err && i < stmt_execute_packet->params->len; i++) {
			network_mysqld_type_t *param = g_ptr_array_index(stmt_execute_packet->params, i);
			
			if (!param->is_null) {
				err = err || network_mysqld_proto_binary_append_type(packet, param);
			}
		}
	}

	return err ? -1 : 0;
}

/**
 * create a struct for a COM_STMT_EXECUTE resultset row
 */
network_mysqld_resultset_row_t *network_mysqld_resultset_row_new() {
	return g_ptr_array_new();
}

/**
 * free a struct for a COM_STMT_EXECUTE resultset row
 */
void network_mysqld_resultset_row_free(network_mysqld_resultset_row_t *row) {
	guint i;

	if (NULL == row) return;

	for (i = 0; i < row->len; i++) {
		network_mysqld_type_t *field = g_ptr_array_index(row, i);

		network_mysqld_type_free(field);
	}

	g_ptr_array_free(row, TRUE);
}

/**
 * get the fields of a row that is in binary row format
 */
int network_mysqld_proto_get_binary_row(network_packet *packet, network_mysqld_proto_fielddefs_t *coldefs, network_mysqld_resultset_row_t *row) {
	int err = 0;
	guint i;
	guint nul_bytes_len;
	GString *nul_bytes;
	guint8 ok;

	err = err || network_mysqld_proto_get_int8(packet, &ok); /* the packet header which seems to be always 0 */
	err = err || (ok != 0);

	nul_bytes_len = (coldefs->len + 7 + 2) / 8; /* the first 2 bits are reserved */
	nul_bytes = g_string_sized_new(nul_bytes_len);
	err = err || network_mysqld_proto_get_gstring_len(packet, nul_bytes_len, nul_bytes);

	for (i = 0; 0 == err && i < coldefs->len; i++) {
		network_mysqld_type_t *param;
		network_mysqld_proto_fielddef_t *coldef = g_ptr_array_index(coldefs, i);

		param = network_mysqld_type_new(coldef->type);
		if (NULL == param) {
			g_debug("%s: coulnd't create type = %d",
					G_STRLOC, coldef->type);

			err = -1;
			break;
		}

		if (nul_bytes->str[(i + 2) / 8] & (1 << ((i + 2) % 8))) {
			param->is_null = TRUE;
		} else {
			err = err || network_mysqld_proto_binary_get_type(packet, param);
		}

		g_ptr_array_add(row, param);
	}

	g_string_free(nul_bytes, TRUE);

	return err ? -1 : 0;
}

/**
 */
GList *network_mysqld_proto_get_next_binary_row(GList *chunk, network_mysqld_proto_fielddefs_t *fields, network_mysqld_resultset_row_t *row) {
	network_packet packet;
	int err = 0;
	network_mysqld_lenenc_type lenenc_type;
    
	packet.data = chunk->data;
	packet.offset = 0;

	err = err || network_mysqld_proto_skip_network_header(&packet);

	err = err || network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);
	if (0 != err) return NULL;

	if (NETWORK_MYSQLD_LENENC_TYPE_EOF == lenenc_type) {
		/* this is a EOF packet, we are done */
		return NULL;
	}

	err = err || network_mysqld_proto_get_binary_row(&packet, fields, row);

	return err ? NULL : chunk->next;
}

/**
 * create a struct for a COM_STMT_CLOSE packet
 */
network_mysqld_stmt_close_packet_t *network_mysqld_stmt_close_packet_new() {
	network_mysqld_stmt_close_packet_t *stmt_close_packet;

	stmt_close_packet = g_slice_new0(network_mysqld_stmt_close_packet_t);

	return stmt_close_packet;
}

/**
 * free a struct for a COM_STMT_CLOSE packet
 */
void network_mysqld_stmt_close_packet_free(network_mysqld_stmt_close_packet_t *stmt_close_packet) {
	if (NULL == stmt_close_packet) return;

	g_slice_free(network_mysqld_stmt_close_packet_t, stmt_close_packet);
}

/**
 */
int network_mysqld_proto_get_stmt_close_packet(network_packet *packet, network_mysqld_stmt_close_packet_t *stmt_close_packet) {
	guint8 packet_type;
	int err = 0;

	err = err || network_mysqld_proto_get_int8(packet, &packet_type);
	if (err) return -1;

	if (COM_STMT_CLOSE != packet_type) {
		g_critical("%s: expected the first byte to be %02x, got %02x",
				G_STRLOC,
				COM_STMT_CLOSE,
				packet_type);
		return -1;
	}

	err = err || network_mysqld_proto_get_int32(packet, &stmt_close_packet->stmt_id);

	return err ? -1 : 0;
}

/**
 * @author sohu-inc.com
 * 用于跟踪协议级实现的prepare的close语句
 */
int network_mysqld_com_stmt_close_track_state(network_packet *packet,network_mysqld_stmt_close_packet_t *udata) {
	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_skip(packet, 1); /* the command */

	g_assert(packet->offset < packet->data->len);

	network_mysqld_proto_get_int32(packet, &udata->stmt_id);
	return 0;
}

int network_mysqld_proto_append_stmt_close_packet(GString *packet, network_mysqld_stmt_close_packet_t *stmt_close_packet) {
	network_mysqld_proto_append_int8(packet, COM_STMT_CLOSE);
	network_mysqld_proto_append_int32(packet, stmt_close_packet->stmt_id);

	return 0;
}




/**
 * added by jinxuan hou
 * password scramble for client auth packet create
 */
void mysql_scramble(gchar *to, const gchar *salt, const gchar *passwd) {
	scramble(to, salt, passwd);
}




