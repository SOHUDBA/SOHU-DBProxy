/*
 * network-sql-normalization.h
 *
 *  Created on: 2013-7-25
 *      Author: jinxuanhou
 */

#ifndef NETWORK_SQL_NORMALIZATION_H_
#define NETWORK_SQL_NORMALIZATION_H_

#include <glib.h>
#include <sql-tokenizer.h>
#define SQL_NORMALIZE_TYPE_NUM 2

#define SQL_NORMALIZE_TYPE_NUM 2

typedef enum {
	NORMALIZE_FOR_SINGLE = 0,
	NORMALIZE_FOR_TEMPLATE
} normalize_type;

extern char * sql_normalize_for_single(
		const GPtrArray *tokens); /** <实现序列化，针对限制单条sql的情况
								   */

extern char * sql_normalize_for_template(
		const GPtrArray *tokens); /**< 实现序列化，针对限制某类sql的情况
									*/

extern char * sql_normalize_with_token(
		const char *sql_original,
		normalize_type type); /**< 实现对传入的sql语句的标准化，
									* 返回标准化之后的sql语句
									* @note 返回的语句内存需要调用者自己释放
									*/

extern char * sql_normalize_with_token_dispatch(
		const GPtrArray *tokens,
		const char *sql_original,
		normalize_type type); /**< 实现对传入的sql语句的标准化，
									* 返回标准化之后的sql语句
									* @note 返回的语句内存需要调用者自己释放
									*/

extern char *sql_normalize_without_token(
		const char *sql_original); /**< 同样实现sql语句的序列化，
									* 通过直接对语句进行扫描来对sql语句进行标准化
									*/

extern char * sql_normalize_MD5(
		const char *sql_normalized);/**< 对标准化时候的sql语句求md5值
									 * 使用的md5函数是：
									 */
#endif /* NETWORK_SQL_NORMALIZATION_H_ */
