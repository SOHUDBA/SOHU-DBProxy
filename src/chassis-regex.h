/* $%BEGINLICENSE%$
 Copyright (c) 2013, 2014, Sohu and/or its affiliates. All rights reserved.

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
 Foundation, Inc.,

 $%ENDLICENSE%$ */

/*
 * chassis-regex.h
 *
 *  Created on: 2013-5-23
 *      Author: jinxuanhou
 */

#ifndef NETWORK_CHARSET_H_
#define NETWORK_CHARSET_H_
#include <stdio.h>
#include <glib.h>

#include "chassis-exports.h"

extern const char* charset_dic[];
extern const char* collation_dic[];
extern const char *distinct_sets[];
extern const char *distinct_collations[];

//extern GHashTable *distinct_sets;

struct charset_regex {
	GRegex *names_set;
	GRegex *client_char_set;
	GRegex *connect_char_set;
	GRegex *results_char_set;
	GRegex *database_char_set;
	GRegex *server_char_set;
	GRegex *connect_coll;// 用于处理connection 校验
};

typedef struct charset_regex charset_regex;

CHASSIS_API charset_regex *charset_regex_new(void);
CHASSIS_API void charset_regex_free(charset_regex *reg);

CHASSIS_API gboolean is_set_names(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_set_client_charset(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_set_connect_charset(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_set_results_charset(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_set_database_charset(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_set_server_charset(charset_regex *reg, const gchar *sql);
CHASSIS_API gboolean is_correct_charsetname(const gchar *charset);

CHASSIS_API gboolean is_set_connect_collation(charset_regex *reg, const gchar *sql); // 判断是否是connection collation set 的语句
CHASSIS_API gint get_default_collation_index(const gchar *charset); /**< 获取对应字符集的默认的校验下标 */
CHASSIS_API gboolean is_correct_collationname(const gchar *collation, guint8 *index); /**< 验证一个校验的名字是否正确,不计大小写 */


#endif /* NETWORK_CHARSET_H_ */
